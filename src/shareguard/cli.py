"""Command line interface.

    shareguard scan PATH... [--json] [--report PATH] [limit options]
    shareguard --version
    shareguard            (no arguments: launch the GUI)

Output never echoes raw paths, argument values or exception text.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import queue
import secrets
import sys
import threading
import time

from . import __version__
from . import platform_support
from .model import (CANCELLED, COMPLETE, ERROR, INCOMPLETE, Issue, IssueCode,
                    ScanResult)
from .policy import MIB, Policy, PolicyError

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2
EXIT_CANCELLED = 3
EXIT_ERROR = 4

PROG = "shareguard"


def exit_code(result) -> int:
    """Map a ScanResult (or its dict) to the documented exit code."""
    if isinstance(result, dict):
        result = ScanResult.from_dict(result)
    if result.completeness == COMPLETE:
        return EXIT_FINDINGS if result.findings else EXIT_CLEAN
    if result.completeness == INCOMPLETE:
        return EXIT_INCOMPLETE
    if result.completeness == CANCELLED:
        return EXIT_CANCELLED
    return EXIT_ERROR


# --------------------------------------------------------------------------
# Argument parsing without echoing input values
# --------------------------------------------------------------------------

class UsageError(Exception):
    pass


class _ParserExit(Exception):
    def __init__(self, status: int):
        super().__init__(status)
        self.status = status


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # noqa: D401 - argparse hook
        raise UsageError()

    def exit(self, status=0, message=None):
        raise _ParserExit(status)


def _positive_int(text):
    try:
        value = int(text, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("invalid") from None
    if value <= 0:
        raise argparse.ArgumentTypeError("invalid")
    return value


def _positive_float(text):
    try:
        value = float(text)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("invalid") from None
    if not value > 0 or value == float("inf"):
        raise argparse.ArgumentTypeError("invalid")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog=PROG,
        description="Local pre-sharing sensitive-information scanner for "
                    f"{platform_support.PUBLIC_PLATFORM}. Not malware detection, "
                    "key validation or a safety certification.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", parser_class=_Parser)
    scan = sub.add_parser("scan", help="scan files, folders or ZIP archives",
                          allow_abbrev=False)
    scan.add_argument("paths", nargs="+", metavar="PATH")
    scan.add_argument("--json", action="store_true",
                      help="print the sanitized JSON result")
    scan.add_argument("--report", metavar="PATH",
                      help="write the sanitized JSON report to a new file")
    scan.add_argument("--max-file-mib", type=_positive_int, metavar="N",
                      help="per-file size limit in MiB (max 16)")
    scan.add_argument("--max-total-mib", type=_positive_int, metavar="N",
                      help="total bytes read limit in MiB (max 256)")
    scan.add_argument("--max-entries", type=_positive_int, metavar="N",
                      help="files + ZIP entries limit (max 10000)")
    scan.add_argument("--max-depth", type=_positive_int, metavar="N",
                      help="directory/archive depth limit (max 32)")
    scan.add_argument("--file-timeout", type=_positive_float, metavar="SEC",
                      help="per-file time limit in seconds (max 5)")
    scan.add_argument("--scan-timeout", type=_positive_float, metavar="SEC",
                      help="whole-scan time limit in seconds (max 120)")
    scan.add_argument("--max-line-chars", type=_positive_int, metavar="N",
                      help="line length bound (max 1048576)")
    return parser


def policy_from_args(args) -> Policy:
    values = {}
    if args.max_file_mib is not None:
        values["max_file_bytes"] = args.max_file_mib * MIB
    if args.max_total_mib is not None:
        values["max_total_bytes"] = args.max_total_mib * MIB
    if args.max_entries is not None:
        values["max_entries"] = args.max_entries
    if args.max_depth is not None:
        values["max_depth"] = args.max_depth
    if args.file_timeout is not None:
        values["file_timeout_seconds"] = args.file_timeout
    if args.scan_timeout is not None:
        values["scan_timeout_seconds"] = args.scan_timeout
    if args.max_line_chars is not None:
        values["max_line_chars"] = args.max_line_chars
    return Policy(**values)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def _write(stream, text: str) -> None:
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError):
        pass


def _err(code: str, what: str) -> None:
    _write(sys.stderr, f"{PROG}: {what} ({code})\n")


def format_summary(result: ScanResult) -> str:
    d = result.to_dict()
    c = d["counts"]
    lines = [
        f"ShareGuard {__version__} scan result",
        f"Completeness: {d['completeness']}",
        f"Outcome: {d['outcome']} ({c['findings']} matches: high={c['high']} "
        f"medium={c['medium']} low={c['low']})",
        f"Targets: {c['targets']}  files scanned: {c['files_scanned']}  "
        f"directories scanned: {c['directories_scanned']}  "
        f"archive entries scanned: {c['archive_entries_scanned']}  "
        f"bytes: {c['bytes_scanned']}",
    ]
    roots = [t for t in d["targets"] if t["root_index"] is not None]
    if roots:
        lines.append("Inputs: " + ", ".join(
            f"{t['target_id']}=input#{t['root_index'] + 1}" for t in roots))
    if d["findings"]:
        lines.append("Findings:")
        for f in d["findings"]:
            lines.append(
                f"  {f['target_id']} line {f['line']}: {f['rule_id']} "
                f"[{f['category']}, severity={f['severity']}, "
                f"confidence={f['confidence']}] x{f['count']}")
    if d["issues"]:
        lines.append("Issues (scan is not complete):")
        for i in d["issues"]:
            lines.append(f"  {i['target_id'] or '-'} {i['code']}")
    if d["completeness"] != COMPLETE:
        lines.append("Note: the scan did not complete; sensitive data may have been missed.")
    lines.append("No result is a safety certification.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

_MAX_WORKER_MESSAGE = 16 * 1024 * 1024
_MAX_SCOPE_MESSAGE = 2 * 1024 * 1024
_STARTUP_GRACE_SECONDS = 3.0
_CANCEL_GRACE_SECONDS = 1.0
_TERMINATE_GRACE_SECONDS = 1.0


def _synthetic_result(policy: Policy, completeness: str, code=None) -> ScanResult:
    issues = [] if code is None else [Issue(code, None)]
    return ScanResult(
        scan_id=secrets.token_hex(8),
        completeness=completeness,
        issues=issues,
        counts={"issues": len(issues)},
        policy=policy.to_dict(),
        duration_ms=0,
    )


def _scan_worker(result_conn, scope_conn, paths, policy_dict, cancel_event) -> None:
    """Owned spawn child: public result and private scope use separate pipes."""
    scan_id = None
    try:
        from .safeio import clear_result_scopes, export_result_scopes
        from .scanner import scan_paths

        result = scan_paths(paths, policy=policy_dict, cancel_event=cancel_event)
        scan_id = result.scan_id
        result_payload = json.dumps(
            result.to_dict(), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        scope_payload = json.dumps(
            export_result_scopes(scan_id), ensure_ascii=True,
            separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        if len(result_payload) > _MAX_WORKER_MESSAGE:
            result_payload = b'{"error":"RESULT_LIMIT"}'
            scope_payload = b"null"
        if len(scope_payload) > _MAX_SCOPE_MESSAGE:
            result_payload = b'{"error":"SCOPE_LIMIT"}'
            scope_payload = b"null"
        result_conn.send_bytes(result_payload)
        scope_conn.send_bytes(scope_payload)
    except BaseException:
        for conn, payload in (
                (result_conn, b'{"error":"WORKER_ERROR"}'),
                (scope_conn, b"null")):
            try:
                conn.send_bytes(payload)
            except BaseException:
                pass
    finally:
        if scan_id is not None:
            try:
                clear_result_scopes(scan_id)
            except Exception:
                pass
        for conn in (result_conn, scope_conn):
            try:
                conn.close()
            except Exception:
                pass


def _decode_worker_message(result_payload: bytes, scope_payload: bytes | None,
                           policy: Policy) -> ScanResult:
    try:
        if len(result_payload) > _MAX_WORKER_MESSAGE:
            raise ValueError
        result = ScanResult.from_dict(json.loads(result_payload.decode("ascii")))
        if scope_payload is not None:
            if len(scope_payload) > _MAX_SCOPE_MESSAGE:
                raise ValueError
            scopes = json.loads(scope_payload.decode("ascii"))
            if scopes is not None:
                from .safeio import import_result_scopes

                if not import_result_scopes(result.scan_id, scopes):
                    raise ValueError
        return result
    except (UnicodeError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return _synthetic_result(policy, ERROR, IssueCode.INTERNAL_ERROR)


def _pipe_receiver(label, conn, limit: int, events) -> None:
    """Blocking frame receive isolated from the deadline-owning main thread."""
    try:
        payload = conn.recv_bytes(limit)
    except BaseException:
        payload = None
    try:
        events.put_nowait((label, payload))
    except Exception:
        pass


def _reap_owned(process) -> bool:
    """Cooperate, terminate, then kill only this child; return confirmed reaped."""
    for action in ("join", "terminate", "kill"):
        try:
            if action == "join":
                process.join(0.1)
            elif process.is_alive():
                getattr(process, action)()
                process.join(_TERMINATE_GRACE_SECONDS)
        except BaseException:
            pass
        try:
            if not process.is_alive():
                return True
        except Exception:
            return False
    return False


def _run_scan(paths, policy) -> ScanResult:
    """Run in one bounded owned spawn worker with cancellable framed IPC."""
    context = multiprocessing.get_context("spawn")
    result_recv, result_send = context.Pipe(duplex=False)
    scope_recv, scope_send = context.Pipe(duplex=False)
    cancel = context.Event()
    process = context.Process(
        target=_scan_worker,
        args=(result_send, scope_send, list(paths), policy.to_dict(), cancel),
        name="shareguard-cli-scan",
        daemon=True,
    )
    events = queue.Queue()
    receivers = []
    payloads = {"result": None, "scope": None}
    completed = set()
    interrupted = False
    timed_out = False
    started = False
    cleanup_failed = False
    try:
        process.start()
        started = True
        result_send.close()
        scope_send.close()
        receivers = [
            threading.Thread(
                target=_pipe_receiver,
                args=("result", result_recv, _MAX_WORKER_MESSAGE, events),
                name="shareguard-cli-recv-result",
                daemon=True,
            ),
            threading.Thread(
                target=_pipe_receiver,
                args=("scope", scope_recv, _MAX_SCOPE_MESSAGE, events),
                name="shareguard-cli-recv-scope",
                daemon=True,
            ),
        ]
        for receiver in receivers:
            receiver.start()

        deadline = time.monotonic() + policy.scan_timeout_seconds + _STARTUP_GRACE_SECONDS
        while len(completed) < 2:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                label, payload = events.get(timeout=min(0.05, remaining))
                completed.add(label)
                payloads[label] = payload
            except queue.Empty:
                if not process.is_alive() and not any(t.is_alive() for t in receivers):
                    break
            except KeyboardInterrupt:
                interrupted = True
                break

        if interrupted or timed_out:
            cancel.set()
            grace_end = time.monotonic() + _CANCEL_GRACE_SECONDS
            while time.monotonic() < grace_end and len(completed) < 2:
                try:
                    label, payload = events.get(timeout=0.05)
                    completed.add(label)
                    payloads[label] = payload
                except queue.Empty:
                    if not process.is_alive():
                        break
                except KeyboardInterrupt:
                    interrupted = True
    except KeyboardInterrupt:
        interrupted = True
        cancel.set()
    except (OSError, RuntimeError):
        pass
    finally:
        for conn in (result_send, scope_send):
            try:
                conn.close()
            except Exception:
                pass
        if started:
            cleanup_failed = not _reap_owned(process)
        for conn in (result_recv, scope_recv):
            try:
                conn.close()
            except Exception:
                pass
        for receiver in receivers:
            receiver.join(_TERMINATE_GRACE_SECONDS)
        cleanup_failed = cleanup_failed or any(t.is_alive() for t in receivers)
        if started and not cleanup_failed:
            try:
                process.close()
            except Exception:
                cleanup_failed = True

    if interrupted:
        return _synthetic_result(
            policy, CANCELLED,
            IssueCode.INTERNAL_ERROR if cleanup_failed else None)
    if cleanup_failed:
        return _synthetic_result(policy, ERROR, IssueCode.INTERNAL_ERROR)
    if timed_out:
        return _synthetic_result(policy, INCOMPLETE, IssueCode.SCAN_TIME_LIMIT)
    if payloads["result"] is not None:
        return _decode_worker_message(
            payloads["result"], payloads["scope"], policy)
    return _synthetic_result(policy, ERROR, IssueCode.INTERNAL_ERROR)


def _cmd_scan(args) -> int:
    try:
        policy = policy_from_args(args)
    except PolicyError:
        _err("POLICY_INVALID", "error: limit option out of range")
        return EXIT_ERROR
    if not platform_support.is_public_platform_supported():
        result = platform_support.unsupported_platform_result(policy)
        if args.json:
            _write(sys.stdout, json.dumps(result.to_dict(), ensure_ascii=True,
                                          sort_keys=True) + "\n")
        else:
            _write(sys.stdout, format_summary(result))
        return EXIT_ERROR
    result = _run_scan(args.paths, policy)
    if args.json:
        _write(sys.stdout, json.dumps(result.to_dict(), ensure_ascii=True,
                                      sort_keys=True) + "\n")
    else:
        _write(sys.stdout, format_summary(result))
    code = exit_code(result)
    if args.report is not None:
        from .safeio import ReportError, write_report

        try:
            write_report(result, args.report, args.paths)
        except ReportError as exc:
            _err(exc.code, "report not written")
            return EXIT_ERROR
        except Exception:
            _err("REPORT_WRITE_FAILED", "report not written")
            return EXIT_ERROR
    return code


def _launch_gui() -> int:
    try:
        from . import gui
    except Exception:
        _err("GUI_UNAVAILABLE", "error: GUI unavailable")
        return EXIT_ERROR
    try:
        rc = gui.main()
    except Exception:
        _err("GUI_ERROR", "error: GUI failed")
        return EXIT_ERROR
    return rc if isinstance(rc, int) else 0


def main(argv=None) -> int:
    multiprocessing.freeze_support()
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    if not argv:
        return _launch_gui()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _ParserExit as exc:
        return EXIT_CLEAN if exc.status == 0 else EXIT_ERROR
    except UsageError:
        _err("USAGE_INVALID", "error: invalid arguments; see --help")
        return EXIT_ERROR
    if args.command != "scan":
        _err("USAGE_INVALID", "error: invalid arguments; see --help")
        return EXIT_ERROR
    try:
        return _cmd_scan(args)
    except KeyboardInterrupt:
        _err("CANCELLED", "cancelled")
        return EXIT_CANCELLED
    except Exception:
        _err("INTERNAL_ERROR", "error: internal failure")
        return EXIT_ERROR
