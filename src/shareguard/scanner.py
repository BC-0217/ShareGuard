"""Scan orchestration: selected roots -> directories -> files -> ZIP entries.

``scan_paths`` never raises; every failure becomes a fixed issue code or the
``error`` completeness. Results contain no raw paths, names or content.
"""

from __future__ import annotations

import os
import secrets
import time

from . import safeio
from .context import READ_CHUNK, ScanContext, StopScan, StopTarget
from .model import (CANCELLED, COMPLETE, ERROR, FATAL_CODES, INCOMPLETE, KIND_ARCHIVE,
                    KIND_DIRECTORY, KIND_FILE, IssueCode, Issue, ScanResult)
from .policy import Policy, PolicyError, coerce_policy
from .textscan import SNIFF_BYTES, is_unsupported_container, sniff_archive
from .zipscan import scan_zip


def scan_paths(paths, policy=None, cancel_event=None, callback=None,
               location_callback=None) -> ScanResult:
    """Scan selected files/directories and return a sanitized ScanResult."""
    started = time.monotonic()
    scan_id = secrets.token_hex(8)
    try:
        effective = coerce_policy(policy)
    except (PolicyError, TypeError, ValueError):
        return _fatal(scan_id, IssueCode.POLICY_INVALID, Policy(), started)
    ctx = ScanContext(effective, cancel_event, callback, location_callback)
    fatal = False
    try:
        selected = _collect_paths(paths, ctx)
        ctx.root_count = len(selected)
        if not selected:
            return _fatal(scan_id, IssueCode.NO_INPUT, effective, started)
        for index, raw in enumerate(selected):
            ctx.check(None)
            _scan_root(ctx, index, raw)
    except StopScan as exc:
        if exc.code is not None:
            ctx.add_issue(exc.code, None, final=True)
    except Exception:
        ctx.add_issue(IssueCode.INTERNAL_ERROR, None, final=True)
        fatal = True

    if fatal:
        completeness = ERROR
    elif ctx.cancelled:
        completeness = CANCELLED
    elif ctx.issues:
        completeness = INCOMPLETE
    else:
        completeness = COMPLETE
    result = _build(ctx, scan_id, completeness, started)
    safeio.register_result_scopes(scan_id, ctx.root_count, ctx.input_scopes)
    return result


def _collect_paths(paths, ctx: ScanContext) -> list:
    """Consume a bounded number of roots with early deadline/cancel checks."""
    if isinstance(paths, (str, bytes, os.PathLike)):
        return [paths]
    if paths is None:
        return []
    try:
        iterator = iter(paths)
    except Exception:
        raise StopScan(IssueCode.PATH_UNSUPPORTED) from None
    selected = []
    while True:
        ctx.check(None)
        try:
            raw = next(iterator)
        except StopIteration:
            return selected
        except Exception:
            raise StopScan(IssueCode.PATH_UNSUPPORTED) from None
        if len(selected) >= ctx.policy.max_entries:
            raise StopScan(IssueCode.ENTRY_COUNT_LIMIT)
        selected.append(raw)


def _fatal(scan_id, code, policy, started) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        completeness=ERROR,
        issues=[Issue(code, None)],
        counts={"issues": 1},
        policy=policy.to_dict(),
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def _build(ctx: ScanContext, scan_id, completeness, started) -> ScanResult:
    findings = list(ctx.findings)
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        severity_counts[f.severity] += f.count
    counts = {
        "targets": len(ctx.targets),
        "files_scanned": ctx.files_scanned,
        "directories_scanned": ctx.directories_scanned,
        "archive_entries_scanned": ctx.archive_entries_scanned,
        "bytes_scanned": ctx.bytes,
        "findings": sum(f.count for f in findings),
        "issues": len(ctx.issues),
        **severity_counts,
    }
    return ScanResult(
        scan_id=scan_id,
        completeness=completeness,
        findings=findings,
        issues=list(ctx.issues),
        targets=ctx.targets,
        counts=counts,
        policy=ctx.policy.to_dict(),
        duration_ms=int((time.monotonic() - started) * 1000),
    )


# --------------------------------------------------------------------------
# Roots, directories, files
# --------------------------------------------------------------------------

def _display_root(raw) -> str | None:
    try:
        path = os.fspath(raw)
        return os.path.abspath(path) if isinstance(path, str) else None
    except Exception:
        return None


def _scan_root(ctx: ScanContext, index: int, raw) -> None:
    display = _display_root(raw)
    tid = ctx.new_target(KIND_FILE, None, index, display, None)
    try:
        handle = safeio.open_root(raw)
    except safeio.FsError as exc:
        ctx.add_issue(exc.code, tid)
        return
    except (TypeError, ValueError, OSError):
        ctx.add_issue(IssueCode.PATH_UNSUPPORTED, tid)
        return
    except Exception:
        ctx.add_issue(IssueCode.INTERNAL_ERROR, tid)
        return
    try:
        try:
            snapshot = handle.snapshot()
            ctx.input_scopes[index] = (int(snapshot[0]), int(snapshot[1]),
                                       bool(handle.is_dir))
        except (safeio.FsError, OSError, TypeError, ValueError):
            ctx.add_issue(IssueCode.IDENTITY_UNVERIFIED, tid)
            return
        _guarded(ctx, tid, _scan_any, ctx, handle, tid, 0, display,
                 os.path.basename(display or ""))
    finally:
        handle.close()


def _guarded(ctx: ScanContext, tid: str, fn, *args) -> None:
    """Run ``fn``; unexpected failures become INTERNAL_ERROR on ``tid``."""
    try:
        fn(*args)
    except (StopScan, StopTarget):
        raise
    except Exception:
        ctx.add_issue(IssueCode.INTERNAL_ERROR, tid)


def _scan_any(ctx: ScanContext, handle, tid: str, depth: int, display, name: str) -> None:
    if handle.is_dir:
        ctx.set_kind(tid, KIND_DIRECTORY)
        _scan_directory(ctx, handle, tid, depth, display)
    else:
        _scan_file(ctx, handle, tid, depth, display, name)


def _scan_directory(ctx: ScanContext, handle, tid: str, depth: int, display) -> None:
    ctx.take_directory()
    try:
        before = handle.snapshot()
        names = handle.list_names(ctx.policy.max_entries)
    except safeio.FsError as exc:
        ctx.add_issue(exc.code, tid)
        return
    if len(names) > ctx.policy.max_entries:
        raise StopScan(IssueCode.ENTRY_COUNT_LIMIT)
    names.sort()
    for name in names:
        ctx.check(None)
        child_display = os.path.join(display, name) if display else None
        child_tid = ctx.new_target(KIND_FILE, tid, None, child_display, None)
        if depth + 1 > ctx.policy.max_depth:
            ctx.add_issue(IssueCode.DEPTH_LIMIT, child_tid)
            continue
        try:
            child = safeio.open_child(handle, name)
        except safeio.FsError as exc:
            ctx.add_issue(exc.code, child_tid)
            continue
        except Exception:
            ctx.add_issue(IssueCode.INTERNAL_ERROR, child_tid)
            continue
        try:
            _guarded(ctx, child_tid, _scan_any, ctx, child, child_tid, depth + 1,
                     child_display, name)
        finally:
            child.close()
    try:
        after = handle.snapshot()
    except safeio.FsError as exc:
        ctx.add_issue(exc.code, tid)
        return
    if after != before:
        ctx.add_issue(IssueCode.MUTATION_DETECTED, tid)
        return
    ctx.directories_scanned += 1


def _read_upto(handle, n: int) -> bytes:
    parts = []
    got = 0
    while got < n:
        data = handle.read(min(n - got, READ_CHUNK))
        if not data:
            break
        parts.append(data)
        got += len(data)
    return b"".join(parts)


def _scan_file(ctx: ScanContext, handle, tid: str, depth: int, display, name: str) -> None:
    ctx.take_entry(tid)
    deadline = ctx.file_deadline()
    try:
        before = handle.snapshot()
        size = before[2]
        head_limit = min(
            SNIFF_BYTES,
            size + 1,
            ctx.policy.max_file_bytes + 1,
            ctx.bytes_left() + 1,
        )
        head = _read_upto(handle, max(1, head_limit))
        kind = sniff_archive(head)
        suffix = os.path.splitext(name.lower())[1]
        known_document = is_unsupported_container(name, head)
        if kind is None and suffix == ".zip":
            kind = "zip"
        if known_document:
            ctx.take_bytes(len(head))
            ctx.add_issue(IssueCode.UNSUPPORTED_ARCHIVE, tid)
            return
        if kind == "zip":
            ctx.set_kind(tid, KIND_ARCHIVE)
            ctx.take_bytes(len(head))
            if size > ctx.policy.max_file_bytes:
                ctx.add_issue(IssueCode.FILE_TOO_LARGE, tid)
                return
            handle.seek(0)
            scan_zip(ctx, handle, tid, depth, size, display, deadline)
            completed = True
        elif kind == "other":
            ctx.take_bytes(len(head))
            ctx.add_issue(IssueCode.UNSUPPORTED_ARCHIVE, tid)
            return
        else:
            if size > ctx.policy.max_file_bytes:
                ctx.take_bytes(len(head))
                ctx.add_issue(IssueCode.FILE_TOO_LARGE, tid)
                return
            ctx.reserve_bytes(size)
            remaining = [size + 1 - len(head)]

            def read_more(n):
                n = min(n, remaining[0])
                if n <= 0:
                    return b""
                data = handle.read(n)
                remaining[0] -= len(data)
                return data

            completed = ctx.scan_stream(tid, head, read_more, max(size, 0),
                                        deadline, IssueCode.MUTATION_DETECTED)
        after = handle.snapshot()
    except StopTarget as exc:
        ctx.add_issue(exc.code, tid)
        return
    except safeio.FsError as exc:
        ctx.add_issue(exc.code, tid)
        return
    if after != before:
        ctx.add_issue(IssueCode.MUTATION_DETECTED, tid)
        return
    if completed:
        ctx.files_scanned += 1
