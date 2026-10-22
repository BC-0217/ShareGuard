"""Programmatic live self-test of the real GUI (development and packaging).

``python -m shareguard.gui_selftest OUT_JSON --scan PATH... [--cancel PATH...]``

It creates the real Tk window, drives it through its public methods on the
UI thread, runs real spawned scans, and writes a JSON summary that contains
only booleans, counts, fixed codes and timings - never paths or content.
This proves Tk-level behaviour (internal widget state) and the worker
pipeline; it is not a screenshot or native-window inspection.

Runtime network observation uses ``sys.addaudithook`` in the GUI process and
in the worker process.  Limits: audit hooks only see events raised by the
Python runtime (``socket.*``, ``urllib.Request`` ...); activity in native code
that bypasses those events is not observed.
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import sys
import threading
import time

NETWORK_EVENT_PREFIXES = ("socket.", "urllib.", "http.client.", "ftplib.", "smtplib.", "poplib.", "imaplib.", "nntplib.", "telnetlib.", "webbrowser.")

_network_events = []


def _audit(event, args):
    if event.startswith(NETWORK_EVENT_PREFIXES):
        _network_events.append(event)


def install_network_audit():
    sys.addaudithook(_audit)


def _write_worker_audit(audit_prefix):
    try:
        with open("%s-%d.json" % (audit_prefix, os.getpid()), "x", encoding="utf-8") as handle:
            json.dump(sorted(set(_network_events)), handle)
    except OSError:
        pass


def audited_worker(audit_prefix, *args):
    """Run the real scanner worker and record this worker's audit events."""
    install_network_audit()
    from shareguard.gui_session import worker_main

    try:
        worker_main(*args)
    finally:
        _write_worker_audit(audit_prefix)


def audited_large_result_worker(audit_prefix, generation, paths, policy_data, cancel_event,
                                result_conn, location_conn, scope_conn):
    """Send a schema-valid 10,000-row result to exercise live Tk rendering."""
    install_network_audit()
    try:
        from shareguard.gui_session import encode_message
        from shareguard.model import COMPLETE, Finding, ScanResult, Target
        from shareguard.policy import Policy
        from shareguard.rules import RULES_BY_ID

        rule = next(iter(RULES_BY_ID.values()))
        findings = [
            Finding("T1", rule.rule_id, rule.category, rule.severity, rule.confidences[0], line + 1)
            for line in range(10_000)
        ]
        severity = {"high": 0, "medium": 0, "low": 0}
        severity[rule.severity] = 10_000
        result = ScanResult(
            scan_id="0123456789abcdef",
            completeness=COMPLETE,
            findings=findings,
            targets=[Target("T1", "file", root_index=0)],
            counts={"targets": 1, "findings": 10_000, "issues": 0, **severity},
            policy=Policy().to_dict(),
        )
        result_conn.send_bytes(
            encode_message({"type": "result", "gen": generation, "result": result.to_dict()})
        )
    finally:
        _write_worker_audit(audit_prefix)


def forced_cancel_worker(generation, paths, policy_data, cancel_event,
                         result_conn, location_conn, scope_conn):
    """Ignore cooperative cancellation so the owned-worker terminate path runs."""
    time.sleep(60)


def collect_worker_audits(audit_prefix):
    """Return (number of worker audit files, union of their events)."""
    folder = os.path.dirname(audit_prefix)
    stem = os.path.basename(audit_prefix) + "-"
    files, events = 0, set()
    for name in sorted(os.listdir(folder)):
        if name.startswith(stem) and name.endswith(".json"):
            path = os.path.join(folder, name)
            try:
                with open(path, encoding="utf-8") as handle:
                    events.update(json.load(handle))
                files += 1
            except (OSError, ValueError):
                events.add("<unreadable audit file>")
            try:
                os.remove(path)
            except OSError:
                pass
    return files, sorted(events)


# Fields that must hold for the self-test to pass (exit code 0).
REQUIRED = {
    "window_viewable": True,
    "window_title_set": True,
    "english_title": True,
    "selection_listed": True,
    "selection_hidden_during_scan": True,
    "scan_finished": True,
    "outcome_text_set": True,
    "worker_reaped": True,
    "shutdown_reaped": True,
    "locations_after_shutdown": 0,
    "helper_threads_after_shutdown": [],
    "gui_network_events": [],
    "worker_network_events": [],
    "large_result_finished": True,
    "large_result_rows": 10_000,
    "forced_cancel_finished": True,
    "forced_cancel_exit_code": 3,
    "forced_cancel_worker_reaped": True,
}
REQUIRED_WITH_FINDINGS = {"location_available_for_selected": True, "reveal_dialog_shown": True}
REQUIRED_WITH_REPORT = {
    "report_unverified_code": "REPORT_IDENTITY_UNVERIFIED",
    "report_scan_finished": True,
    "report_worker_reaped": True,
    "export_ready": True,
    "report_code": None,
    "report_second_write_code": "REPORT_DESTINATION_EXISTS",
    "report_renamed_root_code": "REPORT_IDENTITY_UNVERIFIED",
    "report_renamed_destination_absent": True,
}
REQUIRED_WITH_CANCEL = {
    "locations_cleared_on_new_selection": True,
    "cancel_finished": True,
    "cancel_exit_code": 3,
    "cancel_worker_reaped": True,
}
MAX_UI_GAP_SECONDS = 0.5


def failed_checks(summary, report_requested, cancel_requested):
    expected = dict(REQUIRED)
    if summary.get("finding_rows"):
        expected.update(REQUIRED_WITH_FINDINGS)
    if report_requested:
        expected.update(REQUIRED_WITH_REPORT)
    if cancel_requested:
        expected.update(REQUIRED_WITH_CANCEL)
    failures = sorted(key for key, value in expected.items() if key not in summary or summary[key] != value)
    if cancel_requested and not (0 <= summary.get("max_ui_gap_seconds_during_cancel", -1) < MAX_UI_GAP_SECONDS):
        failures.append("max_ui_gap_seconds_during_cancel")
    if not (0 <= summary.get("max_ui_gap_seconds_large_result", -1) < MAX_UI_GAP_SECONDS):
        failures.append("max_ui_gap_seconds_large_result")
    if not (0 <= summary.get("max_ui_gap_seconds_forced_cancel", -1) < MAX_UI_GAP_SECONDS):
        failures.append("max_ui_gap_seconds_forced_cancel")
    expected_workers = 2 + (1 if report_requested else 0) + (1 if cancel_requested else 0)
    if summary.get("worker_audit_files") != expected_workers:
        failures.append("worker_audit_files")
    return failures


def run(out_path, scan_paths, cancel_paths, report_path=None, deadline_seconds=90.0):
    from shareguard.gui import ShareGuardApp
    from shareguard.gui_session import ScanSession

    # Refer to the worker wrapper through the importable module (not
    # ``__main__``) so a spawned child can always unpickle it.
    from shareguard import gui_selftest as importable

    install_network_audit()
    importable.install_network_audit()
    out_dir = os.path.dirname(os.path.abspath(out_path))
    worker_audit = os.path.join(out_dir, "worker-audit-%d" % os.getpid())
    target = functools.partial(importable.audited_worker, worker_audit)
    factory = functools.partial(ScanSession, worker_target=target)

    summary = {}
    app = ShareGuardApp(session_factory=factory)
    root = app.root
    gaps = []
    last_tick = [time.monotonic()]
    stop_ticks = [False]

    def tick():
        now = time.monotonic()
        gaps.append(now - last_tick[0])
        last_tick[0] = now
        if not stop_ticks[0]:
            root.after(20, tick)

    def wait_until(predicate, limit):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            root.update()
            if predicate():
                return True
            time.sleep(0.01)
        return False

    started = time.monotonic()
    root.update()
    summary["window_viewable"] = bool(root.winfo_viewable())
    summary["window_title_set"] = bool(root.title())
    summary["default_language"] = app.language

    app.set_language("en")
    summary["english_title"] = root.title() == app.t("app.title")
    app.set_language("ko")
    app.apply_theme("dark")
    root.update()
    summary["dark_theme_bg"] = app.style.lookup("TFrame", "background")
    app.apply_theme("light")
    root.after(20, tick)

    # 1. Real scan of the given synthetic paths.
    app.add_paths(list(scan_paths))
    summary["selection_listed"] = app.selection_list.size() == len(scan_paths)
    app.start_scan()
    summary["selection_hidden_during_scan"] = app.selection_list.size() == 0
    ok = wait_until(lambda: app.final is not None and not app.rendering, deadline_seconds)
    summary["scan_finished"] = ok
    if ok:
        summary["scan_outcome"] = app.final["outcome"]
        summary["scan_exit_code"] = app._exit_code
        summary["finding_rows"] = len(app.tree.get_children())
        summary["finding_lines"] = sorted(
            {int(app.tree.item(item, "values")[5]) for item in app.tree.get_children()}
        )
        summary["issue_codes"] = sorted({row[0] for row in (app.issue_tree.item(i, "values") for i in app.issue_tree.get_children())})
        summary["outcome_text_set"] = bool(app.lbl_outcome.cget("text"))
        # Wait for the worker to be reaped while locations keep draining.
        session = app.session
        summary["worker_reaped"] = session is not None and session.reaped.wait(10)
        children = app.tree.get_children()
        if children:
            app.tree.selection_set(children[0])
            target = app.selected_target_id()
            summary["location_available_for_selected"] = app.locations.get(app.generation, target) is not None
            dialog = app.reveal_location(target)
            root.update()
            summary["reveal_dialog_shown"] = dialog is not None and bool(dialog.winfo_exists())
            app._close_dialog()
        if report_path:
            # This scan contains a missing selected root, so identity-bound
            # export must fail closed.  Then scan only the existing synthetic
            # roots and verify a successful exclusive-create report.
            summary["report_unverified_code"] = app.save_report(report_path)
            existing = [path for path in scan_paths if os.path.exists(path)]
            app.add_paths(existing)
            app.start_scan()
            report_ok = wait_until(lambda: app.final is not None and not app.rendering, deadline_seconds)
            summary["report_scan_finished"] = report_ok
            if report_ok:
                report_session = app.session
                summary["export_ready"] = bool(app._export_ready)
                summary["scope_message_received"] = bool(
                    report_session is not None and getattr(report_session, "_scope_message", None) is not None
                )
                summary["report_code"] = app.save_report(report_path)
                summary["report_second_write_code"] = app.save_report(report_path)
                moved_root = existing[0] + ".moved-for-selftest"
                moved_report = report_path + ".renamed-root"
                os.replace(existing[0], moved_root)
                try:
                    summary["report_renamed_root_code"] = app.save_report(moved_report)
                    summary["report_renamed_destination_absent"] = not os.path.exists(moved_report)
                finally:
                    os.replace(moved_root, existing[0])
                summary["report_worker_reaped"] = bool(
                    report_session is not None and report_session.reaped.wait(10)
                )

    # 2. A schema-valid maximum-row result exercises real spawned IPC and
    # batched rendering while a 20 ms Tk heartbeat remains active.
    existing = [path for path in scan_paths if os.path.exists(path)]
    large_target = functools.partial(importable.audited_large_result_worker, worker_audit)
    app._session_factory = functools.partial(ScanSession, worker_target=large_target)
    app.add_paths(existing[:1])
    root.update()
    gaps.clear()
    last_tick[0] = time.monotonic()
    app.start_scan()
    large_ok = wait_until(lambda: app.final is not None and not app.rendering, 30)
    summary["large_result_finished"] = large_ok
    summary["large_result_rows"] = len(app.tree.get_children()) if large_ok else -1
    summary["max_ui_gap_seconds_large_result"] = round(max(gaps) if gaps else -1.0, 3)
    if large_ok and app.session is not None:
        wait_until(lambda: app.session.reaped.is_set(), 10)

    # 3. Cancel a real scan of the given larger synthetic input.
    app._session_factory = factory
    if cancel_paths:
        app.add_paths(list(cancel_paths))
        summary["locations_cleared_on_new_selection"] = len(app.locations) == 0
        gaps.clear()
        app.start_scan()
        wait_until(lambda: app.session is not None and app.session.worker_alive(), 15)
        root.after(300, app.on_cancel)
        cancel_started = time.monotonic()
        ok = wait_until(lambda: app.final is not None, 30)
        summary["cancel_finished"] = ok
        summary["cancel_seconds"] = round(time.monotonic() - cancel_started, 3)
        if ok:
            summary["cancel_outcome"] = app.final["outcome"]
            summary["cancel_exit_code"] = app._exit_code
            session = app.session
            summary["cancel_worker_reaped"] = session is not None and session.reaped.wait(10)
            wait_until(lambda: False, 0.3)
        summary["max_ui_gap_seconds_during_cancel"] = round(max(gaps) if gaps else -1.0, 3)

    # 4. Force the fallback terminate path with a worker that deliberately
    # ignores the cooperative event, while continuing to pump real Tk events.
    app._session_factory = functools.partial(
        ScanSession,
        worker_target=importable.forced_cancel_worker,
        cancel_grace=0.3,
        kill_grace=0.5,
    )
    app.add_paths(existing[:1])
    root.update()
    gaps.clear()
    last_tick[0] = time.monotonic()
    app.start_scan()
    wait_until(lambda: app.session is not None and app.session.worker_alive(), 15)
    root.after(100, app.on_cancel)
    forced_final = wait_until(lambda: app.final is not None, 10)
    forced_session = app.session
    forced_reaped = wait_until(
        lambda: forced_session is not None and forced_session.reaped.is_set(), 10
    )
    summary["forced_cancel_finished"] = forced_final
    summary["forced_cancel_exit_code"] = app._exit_code if forced_final else None
    summary["forced_cancel_worker_reaped"] = forced_reaped
    summary["max_ui_gap_seconds_forced_cancel"] = round(max(gaps) if gaps else -1.0, 3)

    stop_ticks[0] = True
    session = app.session
    app.shutdown()
    if session is not None:
        summary["shutdown_reaped"] = session.reaped.wait(10)
    summary["locations_after_shutdown"] = len(app.locations)
    summary["helper_threads_after_shutdown"] = [t.name for t in threading.enumerate() if t.name.startswith("shareguard-")]
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    summary["gui_network_events"] = sorted(set(_network_events) | set(importable._network_events))
    summary["worker_audit_files"], summary["worker_network_events"] = collect_worker_audits(worker_audit)
    summary["frozen"] = bool(getattr(sys, "frozen", False))
    summary["failures"] = failed_checks(summary, bool(report_path), bool(cancel_paths))
    summary["passed"] = not summary["failures"]
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1, sort_keys=True)
    return 0 if summary["passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(prog="shareguard-gui-selftest")
    parser.add_argument("out")
    parser.add_argument("--scan", nargs="+", required=True)
    parser.add_argument("--cancel", nargs="*", default=[])
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    return run(args.out, args.scan, args.cancel, args.report)


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    raise SystemExit(main())
