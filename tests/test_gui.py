"""In-process GUI unit tests.

These drive the real ``ShareGuardApp`` widgets in this process with a fake
scan session (no worker process), plus real core results produced from
synthetic fixtures.  They are unit tests of Tk state, not a live/visible GUI
proof; see ``test_gui_live.py`` for that.
"""

from __future__ import annotations

import copy
import gc
import os
from contextlib import ExitStack
from types import SimpleNamespace
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from shareguard import gui, gui_session, locales, platform_support  # noqa: E402
from shareguard.model import CONFIDENCES, ISSUE_CODES, SEVERITIES  # noqa: E402
from shareguard.rules import RULES  # noqa: E402
from shareguard.scanner import scan_paths  # noqa: E402

CANARY = "SGCANARY4410"


def make_tk():
    try:
        import tkinter
    except ImportError:
        raise unittest.SkipTest("tkinter is not installed")
    try:
        root = tkinter.Tk()
    except tkinter.TclError as exc:  # no display (e.g. headless CI)
        raise unittest.SkipTest("Tk unavailable: %s" % type(exc).__name__)
    root.withdraw()
    return root


class FakeSession:
    """Stands in for ScanSession; the test decides the final outcome."""

    instances = []

    def __init__(self, generation, paths, policy_data, *, location_store=None, wall_timeout=None):
        self.generation = generation
        self.paths = paths
        self.policy_data = policy_data
        self.store = location_store
        self.wall_timeout = wall_timeout
        self.final = None
        self.cancelled = False
        self.closed = []
        self.reaped = threading.Event()
        self.progress = None
        self.export_ready = True
        FakeSession.instances.append(self)

    @property
    def finished(self):
        return self.final is not None

    def start(self):
        self.store.reset(self.generation)
        return True

    def poll(self):
        progress, self.progress = self.progress, None
        return progress

    def cancel(self):
        if self.final is None:
            self.cancelled = True
            return True
        return False

    def close(self, graceful=False):
        self.closed.append(graceful)
        self.reaped.set()

    def worker_alive(self):
        return False


class Fixtures:
    def __init__(self):
        artifacts = os.path.join(ROOT, "artifacts")
        os.makedirs(artifacts, exist_ok=True)
        self.base = tempfile.mkdtemp(prefix="gui-unit-", dir=artifacts)
        self.secret = os.path.join(self.base, "secret_" + CANARY + ".txt")
        with open(self.secret, "w", encoding="utf-8") as handle:
            handle.write("x\n" + "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n")
        self.missing = os.path.join(self.base, "missing_" + CANARY)

    def cleanup(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def real_result(self, locations=None):
        def on_location(tid, path, member):
            if locations is not None:
                locations.append((tid, os.fspath(path), member))

        result = scan_paths([self.secret, self.missing], location_callback=on_location)
        return gui_session.validate_core_result(result.to_dict())


class LocaleTests(unittest.TestCase):
    def test_catalogs_complete(self):
        for language in locales.available_languages():
            self.assertEqual(locales.missing_keys(language), [], language)

    def test_every_core_issue_code_is_described(self):
        for code in ISSUE_CODES:
            for language in ("ko", "en"):
                self.assertNotEqual(locales.text(language, "issue." + code), "issue." + code)

    def test_unknown_language_falls_back_to_korean(self):
        self.assertEqual(locales.text("xx", "btn.scan"), locales.text("ko", "btn.scan"))

    def test_english_label_count_summary_and_minimal_status(self):
        for count in (0, 1, 7):
            with self.subTest(count=count):
                self.assertEqual(
                    locales.text(
                        "en", "label.summary", findings=count, files=count,
                        entries=count, issues=count,
                    ),
                    "Findings: {0} · Files: {0} · ZIP entries: {0} · Not scanned: {0}".format(count),
                )
                self.assertEqual(
                    locales.text("en", "status.scanning", targets=count),
                    "Scanning... Targets: %d" % count,
                )
                self.assertEqual(
                    locales.text("ko", "status.scanning", targets=count),
                    "점검 중... 대상 %d개" % count,
                )

    def test_finding_enum_catalogs_cover_exact_core_values(self):
        categories = {rule.category for rule in RULES}
        self.assertEqual(set(locales.FINDING_CATEGORY_KEYS), categories)
        self.assertEqual(set(locales.FINDING_LEVEL_KEYS), set(CONFIDENCES))
        self.assertEqual(set(locales.FINDING_LEVEL_KEYS), set(SEVERITIES))
        expected = {
            "ko": {
                "service_token": "서비스 토큰",
                "credential_assignment": "비밀번호·키 값",
                "private_key": "개인 키",
                "url_credential": "URL 로그인 정보",
                "high": "높음", "medium": "보통", "low": "낮음",
            },
            "en": {
                "service_token": "Service Token",
                "credential_assignment": "Password or Key Value",
                "private_key": "Private Key",
                "url_credential": "URL Login Information",
                "high": "High", "medium": "Medium", "low": "Low",
            },
        }
        for language, values in expected.items():
            with self.subTest(language=language):
                for category in categories:
                    self.assertEqual(locales.finding_category(language, category), values[category])
                for level in CONFIDENCES:
                    self.assertEqual(locales.finding_level(language, level), values[level])
                unknown = "RAW_ENUM_" + CANARY
                self.assertNotIn(unknown, locales.finding_category(language, unknown))
                self.assertNotIn(unknown, locales.finding_level(language, unknown))


class CoreIntegrationTests(unittest.TestCase):
    """Real core results through the GUI's validation and view helpers."""

    def setUp(self):
        self.fx = Fixtures()
        self.addCleanup(self.fx.cleanup)

    def test_strict_validation_and_incomplete_reason_visible(self):
        validated = self.fx.real_result()
        self.assertEqual(validated.exit_code, 2)
        rows = gui.issue_rows(validated.data, "ko")
        self.assertEqual(rows[0][0], "PATH_NOT_FOUND")
        self.assertEqual(rows[0][1], locales.text("ko", "issue.PATH_NOT_FOUND"))
        findings = gui.finding_rows(validated.data)
        self.assertEqual(findings[0][2], "private-key.openssh")
        self.assertNotIn(CANARY, repr(validated.data))

    def test_all_finding_values_localize_without_mutating_result(self):
        by_category = {}
        for rule in RULES:
            by_category.setdefault(rule.category, rule.rule_id)
        findings = []
        index = 0
        for category in sorted(by_category):
            for level in CONFIDENCES:
                index += 1
                findings.append({
                    "target_id": "T%d" % index,
                    "category": category,
                    "rule_id": by_category[category],
                    "confidence": level,
                    "severity": level,
                    "line": index,
                    "count": 1,
                })
        result = {"findings": findings}
        before = copy.deepcopy(result)
        for language in ("ko", "en"):
            rows = gui.finding_rows(result, language)
            self.assertEqual(len(rows), len(findings))
            for finding, row in zip(findings, rows):
                self.assertEqual(row[0], finding["target_id"])
                self.assertEqual(row[1], locales.finding_category(language, finding["category"]))
                self.assertEqual(row[2], finding["rule_id"])
                self.assertEqual(row[3], locales.finding_level(language, finding["confidence"]))
                self.assertEqual(row[4], locales.finding_level(language, finding["severity"]))
        self.assertEqual(result, before)

        unknown = "RAW_ENUM_" + CANARY
        unsafe = {"findings": [{
            "target_id": "T1", "category": unknown, "rule_id": "rule.raw-id",
            "confidence": unknown, "severity": unknown, "line": 1, "count": 1,
        }]}
        for language in ("ko", "en"):
            row = gui.finding_rows(unsafe, language)[0]
            self.assertEqual(row[0], "T1")
            self.assertEqual(row[2], "rule.raw-id")
            self.assertNotIn(unknown, repr(row))

    def test_strict_validation_rejects_tampering(self):
        data = self.fx.real_result().data
        tampered = [
            dict(data, extra=1),
            dict(data, outcome="no_findings"),
            dict(data, issues=[{"code": "C:\\x", "target_id": None}]),
            dict(data, findings=[dict(data["findings"][0], snippet="secret")]),
        ]
        for payload in tampered:
            with self.subTest(keys=sorted(payload)[:3]):
                with self.assertRaises(Exception):
                    gui_session.validate_core_result(payload)


class AppTests(unittest.TestCase):
    def setUp(self):
        FakeSession.instances = []
        self.root = make_tk()
        self.addCleanup(self._destroy)
        self.real_platform_predicate = gui.supported_public_platform
        self.platform_patch = mock.patch.object(gui, "supported_public_platform", return_value=True)
        self.platform_patch.start()
        self.addCleanup(self.platform_patch.stop)
        self.app = gui.ShareGuardApp(self.root, session_factory=FakeSession)
        self.fx = Fixtures()
        self.addCleanup(self.fx.cleanup)

    def _destroy(self):
        try:
            self.app.shutdown()
        except Exception:
            try:
                self.root.destroy()
            except Exception:
                pass
        # Tk Variable finalizers must run on the creating thread, not later in
        # one of the session concurrency-test threads in this same process.
        self.app = None
        gc.collect()

    def pump(self, seconds=0.0):
        end = time.monotonic() + seconds
        while True:
            self.root.update()
            if time.monotonic() >= end:
                break
            time.sleep(0.01)

    def finish(self, validated=None, outcome="result", code=None):
        session = FakeSession.instances[-1]
        session.final = {"outcome": outcome, "result": validated, "code": code}
        self.pump(0.3)
        return session

    def test_shared_platform_guard_refuses_without_worker_or_input_touch(self):
        sentinel = "C:/must-not-be-opened-" + CANARY
        cases = (
            ("non_windows", {"os_name": "posix", "sys_platform": "linux", "pointer": 8, "version": (10, 19045)}),
            ("old_windows", {"os_name": "nt", "sys_platform": "win32", "pointer": 8, "version": (10, 10239)}),
            ("32_bit", {"os_name": "nt", "sys_platform": "win32", "pointer": 4, "version": (10, 19045)}),
            ("missing_version", {"os_name": "nt", "sys_platform": "win32", "pointer": 8, "version": None}),
        )
        for label, case in cases:
            with self.subTest(case=label), ExitStack() as stack:
                self.app.paths = []
                self.app.add_paths([sentinel])
                FakeSession.instances.clear()
                stack.enter_context(mock.patch.object(platform_support.os, "name", case["os_name"]))
                stack.enter_context(mock.patch.object(platform_support.sys, "platform", case["sys_platform"]))
                stack.enter_context(mock.patch.object(platform_support.struct, "calcsize", return_value=case["pointer"]))
                if case["version"] is None:
                    stack.enter_context(mock.patch.object(
                        platform_support.sys, "getwindowsversion", create=True,
                        side_effect=AttributeError("synthetic missing version"),
                    ))
                else:
                    major, build = case["version"]
                    stack.enter_context(mock.patch.object(
                        platform_support.sys, "getwindowsversion", create=True,
                        return_value=SimpleNamespace(major=major, build=build),
                    ))
                stack.enter_context(mock.patch.object(
                    gui, "supported_public_platform", side_effect=self.real_platform_predicate,
                ))
                backend = stack.enter_context(mock.patch(
                    "shareguard.scanner.scan_paths", side_effect=AssertionError("input backend called"),
                ))

                self.assertFalse(platform_support.is_public_platform_supported())
                self.assertFalse(self.app.start_scan())
                backend.assert_not_called()
                self.assertEqual(FakeSession.instances, [])
                self.assertEqual(
                    self.app.final,
                    {"outcome": "error", "result": None, "code": "unsupported_platform"},
                )
                self.assertEqual(self.app._exit_code, 4)
                self.assertIn(sentinel, self.app.paths)
                self.assertNotIn(sentinel, self.app.lbl_outcome.cget("text"))

    def test_defaults_language_and_theme(self):
        self.assertEqual(self.root.title(), locales.text("ko", "app.title"))
        self.app.set_language("en")
        self.assertEqual(self.app.btn_scan.cget("text"), locales.text("en", "btn.scan"))
        self.app.apply_theme("dark")
        self.assertEqual(self.app.style.lookup("TFrame", "background"), gui.THEMES["dark"]["bg"])
        self.app.apply_theme("light")
        self.assertEqual(self.app.style.lookup("TFrame", "background"), gui.THEMES["light"]["bg"])

    def test_selection_shown_only_while_selecting(self):
        self.app.add_paths([self.fx.secret, self.fx.missing])
        self.assertEqual(self.app.selection_list.size(), 2)
        self.assertTrue(self.app.start_scan())
        self.assertEqual(self.app.selection_list.size(), 0)
        self.assertEqual(str(self.app.btn_scan.cget("state")), "disabled")
        self.assertEqual(str(self.app.btn_cancel.cget("state")), "normal")
        session = FakeSession.instances[-1]
        self.assertEqual(session.wall_timeout, 120.0 + gui_session.STARTUP_GRACE_SECONDS)

    def test_result_render_reveal_and_cleanup(self):
        locations = []
        validated = self.fx.real_result(locations)
        self.app.add_paths([self.fx.secret, self.fx.missing])
        self.app.start_scan()
        session = FakeSession.instances[-1]
        for tid, path, member in locations:
            self.app.locations.put(session.generation, tid, path, member)
        self.finish(validated)
        self.assertEqual(session.closed, [True])  # reaped right away, gracefully
        self.assertEqual(len(self.app.tree.get_children()), 1)
        issue_values = self.app.issue_tree.item(self.app.issue_tree.get_children()[0], "values")
        self.assertEqual(issue_values[0], "PATH_NOT_FOUND")
        self.assertIn(locales.text("ko", "outcome.incomplete"), self.app.lbl_outcome.cget("text"))
        self.assertEqual(str(self.app.btn_save.cget("state")), "normal")
        finding_values = self.app.tree.item(self.app.tree.get_children()[0], "values")
        self.assertEqual(finding_values[1], locales.finding_category("ko", "private_key"))
        self.assertEqual(finding_values[3], locales.finding_level("ko", "high"))
        original_result = copy.deepcopy(self.app.result)
        self.app.set_language("en")
        finding_values = self.app.tree.item(self.app.tree.get_children()[0], "values")
        self.assertEqual(finding_values[1], locales.finding_category("en", "private_key"))
        self.assertEqual(finding_values[3], locales.finding_level("en", "high"))
        self.assertEqual(self.app.result, original_result)
        self.assertEqual(
            self.app.lbl_summary.cget("text"),
            "Findings: 1 · Files: 1 · ZIP entries: 0 · Not scanned: 1",
        )
        self.app.set_language("ko")
        for widget in (self.app.lbl_outcome, self.app.lbl_summary, self.app.lbl_status):
            self.assertNotIn(CANARY, widget.cget("text"))

        with mock.patch("tkinter.messagebox.showinfo") as info:
            self.app.on_reveal()  # nothing selected
            info.assert_called_once()
        self.app.tree.selection_set(self.app.tree.get_children()[0])
        with mock.patch("tkinter.messagebox.askokcancel", return_value=False):
            self.app.on_reveal()
        self.assertIsNone(self.app._dialog)
        clipboard = mock.Mock(side_effect=AssertionError("clipboard used"))
        with mock.patch("tkinter.messagebox.askokcancel", return_value=True) as ask, \
                mock.patch.object(self.root, "clipboard_append", clipboard), \
                mock.patch.object(self.root, "clipboard_clear", clipboard):
            self.app.on_reveal()
            self.assertEqual(ask.call_args.kwargs.get("icon"), "warning")
        dialog = self.app._dialog
        self.assertIsNotNone(dialog)
        entries = [w for w in dialog.winfo_children()[0].winfo_children() if w.winfo_class() == "TEntry"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].get(), self.fx.secret)
        self.assertEqual(str(entries[0].cget("state")), "readonly")

        # A new selection forgets results, locations and the dialog.
        self.app.add_paths([self.fx.secret])
        self.assertIsNone(self.app._dialog)
        self.assertEqual(len(self.app.locations), 0)
        self.assertEqual(self.app.tree.get_children(), ())
        self.assertEqual(self.app.paths, [self.fx.secret])

    def test_reveal_unavailable_location(self):
        self.app.add_paths([self.fx.secret, self.fx.missing])
        self.app.start_scan()
        self.finish(self.fx.real_result())
        with mock.patch("tkinter.messagebox.showinfo") as info:
            self.assertIsNone(self.app.reveal_location("T1"))
            self.assertIn(locales.text("ko", "dlg.reveal_unavailable"), info.call_args.args)

    def test_error_and_cancelled_outcomes(self):
        self.app.add_paths([self.fx.secret])
        self.app.start_scan()
        self.finish(outcome="error", code="timeout")
        self.assertIn("timeout", self.app.lbl_outcome.cget("text"))
        self.assertEqual(str(self.app.btn_save.cget("state")), "disabled")
        self.app.add_paths([self.fx.secret])
        self.app.start_scan()
        self.app.on_cancel()
        self.assertTrue(FakeSession.instances[-1].cancelled)
        self.finish(outcome="cancelled")
        self.assertEqual(self.app.lbl_outcome.cget("text"), locales.text("ko", "outcome.cancelled"))
        self.app.add_paths([self.fx.secret])
        self.app.start_scan()
        self.finish(outcome="error", code="C:\\Users\\leak")  # not a fixed code
        self.assertNotIn("leak", self.app.lbl_outcome.cget("text"))

    def test_progress_updates_status(self):
        self.app.add_paths([self.fx.secret])
        self.app.start_scan()
        FakeSession.instances[-1].progress = {"targets": 7, "findings": 2, "files": 3, "entries": 4}
        self.pump(0.3)
        self.assertEqual(
            self.app.lbl_status.cget("text"),
            locales.text("ko", "status.scanning", targets=7),
        )

    def test_report_error_codes_are_fixed(self):
        from shareguard import safeio

        self.app.add_paths([self.fx.secret, self.fx.missing])
        self.app.start_scan()
        self.finish(self.fx.real_result())
        with mock.patch.object(safeio, "write_report", side_effect=safeio.ReportError("REPORT_DESTINATION_EXISTS")):
            self.assertEqual(self.app.save_report("unused.json"), "REPORT_DESTINATION_EXISTS")
        with mock.patch.object(safeio, "write_report", side_effect=RuntimeError("C:\\secret\\path")):
            self.assertEqual(self.app.save_report("unused.json"), "REPORT_WRITE_FAILED")
        with mock.patch.object(safeio, "write_report") as write:
            self.assertIsNone(self.app.save_report("dest.json"))
            args = write.call_args.args
            self.assertIs(args[0], self.app.scan_result)
            self.assertEqual(args[2], [self.fx.secret, self.fx.missing])

    def test_large_result_renders_in_batches(self):
        validated = self.fx.real_result()
        data = dict(validated.data)
        finding = data["findings"][0]
        data["findings"] = [dict(finding, line=i + 1) for i in range(10_000)]
        self.app.add_paths([self.fx.secret])
        self.app.start_scan()
        FakeSession.instances[-1].final = {
            "outcome": "result", "result": gui_session.ValidatedResult(None, data, 1), "code": None}
        gaps = []
        last = time.monotonic()
        deadline = last + 30
        self.root.update()
        while (self.app.rendering or not self.app.tree.get_children()) and time.monotonic() < deadline:
            self.root.update()
            now = time.monotonic()
            gaps.append(now - last)
            last = now
        self.assertEqual(len(self.app.tree.get_children()), 10_000)
        self.assertLess(max(gaps), 0.25)

    def test_shutdown_clears_memory_and_stops_session(self):
        self.app.add_paths([self.fx.secret])
        self.app.start_scan()
        session = FakeSession.instances[-1]
        self.app.locations.put(session.generation, "T1", "C:/x", None)
        self.app.shutdown()
        self.assertTrue(session.cancelled)
        self.assertEqual(session.closed, [False])
        self.assertEqual(len(self.app.locations), 0)
        self.assertEqual(self.app.paths, [])

    def test_tk_access_off_ui_thread_is_refused(self):
        errors = []

        def other():
            try:
                self.app.set_language("en")
            except RuntimeError as exc:
                errors.append(exc)

        thread = threading.Thread(target=other)
        thread.start()
        thread.join()
        self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
