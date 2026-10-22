"""Actual mapped-Tk client-bounds regression for the supported minimum GUI size."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import gc
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
import weakref

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shareguard import gui, locales  # noqa: E402


if os.name == "nt":
    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _get_client_rect = _user32.GetClientRect
    _get_client_rect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _get_client_rect.restype = wintypes.BOOL
else:
    _get_client_rect = None


def make_result():
    findings = [
        {
            "target_id": "T1", "category": "private_key", "rule_id": "private-key.pem",
            "confidence": "high", "severity": "high", "line": 1, "count": 1,
        },
        {
            "target_id": "T2", "category": "service_token", "rule_id": "token.aws-access-key-id",
            "confidence": "high", "severity": "medium", "line": 2, "count": 1,
        },
        {
            "target_id": "T3", "category": "credential_assignment", "rule_id": "assignment.password",
            "confidence": "low", "severity": "medium", "line": 3, "count": 1,
        },
        {
            "target_id": "T4", "category": "url_credential", "rule_id": "url.credentials",
            "confidence": "medium", "severity": "high", "line": 4, "count": 1,
        },
    ]
    return {
        "outcome": "findings",
        "completeness": "complete",
        "findings": findings,
        "issues": [],
        "counts": {
            "files_scanned": 4,
            "archive_entries_scanned": 0,
        },
    }


def client_size(hwnd):
    rect = wintypes.RECT()
    if not _get_client_rect(wintypes.HWND(hwnd), ctypes.byref(rect)):
        raise ctypes.WinError(ctypes.get_last_error())
    return rect.right - rect.left, rect.bottom - rect.top


def settle_client(root, expected, timeout=2.0):
    """Wait for a mapped native client to reach a stable requested size."""
    deadline = time.monotonic() + timeout
    previous = None
    stable = 0
    samples = []
    while time.monotonic() < deadline:
        root.update_idletasks()
        root.update()
        measured = client_size(root.winfo_id())
        if not samples or measured != samples[-1]:
            samples.append(measured)
        if root.winfo_viewable() and measured == expected and measured == previous:
            stable += 1
            if stable >= 2:
                return measured, samples
        else:
            stable = 0
        previous = measured
        root.lift()
        time.sleep(0.01)
    return previous, samples


@unittest.skipUnless(os.name == "nt", "native client-bounds test requires Windows")
class NativeClientBoundsTests(unittest.TestCase):
    def test_all_post_result_actions_fit_and_hit_test_at_supported_sizes(self):
        import tkinter

        self.root = tkinter.Tk()
        self.app = gui.ShareGuardApp(self.root)
        self._install_lifecycle_proof()
        self.addCleanup(self._cleanup)

        self.app.result = make_result()
        self.app.final = {"outcome": "result", "result": None, "code": None}
        self.app._exit_code = 1
        self.app._export_ready = True
        self.app._refresh_outcome()
        self.app._render_result()
        self.root.deiconify()
        self.root.lift()
        self.root.update_idletasks()
        self.root.update()

        invoked = []
        self._configure_actions(invoked)

        evidence = []
        for width, height in ((720, 480), (900, 620)):
            for language in ("ko", "en"):
                for theme in ("light", "dark"):
                    with self.subTest(size=(width, height), language=language, theme=theme):
                        self._measure_and_assert_case(
                            width, height, language, theme, invoked, evidence
                        )

        output = {
            "schema": "shareguard.ui-native-bounds-measurements/1",
            "measurements_only": True,
            "test_outcome_source": "unittest result",
            "cases": len(evidence),
            "minimum_client": [720, 480],
            "normal_client": [900, 620],
            "combinations": evidence,
        }
        evidence_path = ROOT / "artifacts" / "ui-native-bounds.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def _install_lifecycle_proof(self):
        creator_thread_id = threading.get_ident()
        events = []

        def callback(name):
            def record(_reference):
                events.append({"object": name, "thread_id": threading.get_ident()})

            return record

        self._creator_thread_id = creator_thread_id
        self._lifecycle_events = events
        self._app_ref = weakref.ref(self.app, callback("app"))
        self._root_ref = weakref.ref(self.root, callback("root"))

    def _essential_widgets(self):
        return {
            "add_files": self.app.btn_add_files,
            "add_folder": self.app.btn_add_folder,
            "clear": self.app.btn_clear,
            "scan": self.app.btn_scan,
            "reveal": self.app.btn_reveal,
            "save": self.app.btn_save,
        }

    def _configure_actions(self, invoked):
        essential = self._essential_widgets()
        widget = None
        try:
            for name, widget in essential.items():
                widget.configure(command=lambda n=name: invoked.append(n))
        finally:
            widget = None
            essential.clear()

    def _measure_and_assert_case(
        self, width, height, language, theme, invoked, evidence
    ):
        essential = None
        widget = None
        cancel = None
        rendered = None
        source = None
        values = None
        try:
            self.root.geometry("%dx%d+40+40" % (width, height))
            self.app.set_language(language)
            self.app.apply_theme(theme)
            (actual_width, actual_height), samples = settle_client(
                self.root, (width, height)
            )
            row = {
                "requested": [width, height],
                "client": [actual_width, actual_height],
                "settle_samples": [list(sample) for sample in samples],
                "language": language,
                "theme": theme,
                "buttons": {},
            }
            essential = self._essential_widgets()
            for name, widget in essential.items():
                left = widget.winfo_rootx() - self.root.winfo_rootx()
                top = widget.winfo_rooty() - self.root.winfo_rooty()
                right = left + widget.winfo_width()
                bottom = top + widget.winfo_height()
                screen_x = widget.winfo_rootx() + widget.winfo_width() // 2
                screen_y = widget.winfo_rooty() + widget.winfo_height() // 2
                before = len(invoked)
                widget.invoke()
                row["buttons"][name] = {
                    "rect": [left, top, right, bottom],
                    "mapped": bool(widget.winfo_ismapped()),
                    "viewable": bool(widget.winfo_viewable()),
                    "state": str(widget.cget("state")),
                    "hit": self.root.winfo_containing(screen_x, screen_y) is widget,
                    "invoked": invoked[before:] == [name],
                }

            # Cancel is intentionally disabled after a result. Its center
            # must still hit the native widget, and invoke must stay inert.
            cancel = self.app.btn_cancel
            cancel_left = cancel.winfo_rootx() - self.root.winfo_rootx()
            cancel_top = cancel.winfo_rooty() - self.root.winfo_rooty()
            cancel_right = cancel_left + cancel.winfo_width()
            cancel_bottom = cancel_top + cancel.winfo_height()
            cancel_x = cancel.winfo_rootx() + cancel.winfo_width() // 2
            cancel_y = cancel.winfo_rooty() + cancel.winfo_height() // 2
            before_cancel = len(invoked)
            cancel.invoke()
            row["buttons"]["cancel"] = {
                "rect": [cancel_left, cancel_top, cancel_right, cancel_bottom],
                "mapped": bool(cancel.winfo_ismapped()),
                "viewable": bool(cancel.winfo_viewable()),
                "state": str(cancel.cget("state")),
                "hit": self.root.winfo_containing(cancel_x, cancel_y) is cancel,
                "disabled_invoke_suppressed": len(invoked) == before_cancel,
            }

            rendered = [
                self.app.tree.item(item, "values")
                for item in self.app.tree.get_children()
            ]
            row["rendered_rows"] = len(rendered)
            evidence.append(row)

            # Record all native measurements before asserting so a hosted
            # failure remains diagnosable even when later tests use threads.
            self.assertEqual((actual_width, actual_height), (width, height))
            for name in essential:
                measured = row["buttons"][name]
                left, top, right, bottom = measured["rect"]
                self.assertTrue(measured["mapped"], name)
                self.assertTrue(measured["viewable"], name)
                self.assertEqual(measured["state"], "normal", name)
                self.assertGreaterEqual(left, 0, name)
                self.assertGreaterEqual(top, 0, name)
                self.assertLessEqual(right, actual_width, name)
                self.assertLessEqual(bottom, actual_height, name)
                self.assertTrue(measured["hit"], name)
                self.assertTrue(measured["invoked"], name)

            cancel_measured = row["buttons"]["cancel"]
            left, top, right, bottom = cancel_measured["rect"]
            self.assertTrue(cancel_measured["mapped"], "cancel")
            self.assertTrue(cancel_measured["viewable"], "cancel")
            self.assertEqual(cancel_measured["state"], "disabled", "cancel")
            self.assertGreaterEqual(left, 0, "cancel")
            self.assertGreaterEqual(top, 0, "cancel")
            self.assertLessEqual(right, actual_width, "cancel")
            self.assertLessEqual(bottom, actual_height, "cancel")
            self.assertTrue(cancel_measured["hit"], "cancel")
            self.assertTrue(
                cancel_measured["disabled_invoke_suppressed"], "cancel"
            )

            self.assertEqual(len(rendered), 4)
            for source, values in zip(self.app.result["findings"], rendered):
                self.assertEqual(values[0], source["target_id"])
                self.assertEqual(
                    values[1],
                    locales.finding_category(language, source["category"]),
                )
                self.assertEqual(values[2], source["rule_id"])
                self.assertEqual(
                    values[3],
                    locales.finding_level(language, source["confidence"]),
                )
                self.assertEqual(
                    values[4],
                    locales.finding_level(language, source["severity"]),
                )
        finally:
            # A retained assertion traceback may keep this frame alive. Remove
            # every local strong reference that can lead back to Tk before the
            # testcase cleanup drops its two owning instance fields.
            source = None
            values = None
            rendered = None
            cancel = None
            widget = None
            if essential is not None:
                essential.clear()
            essential = None

    def _cleanup(self):
        shutdown_failed = False
        fallback_failed = False
        try:
            if self.app is not None:
                self.app.shutdown()
        except Exception:
            shutdown_failed = True
            try:
                if self.root is not None:
                    self.root.destroy()
            except Exception:
                fallback_failed = True

        # These are the only intended strong owners retained by the testcase.
        # Drop them on the creating thread before collecting Tk widget cycles.
        self.app = None
        self.root = None
        collected = gc.collect()

        app_finalized = self._app_ref() is None
        root_finalized = self._root_ref() is None
        lifecycle = {
            "schema": "shareguard.ui-native-lifecycle/1",
            "creator_thread_id": self._creator_thread_id,
            "callbacks": list(self._lifecycle_events),
            "app_finalized": app_finalized,
            "root_finalized": root_finalized,
            "gc_collected": collected,
            "shutdown_failed": shutdown_failed,
            "fallback_failed": fallback_failed,
        }
        evidence_path = ROOT / "artifacts" / "ui-native-lifecycle.json"
        evidence_path.parent.mkdir(parents=True, exist_ok=True)
        evidence_path.write_text(
            json.dumps(lifecycle, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.assertFalse(shutdown_failed, "ShareGuardApp.shutdown raised")
        self.assertFalse(fallback_failed, "fallback Tk destroy raised")
        self.assertTrue(app_finalized, "ShareGuardApp remained strongly referenced")
        self.assertTrue(root_finalized, "Tk root remained strongly referenced")
        self.assertCountEqual(
            [event["object"] for event in self._lifecycle_events],
            ["app", "root"],
        )
        for event in self._lifecycle_events:
            self.assertEqual(event["thread_id"], self._creator_thread_id)


if __name__ == "__main__":
    unittest.main()
