"""Actual mapped-Tk client-bounds regression for the supported minimum GUI size."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shareguard import gui, locales  # noqa: E402


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
    if not ctypes.windll.user32.GetClientRect(hwnd, ctypes.byref(rect)):
        raise OSError("GetClientRect failed")
    return rect.right - rect.left, rect.bottom - rect.top


@unittest.skipUnless(os.name == "nt", "native client-bounds test requires Windows")
class NativeClientBoundsTests(unittest.TestCase):
    def test_all_post_result_actions_fit_and_hit_test_at_supported_sizes(self):
        import tkinter

        root = tkinter.Tk()
        app = gui.ShareGuardApp(root)
        self.addCleanup(self._cleanup, app, root)
        app.result = make_result()
        app.final = {"outcome": "result", "result": None, "code": None}
        app._exit_code = 1
        app._export_ready = True
        app._refresh_outcome()
        app._render_result()
        root.deiconify()
        root.lift()
        root.update_idletasks()
        root.update()

        essential = {
            "add_files": app.btn_add_files,
            "add_folder": app.btn_add_folder,
            "clear": app.btn_clear,
            "scan": app.btn_scan,
            "reveal": app.btn_reveal,
            "save": app.btn_save,
        }
        invoked = []
        for name, widget in essential.items():
            widget.configure(command=lambda n=name: invoked.append(n))

        evidence = []
        for width, height in ((720, 480), (900, 620)):
            for language in ("ko", "en"):
                for theme in ("light", "dark"):
                    with self.subTest(size=(width, height), language=language, theme=theme):
                        root.geometry("%dx%d+40+40" % (width, height))
                        app.set_language(language)
                        app.apply_theme(theme)
                        root.update_idletasks()
                        root.update()

                        actual_width, actual_height = client_size(root.winfo_id())
                        self.assertEqual((actual_width, actual_height), (width, height))
                        row = {
                            "requested": [width, height],
                            "client": [actual_width, actual_height],
                            "language": language,
                            "theme": theme,
                            "buttons": {},
                        }
                        for name, widget in essential.items():
                            self.assertTrue(widget.winfo_ismapped(), name)
                            self.assertTrue(widget.winfo_viewable(), name)
                            self.assertEqual(str(widget.cget("state")), "normal", name)
                            left = widget.winfo_rootx() - root.winfo_rootx()
                            top = widget.winfo_rooty() - root.winfo_rooty()
                            right = left + widget.winfo_width()
                            bottom = top + widget.winfo_height()
                            self.assertGreaterEqual(left, 0, name)
                            self.assertGreaterEqual(top, 0, name)
                            self.assertLessEqual(right, actual_width, name)
                            self.assertLessEqual(bottom, actual_height, name)
                            screen_x = widget.winfo_rootx() + widget.winfo_width() // 2
                            screen_y = widget.winfo_rooty() + widget.winfo_height() // 2
                            self.assertIs(root.winfo_containing(screen_x, screen_y), widget, name)
                            before = len(invoked)
                            widget.invoke()
                            self.assertEqual(invoked[before:], [name], name)
                            row["buttons"][name] = [left, top, right, bottom]

                        # Cancel is intentionally disabled after a result, but still
                        # must remain mapped and entirely inside the client.
                        cancel = app.btn_cancel
                        self.assertTrue(cancel.winfo_viewable())
                        cancel_left = cancel.winfo_rootx() - root.winfo_rootx()
                        cancel_top = cancel.winfo_rooty() - root.winfo_rooty()
                        cancel_right = cancel_left + cancel.winfo_width()
                        cancel_bottom = cancel_top + cancel.winfo_height()
                        self.assertGreaterEqual(cancel_left, 0)
                        self.assertGreaterEqual(cancel_top, 0)
                        self.assertLessEqual(cancel_right, actual_width)
                        self.assertLessEqual(cancel_bottom, actual_height)
                        self.assertEqual(str(cancel.cget("state")), "disabled")
                        row["buttons"]["cancel_disabled"] = [
                            cancel_left, cancel_top, cancel_right, cancel_bottom
                        ]

                        rendered = [app.tree.item(item, "values") for item in app.tree.get_children()]
                        self.assertEqual(len(rendered), 4)
                        for source, values in zip(app.result["findings"], rendered):
                            self.assertEqual(values[0], source["target_id"])
                            self.assertEqual(values[1], locales.finding_category(language, source["category"]))
                            self.assertEqual(values[2], source["rule_id"])
                            self.assertEqual(values[3], locales.finding_level(language, source["confidence"]))
                            self.assertEqual(values[4], locales.finding_level(language, source["severity"]))
                        evidence.append(row)

        output = {
            "schema": "shareguard.ui-native-bounds/1",
            "passed": True,
            "cases": len(evidence),
            "minimum_client": [720, 480],
            "normal_client": [900, 620],
            "combinations": evidence,
        }
        evidence_path = ROOT / ".git" / "agent-runs" / "ui-native-bounds.json"
        evidence_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @staticmethod
    def _cleanup(app, root):
        try:
            app.shutdown()
        except Exception:
            try:
                root.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
