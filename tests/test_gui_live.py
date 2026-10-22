"""Live GUI test: real Tk window, real spawned scans, synthetic fixtures.

Runs ``shareguard.gui_selftest`` in a separate GUI process (``pythonw.exe`` on
Windows, so no console window) and checks its sanitized summary.  This proves
Tk-level behaviour and the real core/worker pipeline.  It does not inspect
native window pixels; visual checks are a separate manual/automation step.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
CANARY = "SGCANARY7781"
LIVE_TIMEOUT = 150


def input_hashes(paths):
    result = {}
    for selected in paths:
        if os.path.isfile(selected):
            candidates = [selected]
        elif os.path.isdir(selected):
            candidates = [os.path.join(folder, name) for folder, _, names in os.walk(selected) for name in names]
        else:
            continue
        for path in candidates:
            digest = hashlib.sha256()
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
            result[path] = digest.hexdigest()
    return result


def gui_python():
    exe = sys.executable
    if os.name == "nt":
        candidate = os.path.join(os.path.dirname(exe), "pythonw.exe")
        if os.path.exists(candidate):
            return candidate
    return exe


def display_available():
    try:
        import tkinter  # noqa: F401
    except ImportError:
        return False
    if os.name == "nt" or sys.platform == "darwin":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def make_fixtures(base):
    """Create synthetic inputs; secrets are assembled at runtime."""
    clean = os.path.join(base, "clean.txt")
    with open(clean, "w", encoding="utf-8") as handle:
        handle.write("nothing to see here\n")
    secret_dir = os.path.join(base, "dir_" + CANARY)
    os.mkdir(secret_dir)
    header = "-----BEGIN " + "PRIVATE KEY-----"
    with open(os.path.join(secret_dir, "key_" + CANARY + ".pem"), "w", encoding="utf-8") as handle:
        handle.write("first line\n" + header + "\n" + CANARY + "\n")
    missing = os.path.join(base, "missing_" + CANARY + ".txt")
    bulk = os.path.join(base, "bulk")
    os.mkdir(bulk)
    line = ("lorem ipsum dolor sit amet " * 4 + "\n") * 40
    for index in range(4000):
        with open(os.path.join(bulk, "f%04d.txt" % index), "w", encoding="utf-8") as handle:
            handle.write(line)
    return [clean, secret_dir, missing], [bulk]


@unittest.skipUnless(os.name == "nt" and display_available(), "live public GUI requires Windows and a display")
class LiveGuiTest(unittest.TestCase):
    def test_live_launch_scan_reveal_export_cancel(self):
        artifacts = os.path.join(ROOT, "artifacts")
        os.makedirs(artifacts, exist_ok=True)
        base = tempfile.mkdtemp(prefix="gui-live-", dir=artifacts)
        self.addCleanup(shutil.rmtree, base, True)
        scan_paths, cancel_paths = make_fixtures(base)
        before_hashes = input_hashes(scan_paths + cancel_paths)
        out_dir = os.path.join(base, "out")
        os.mkdir(out_dir)
        summary_path = os.path.join(out_dir, "summary.json")
        report_path = os.path.join(out_dir, "report.json")

        env = dict(os.environ)
        env["PYTHONPATH"] = SRC
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [gui_python(), "-m", "shareguard.gui_selftest", summary_path,
                   "--scan", *scan_paths, "--cancel", *cancel_paths, "--report", report_path]
        started = time.monotonic()
        process = subprocess.Popen(command, cwd=out_dir, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            _, stderr = process.communicate(timeout=LIVE_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()  # only the process this test started
            process.communicate()
            self.fail("live GUI self-test timed out")
        elapsed = time.monotonic() - started
        self.assertEqual(process.returncode, 0, (stderr or b"")[-2000:])

        with open(summary_path, encoding="utf-8") as handle:
            text = handle.read()
        summary = json.loads(text)
        self.assertNotIn(CANARY, text)
        self.assertNotIn(base, text)

        self.assertTrue(summary["window_viewable"])
        self.assertEqual(summary["default_language"], "ko")
        self.assertTrue(summary["english_title"])
        self.assertEqual(summary["dark_theme_bg"], "#1e2024")
        self.assertTrue(summary["selection_listed"])
        self.assertTrue(summary["selection_hidden_during_scan"])

        self.assertTrue(summary["scan_finished"])
        self.assertEqual(summary["scan_outcome"], "result")
        self.assertEqual(summary["scan_exit_code"], 2)  # missing input -> incomplete
        self.assertGreaterEqual(summary["finding_rows"], 1)
        self.assertIn(2, summary["finding_lines"])
        self.assertIn("PATH_NOT_FOUND", summary["issue_codes"])
        self.assertTrue(summary["outcome_text_set"])
        self.assertTrue(summary["worker_reaped"])
        self.assertTrue(summary["location_available_for_selected"])
        self.assertTrue(summary["reveal_dialog_shown"])
        self.assertEqual(summary["report_unverified_code"], "REPORT_IDENTITY_UNVERIFIED")
        self.assertTrue(summary["report_scan_finished"])
        self.assertTrue(summary["report_worker_reaped"])
        self.assertTrue(summary["export_ready"])
        self.assertTrue(summary["scope_message_received"])
        self.assertIsNone(summary["report_code"])
        self.assertEqual(summary["report_second_write_code"], "REPORT_DESTINATION_EXISTS")
        self.assertEqual(summary["report_renamed_root_code"], "REPORT_IDENTITY_UNVERIFIED")
        self.assertTrue(summary["report_renamed_destination_absent"])
        with open(report_path, encoding="utf-8") as handle:
            report = handle.read()
        self.assertNotIn(CANARY, report)
        self.assertNotIn(base, report)
        self.assertNotIn("PRIVATE KEY", report)
        self.assertEqual(input_hashes(scan_paths + cancel_paths), before_hashes)

        self.assertTrue(summary["large_result_finished"])
        self.assertEqual(summary["large_result_rows"], 10_000)
        self.assertLess(summary["max_ui_gap_seconds_large_result"], 0.5)

        self.assertTrue(summary["locations_cleared_on_new_selection"])
        self.assertTrue(summary["cancel_finished"])
        self.assertEqual(summary["cancel_exit_code"], 3)
        self.assertTrue(summary["cancel_worker_reaped"])
        self.assertLess(summary["cancel_seconds"], 8.0)
        self.assertLess(summary["max_ui_gap_seconds_during_cancel"], 0.5)
        self.assertTrue(summary["forced_cancel_finished"])
        self.assertEqual(summary["forced_cancel_exit_code"], 3)
        self.assertTrue(summary["forced_cancel_worker_reaped"])
        self.assertLess(summary["max_ui_gap_seconds_forced_cancel"], 0.5)

        self.assertTrue(summary["shutdown_reaped"])
        self.assertEqual(summary["locations_after_shutdown"], 0)
        self.assertEqual(summary["helper_threads_after_shutdown"], [])
        self.assertEqual(summary["gui_network_events"], [])
        self.assertEqual(summary["worker_audit_files"], 4)  # scan, exportable scan, large result, real cancel
        self.assertEqual(summary["worker_network_events"], [])
        self.assertFalse(summary["frozen"])
        self.assertEqual(summary["failures"], [])
        self.assertTrue(summary["passed"])
        self.assertLess(elapsed, LIVE_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
