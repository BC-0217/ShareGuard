"""JSON report export protections."""

import json
import os
import unittest
from unittest import mock

from tests import PATH_CANARY, SECRET_CANARY, WorkDirTestCase, make_junction, synthetic
from shareguard import safeio
from shareguard.model import ScanResult
from shareguard.safeio import ReportError, write_report
from shareguard.scanner import scan_paths

WINDOWS = os.name == "nt"


class ReportExport(WorkDirTestCase):
    def setUp(self):
        super().setUp()
        self.input_dir = self.path(f"in-{PATH_CANARY}")
        self.write(f"in-{PATH_CANARY}/a.txt",
                   f'password = "{SECRET_CANARY}{synthetic(8, 2)}"\n')
        self.out_dir = self.path("out")
        os.makedirs(self.out_dir)
        self.result = scan_paths([self.input_dir])

    def assert_code(self, code, dest, inputs=None):
        with self.assertRaises(ReportError) as cm:
            write_report(self.result, dest, inputs if inputs is not None else [self.input_dir])
        self.assertEqual(cm.exception.code, code)
        self.assertEqual(str(cm.exception), code)
        self.assertNotIn(PATH_CANARY, repr(cm.exception.args))

    def test_writes_new_sanitized_report(self):
        dest = os.path.join(self.out_dir, "report.json")
        write_report(self.result, dest, [self.input_dir])
        with open(dest, "rb") as fh:
            raw = fh.read()
        for canary in (PATH_CANARY, SECRET_CANARY):
            self.assertNotIn(canary.encode(), raw)
        parsed = ScanResult.from_dict(json.loads(raw.decode("ascii")))
        self.assertEqual(parsed.to_dict(), self.result.to_dict())

    def test_accepts_result_dict(self):
        dest = os.path.join(self.out_dir, "r2.json")
        write_report(self.result.to_dict(), dest, [self.input_dir])
        self.assertTrue(os.path.isfile(dest))

    def test_never_overwrites_existing(self):
        dest = self.write("out/existing.json", "keep me\n")
        self.assert_code("REPORT_DESTINATION_EXISTS", dest)
        with open(dest, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "keep me\n")

    def test_destination_is_input_file(self):
        f = self.path(f"in-{PATH_CANARY}", "a.txt")
        before = self.tree_digest()
        file_result = scan_paths([f])
        with self.assertRaises(ReportError) as cm:
            write_report(file_result, f, [f])
        self.assertEqual(cm.exception.code, "REPORT_DESTINATION_IS_INPUT")
        self.assertEqual(self.tree_digest(), before)

    def test_destination_inside_selected_directory(self):
        self.assert_code("REPORT_DESTINATION_INSIDE_INPUT",
                         os.path.join(self.input_dir, "report.json"))
        self.assert_code("REPORT_PATH_INVALID",
                         os.path.join(self.input_dir, "..", f"in-{PATH_CANARY}", "r.json"))
        self.assertFalse(os.path.exists(os.path.join(self.input_dir, "report.json")))

    def test_destination_inside_selected_directory_case_variant(self):
        if not WINDOWS:
            self.skipTest("case-insensitive filesystem semantics")
        self.assert_code("REPORT_DESTINATION_INSIDE_INPUT",
                         os.path.join(self.input_dir.upper(), "report.json"))

    def test_missing_parent(self):
        self.assert_code("REPORT_PARENT_MISSING", self.path("nope", "r.json"))

    def test_parent_is_file(self):
        f = self.write("out/file.txt", "x")
        self.assert_code("REPORT_PARENT_INVALID", os.path.join(f, "r.json"))

    def test_invalid_paths(self):
        if WINDOWS:
            for dest in ("NUL", r"\\.\NUL", os.path.join(self.out_dir, "r.json:stream")):
                with self.subTest(dest=dest):
                    self.assert_code("REPORT_PATH_INVALID", dest)
        self.assert_code("REPORT_PATH_INVALID", "")
        self.assert_code("REPORT_PATH_INVALID", "bad\x00name.json")

    def test_junction_in_destination_ancestry_rejected(self):
        if not WINDOWS:
            self.skipTest("junctions are Windows-only")
        link = self.path("alias")
        if not make_junction(link, self.out_dir):
            self.skipTest("junction creation unavailable")
        self.assert_code("REPORT_LINK_REJECTED", os.path.join(link, "r.json"))
        self.assertFalse(os.path.exists(os.path.join(self.out_dir, "r.json")))

    def test_junction_alias_into_input_rejected(self):
        if not WINDOWS:
            self.skipTest("junctions are Windows-only")
        link = self.path("alias-in")
        if not make_junction(link, self.input_dir):
            self.skipTest("junction creation unavailable")
        with self.assertRaises(ReportError) as cm:
            write_report(self.result, os.path.join(link, "r.json"), [self.input_dir])
        self.assertIn(cm.exception.code, {"REPORT_LINK_REJECTED",
                                          "REPORT_DESTINATION_INSIDE_INPUT"})

    def test_moved_scanned_root_fails_closed_before_create(self):
        original = self.input_dir
        moved = self.path("moved-input")
        os.rename(original, moved)
        destination = os.path.join(moved, "report.json")
        with self.assertRaises(ReportError) as cm:
            write_report(self.result, destination, [original])
        self.assertEqual(cm.exception.code, "REPORT_IDENTITY_UNVERIFIED")
        self.assertFalse(os.path.exists(destination))

    def test_replaced_original_root_identity_fails_closed(self):
        original = self.input_dir
        moved = self.path("moved-original")
        os.rename(original, moved)
        os.makedirs(original)
        destination = os.path.join(self.out_dir, "replacement.json")
        with self.assertRaises(ReportError) as cm:
            write_report(self.result, destination, [original])
        self.assertEqual(cm.exception.code, "REPORT_IDENTITY_UNVERIFIED")
        self.assertFalse(os.path.exists(destination))

    def test_unverified_or_mismatched_input_list_fails_closed(self):
        other = self.write("other/a.txt", "ok\n")
        destination = os.path.join(self.out_dir, "wrong-input.json")
        with self.assertRaises(ReportError) as cm:
            write_report(self.result, destination, [other])
        self.assertEqual(cm.exception.code, "REPORT_IDENTITY_UNVERIFIED")
        self.assertFalse(os.path.exists(destination))

    def test_input_handle_closed_when_snapshot_fails(self):
        class BrokenHandle:
            def __init__(self):
                self.closed = False

            def snapshot(self):
                raise safeio.FsError("IDENTITY_UNVERIFIED")

            def close(self):
                self.closed = True

        handle = BrokenHandle()
        with mock.patch("shareguard.safeio.open_root", return_value=handle):
            with self.assertRaises(ReportError) as cm:
                safeio._open_inputs(self.result.scan_id, [self.input_dir])
        self.assertEqual(cm.exception.code, "REPORT_IDENTITY_UNVERIFIED")
        self.assertTrue(handle.closed)

    def test_invalid_result_rejected(self):
        with self.assertRaises(ReportError) as cm:
            write_report({"schema": "x"}, os.path.join(self.out_dir, "r.json"), [])
        self.assertEqual(cm.exception.code, "REPORT_INVALID_RESULT")

    def test_write_failure_cleanup_is_object_safe(self):
        dest = os.path.join(self.out_dir, "partial.json")
        target = "shareguard._winfs.WinHandle.write_all" if WINDOWS else \
            "shareguard._posixfs.PosixHandle.write_all"
        with mock.patch(target, side_effect=safeio.FsError("REPORT_WRITE_FAILED")):
            self.assert_code("REPORT_WRITE_FAILED", dest)
        if WINDOWS:
            self.assertFalse(os.path.exists(dest))
        else:
            # No atomic unlink-if-inode exists in the stdlib.  Leaving the
            # sanitized partial is safer than deleting a pathname replacement.
            self.assertTrue(os.path.exists(dest))

    def test_unexpected_exception_sanitized(self):
        with mock.patch("shareguard.safeio._check_inputs",
                        side_effect=RuntimeError(PATH_CANARY)):
            self.assert_code("REPORT_WRITE_FAILED", os.path.join(self.out_dir, "u.json"))

    @unittest.skipUnless(WINDOWS, "Win32 created-handle verification")
    def test_created_handle_final_path_mismatch_deletes_file(self):
        from shareguard import _winfs

        dest = os.path.join(self.out_dir, "mismatch.json")
        real = _winfs.final_path
        with mock.patch.object(_winfs, "final_path", side_effect=lambda h: real(h) + "x"):
            with self.assertRaises(ReportError) as cm:
                write_report(self.result, dest, [self.input_dir])
        self.assertIn(cm.exception.code, {"REPORT_IDENTITY_UNVERIFIED", "REPORT_PARENT_INVALID"})
        self.assertFalse(os.path.exists(dest))

    @unittest.skipUnless(WINDOWS, "Win32 created-handle verification")
    def test_created_handle_mismatch_only(self):
        """Parent verifies, only the created file's final path mismatches."""
        from shareguard import _winfs

        dest = os.path.join(self.out_dir, "mismatch2.json")
        real = _winfs.final_path

        def fake(h):
            p = real(h)
            return p + "x" if p.endswith("mismatch2.json") else p

        with mock.patch.object(_winfs, "final_path", side_effect=fake):
            self.assert_code("REPORT_IDENTITY_UNVERIFIED", dest)
        self.assertFalse(os.path.exists(dest))
