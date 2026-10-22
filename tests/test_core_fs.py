"""Symlink / junction / reparse rejection, scope, special paths, permissions."""

import csv
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import types
import unittest
from unittest import mock

from tests import (PATH_CANARY, SECRET_CANARY, WorkDirTestCase, codes, make_junction,
                   make_symlink, synthetic)
from shareguard import safeio
from shareguard.model import COMPLETE, INCOMPLETE
from shareguard.scanner import scan_paths

WINDOWS = os.name == "nt"


def secret_line():
    return f'client_secret = "{SECRET_CANARY}{synthetic(10, 4)}"\n'


SID_PATTERN = re.compile(r"S-\d+-\d+(?:-\d+)+", re.IGNORECASE)


def parse_whoami_sid(output):
    """Parse the SID column from one machine-format ``whoami`` CSV row."""
    try:
        rows = list(csv.reader(io.StringIO(output), strict=True))
    except csv.Error:
        return None
    if len(rows) != 1 or len(rows[0]) != 2:
        return None
    sid = rows[0][1].strip()
    return sid if SID_PATTERN.fullmatch(sid) else None


def current_token_sid():
    """Return the current Windows token SID without exposing account names."""
    if not WINDOWS:
        return None
    try:
        result = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, errors="replace",
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return parse_whoami_sid(result.stdout)


class Junctions(WorkDirTestCase):
    def setUp(self):
        super().setUp()
        if not WINDOWS:
            self.skipTest("junctions are Windows-only")
        self.write("outside/secret.txt", secret_line())
        self.write("root/inside.txt", "clean\n")
        if not make_junction(self.path("root", "jlink"), self.path("outside")):
            self.skipTest("junction creation unavailable")

    def test_descendant_junction_rejected_and_not_followed(self):
        r = scan_paths([self.path("root")])
        self.assertIn("LINK_REJECTED", codes(r))
        self.assertEqual(r.findings, [])
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_ancestor_junction_stops_before_leaf_metadata_probe(self):
        from shareguard import _winfs

        leaf = self.path("root", "jlink", "secret.txt")
        outside = self.path("outside", "secret.txt")
        with open(outside, "rb") as fh:
            before = hashlib.sha256(fh.read()).hexdigest()

        calls = {"attrs": [], "lstat": [], "create": [], "long": []}
        real_attrs = _winfs._GetFileAttributesW
        real_lstat = _winfs.os.lstat
        real_create = _winfs._CreateFileW
        real_long = _winfs._GetLongPathNameW

        def attrs(path):
            calls["attrs"].append(path)
            return real_attrs(path)

        def lstat(path):
            calls["lstat"].append(path)
            return real_lstat(path)

        def create(*args):
            calls["create"].append(args[0])
            return real_create(*args)

        def long_name(*args):
            calls["long"].append(args[0])
            return real_long(*args)

        with mock.patch.object(_winfs, "_GetFileAttributesW", side_effect=attrs), \
                mock.patch.object(_winfs.os, "lstat", side_effect=lstat), \
                mock.patch.object(_winfs, "_CreateFileW", side_effect=create), \
                mock.patch.object(_winfs, "_GetLongPathNameW",
                                  side_effect=long_name):
            with self.assertRaises(safeio.FsError) as cm:
                safeio.open_root(leaf)

        self.assertEqual(cm.exception.code, "LINK_REJECTED")
        leaf_key = os.path.normcase(leaf).rstrip("\\")
        for api_calls in calls.values():
            self.assertNotIn(
                leaf_key,
                [os.path.normcase(_winfs.strip_prefix(str(path))).rstrip("\\")
                 for path in api_calls],
            )
        with open(outside, "rb") as fh:
            after = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(after, before)

    def test_child_junction_preflight_rejects_before_read_open(self):
        from shareguard import _winfs

        outside = self.path("outside", "secret.txt")
        with open(outside, "rb") as fh:
            before = hashlib.sha256(fh.read()).hexdigest()
        parent = safeio.open_root(self.path("root"))
        try:
            with mock.patch.object(
                    _winfs, "_open_raw", wraps=_winfs._open_raw) as opened:
                with self.assertRaises(safeio.FsError) as cm:
                    safeio.open_child(parent, "jlink")
            self.assertEqual(cm.exception.code, "LINK_REJECTED")
            opened.assert_not_called()
        finally:
            parent.close()
        with open(outside, "rb") as fh:
            after = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(after, before)

    def test_selected_junction_root_rejected(self):
        r = scan_paths([self.path("root", "jlink")])
        self.assertEqual(codes(r), {"LINK_REJECTED"})
        self.assertEqual(r.findings, [])

    def test_ancestor_junction_rejected(self):
        r = scan_paths([self.path("root", "jlink", "secret.txt")])
        self.assertEqual(codes(r), {"LINK_REJECTED"})
        self.assertEqual(r.findings, [])


class Symlinks(WorkDirTestCase):
    def setUp(self):
        super().setUp()
        self.target = self.write("outside/secret.txt", secret_line())
        self.write("root/inside.txt", "clean\n")
        if not make_symlink(self.path("root", "flink.txt"), self.target):
            self.skipTest("symlink creation needs privilege on this host")

    def test_file_symlink_descendant_rejected(self):
        r = scan_paths([self.path("root")])
        self.assertIn("LINK_REJECTED", codes(r))
        self.assertEqual(r.findings, [])

    def test_file_symlink_root_rejected(self):
        r = scan_paths([self.path("root", "flink.txt")])
        self.assertEqual(codes(r), {"LINK_REJECTED"})


class SpecialPaths(WorkDirTestCase):
    @unittest.skipUnless(WINDOWS, "Windows device names")
    def test_device_names_rejected(self):
        for p in ("NUL", "CON", r"\\.\NUL", r"\\?\GLOBALROOT\Device\Null"):
            with self.subTest(p=p):
                r = scan_paths([p])
                self.assertEqual(r.completeness, INCOMPLETE)
                self.assertTrue(codes(r) & {"PATH_UNSUPPORTED", "SPECIAL_FILE"}, codes(r))
                self.assertEqual(r.counts["bytes_scanned"], 0)

    @unittest.skipUnless(WINDOWS, "Win32 local-only preflight")
    def test_unc_rejected_before_any_filesystem_api(self):
        from shareguard import _winfs

        with mock.patch.object(_winfs, "_GetDriveTypeW") as drive, \
                mock.patch.object(_winfs, "_GetFileAttributesW") as attrs, \
                mock.patch.object(_winfs, "_CreateFileW") as create, \
                mock.patch.object(_winfs.os, "lstat") as lstat:
            with self.assertRaises(safeio.FsError) as cm:
                safeio.open_root(r"\\server.invalid\share\file.txt")
        self.assertEqual(cm.exception.code, "PATH_UNSUPPORTED")
        drive.assert_not_called()
        attrs.assert_not_called()
        create.assert_not_called()
        lstat.assert_not_called()

    @unittest.skipUnless(WINDOWS, "Win32 local-only preflight")
    def test_mapped_remote_and_offline_rejected_before_open(self):
        from shareguard import _winfs

        with mock.patch.object(_winfs, "_GetDriveTypeW", return_value=_winfs.DRIVE_REMOTE), \
                mock.patch.object(_winfs, "_GetFileAttributesW") as attrs, \
                mock.patch.object(_winfs, "_CreateFileW") as create, \
                mock.patch.object(_winfs.os, "lstat") as lstat:
            with self.assertRaises(safeio.FsError) as cm:
                safeio.open_root(r"Z:\synthetic.txt")
        self.assertEqual(cm.exception.code, "PATH_UNSUPPORTED")
        attrs.assert_not_called()
        create.assert_not_called()
        lstat.assert_not_called()

        class Guard:
            is_dir = True

            def close(self):
                pass

        root = "C:\\"
        ancestor = r"C:\synthetic-cloud"
        leaf = ancestor + r"\leaf.txt"
        for remote_attr, expected_code in (
                (_winfs.FILE_ATTRIBUTE_REPARSE_POINT, "LINK_REJECTED"),
                (_winfs.FILE_ATTRIBUTE_OFFLINE, "SPECIAL_FILE"),
                (_winfs.FILE_ATTRIBUTE_RECALL_ON_OPEN, "SPECIAL_FILE"),
                (_winfs.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "SPECIAL_FILE")):
            calls = {"lstat": [], "attrs": [], "create": [], "long": []}

            def fake_lstat(path):
                calls["lstat"].append(path)
                key = _winfs.ntpath.normcase(path).rstrip("\\")
                if key == _winfs.ntpath.normcase(root).rstrip("\\"):
                    attrs = 0
                elif key == _winfs.ntpath.normcase(ancestor).rstrip("\\"):
                    attrs = remote_attr
                else:
                    raise AssertionError("deeper prefix probed")
                return types.SimpleNamespace(
                    st_mode=stat.S_IFDIR | 0o755,
                    st_file_attributes=attrs,
                )

            def fake_long(path, _buf, _size):
                calls["long"].append(path)
                return 0

            with self.subTest(remote_attr=remote_attr), \
                    mock.patch.object(_winfs, "_GetDriveTypeW", return_value=3), \
                    mock.patch.object(_winfs.os, "lstat",
                                      side_effect=fake_lstat), \
                    mock.patch.object(_winfs, "open_verified",
                                      return_value=Guard()), \
                    mock.patch.object(_winfs, "_GetFileAttributesW",
                                      side_effect=lambda path: calls["attrs"].append(path)), \
                    mock.patch.object(_winfs, "_CreateFileW",
                                      side_effect=lambda *args: calls["create"].append(args[0])), \
                    mock.patch.object(_winfs, "_GetLongPathNameW",
                                      side_effect=fake_long):
                with self.assertRaises(safeio.FsError) as cm:
                    _winfs.open_root(leaf)

            self.assertEqual(cm.exception.code, expected_code)
            leaf_key = _winfs.ntpath.normcase(leaf).rstrip("\\")
            for api_calls in calls.values():
                self.assertNotIn(
                    leaf_key,
                    [_winfs.ntpath.normcase(str(path)).rstrip("\\")
                     for path in api_calls],
                )

    @unittest.skipUnless(WINDOWS, "NTFS alternate data streams")
    def test_alternate_data_stream_rejected(self):
        p = self.write("ads.txt", "clean\n")
        try:
            with open(p + ":hidden", "w", encoding="ascii") as fh:
                fh.write(secret_line())
        except OSError:
            self.skipTest("ADS unsupported")
        r = scan_paths([p + ":hidden"])
        self.assertEqual(codes(r), {"PATH_UNSUPPORTED"})
        self.assertEqual(r.findings, [])

    @unittest.skipIf(WINDOWS or not hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_fifo_never_read(self):
        os.mkfifo(self.path("pipe"))
        r = scan_paths([self.work])
        self.assertIn("SPECIAL_FILE", codes(r))

    def test_root_without_canary_leak(self):
        r = scan_paths([self.path(f"missing-{PATH_CANARY}", "x.txt")])
        self.assertNotIn(PATH_CANARY, json.dumps(r.to_dict()))


class Permissions(WorkDirTestCase):
    def test_whoami_sid_parser_uses_sid_column(self):
        account_name = "S-1-5-999"
        token_sid = "S-1-5-21-111111111-222222222-333333333-4444"
        row = f'"{account_name}","{token_sid}"\r\n'
        self.assertEqual(parse_whoami_sid(row), token_sid)
        for malformed in (
                "",
                f'"{account_name}"\r\n',
                f'"{account_name}","not-a-sid"\r\n',
                row + row,
                f'"{account_name}","{token_sid}\r\n'):
            with self.subTest(malformed=malformed):
                self.assertIsNone(parse_whoami_sid(malformed))

    def test_unreadable_file_is_incomplete(self):
        p = self.write("d/locked.txt", secret_line())
        if WINDOWS:
            sid = current_token_sid()
            if sid is None:
                self.skipTest("unreadable-fixture-unavailable")
            deny = subprocess.run(
                ["icacls", p, "/deny", f"*{sid}:(R)"],
                capture_output=True,
            )
            if deny.returncode != 0:
                self.skipTest("unreadable-fixture-unavailable")
            self._cleanups_fs.append(
                lambda: subprocess.run(
                    ["icacls", p, "/reset"], capture_output=True))
            try:
                with open(p, "rb") as handle:
                    handle.read(1)
            except PermissionError:
                pass
            except OSError:
                self.fail("unreadable fixture probe did not raise PermissionError")
            else:
                self.skipTest("unreadable-fixture-unavailable")
        else:
            if os.geteuid() == 0:
                self.skipTest("root bypasses permissions")
            os.chmod(p, 0)
            self._cleanups_fs.append(lambda: os.chmod(p, 0o600))
        r = scan_paths([self.path("d")])
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertIn("ACCESS_DENIED", codes(r))
        self.assertEqual(r.findings, [])

    def test_access_denied_mapping_is_incomplete(self):
        p = self.write("mapping/ordinary.txt", secret_line())
        with mock.patch.object(
                safeio, "open_root",
                side_effect=safeio.FsError("ACCESS_DENIED")):
            r = scan_paths([p])
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertEqual(codes(r), {"ACCESS_DENIED"})
        self.assertEqual(r.findings, [])


class IdentityChecks(WorkDirTestCase):
    @unittest.skipUnless(WINDOWS, "Win32 final-path verification")
    def test_final_path_mismatch_fails_closed(self):
        from shareguard import _winfs

        self.write("d/a.txt", secret_line())
        real = _winfs.final_path

        def lying(h):
            return real(h) + "-elsewhere"

        with mock.patch.object(_winfs, "final_path", lying):
            r = scan_paths([self.path("d")])
        self.assertEqual(codes(r), {"IDENTITY_UNVERIFIED"})
        self.assertEqual(r.findings, [])

    @unittest.skipUnless(WINDOWS, "Win32 handle attributes")
    def test_handle_reparse_attribute_rejected(self):
        """A reparse attribute seen on the opened handle itself is rejected
        even if the pre-open lstat chain looked clean."""
        import ctypes

        from shareguard import _winfs

        self.write("d/a.txt", secret_line())
        real = _winfs._GetFileInformationByHandleEx

        def fake(h, cls, buf, size):
            ok = real(h, cls, buf, size)
            if cls == _winfs.FILE_ATTRIBUTE_TAG_INFO_CLASS:
                # ``buf`` is a ctypes byref(); ``_obj`` is the structure.
                info = _winfs.FILE_ATTRIBUTE_TAG_INFO.from_address(ctypes.addressof(buf._obj))
                if not info.FileAttributes & _winfs.FILE_ATTRIBUTE_DIRECTORY:
                    info.FileAttributes |= _winfs.FILE_ATTRIBUTE_REPARSE_POINT
            return ok

        with mock.patch.object(_winfs, "_GetFileInformationByHandleEx", fake):
            r = scan_paths([self.path("d")])
        self.assertEqual(codes(r), {"LINK_REJECTED"})

    @unittest.skipUnless(WINDOWS, "Win32 child nofollow preflight")
    def test_child_attributes_preflight_before_generic_read_open(self):
        from shareguard import _winfs

        self.write("parent/ordinary.txt", "clean\n")
        parent = safeio.open_root(self.path("parent"))
        try:
            for attrs, expected in (
                    (_winfs.FILE_ATTRIBUTE_REPARSE_POINT, "LINK_REJECTED"),
                    (_winfs.FILE_ATTRIBUTE_OFFLINE, "SPECIAL_FILE"),
                    (_winfs.FILE_ATTRIBUTE_RECALL_ON_OPEN, "SPECIAL_FILE"),
                    (_winfs.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, "SPECIAL_FILE"),
                    (_winfs.FILE_ATTRIBUTE_DEVICE, "SPECIAL_FILE")):
                fake_stat = types.SimpleNamespace(
                    st_mode=stat.S_IFREG | 0o600,
                    st_file_attributes=attrs,
                )
                with self.subTest(attrs=attrs), \
                        mock.patch.object(_winfs.os, "lstat",
                                          return_value=fake_stat) as lstat, \
                        mock.patch.object(
                            _winfs, "_lstat_prefix",
                            wraps=_winfs._lstat_prefix) as preflight, \
                        mock.patch.object(
                            _winfs, "_open_raw",
                            side_effect=AssertionError(
                                "child opened before attribute preflight")) as opened:
                    with self.assertRaises(safeio.FsError) as cm:
                        safeio.open_child(parent, "synthetic-child.txt")
                self.assertEqual(cm.exception.code, expected)
                preflight.assert_called_once()
                lstat.assert_called_once()
                opened.assert_not_called()
        finally:
            parent.close()

    def test_clean_tree_is_complete(self):
        self.write("d/a.txt", "fine\n")
        r = scan_paths([self.path("d")])
        self.assertEqual(r.completeness, COMPLETE)

    def test_open_root_handle_pins_path_on_windows(self):
        """While a verified handle is open the object cannot be renamed."""
        if not WINDOWS:
            self.skipTest("share-mode semantics are Windows-specific")
        p = self.write("d/a.txt", "x\n")
        h = safeio.open_root(p)
        try:
            with self.assertRaises(OSError):
                os.replace(p, p + ".moved")
        finally:
            h.close()
        os.replace(p, p + ".moved")
