"""ZIP archive handling: bounds, bombs, CRC, encryption, names, nesting."""

import io
import json
import struct
import warnings
import zipfile
import zlib
from unittest import mock

from tests import (MEMBER_CANARY, SECRET_CANARY, WorkDirTestCase, codes, synthetic,
                   token)
from shareguard import zipscan
from shareguard.context import StopScan
from shareguard.model import COMPLETE, INCOMPLETE, KIND_ARCHIVE, KIND_ARCHIVE_ENTRY
from shareguard.policy import MIB, Policy
from shareguard.scanner import scan_paths


def secret_text(seed=1):
    return f'access_token = "{SECRET_CANARY}{synthetic(12, seed)}"\n'


def build_zip(entries, comment=b"", method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(buf, "w", method) as zf:
            for item in entries:
                if isinstance(item, zipfile.ZipInfo):
                    zf.writestr(item, b"data")
                else:
                    name, data = item[0], item[1]
                    info = zipfile.ZipInfo(name)
                    info.compress_type = item[2] if len(item) > 2 else method
                    zf.writestr(info, data)
            zf.comment = comment
    return buf.getvalue()


def build_one_info(info, data=b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(info, data)
    return buf.getvalue()


def forge_understated(method, prefix: bytes, tail: bytes) -> bytes:
    """Keep the real compressed stream but claim only the harmless prefix."""
    data = bytearray(build_zip([("entry.txt", prefix + tail, method)]))
    crc = zlib.crc32(prefix)
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<L", data, local + 14, crc)
    struct.pack_into("<L", data, local + 22, len(prefix))
    struct.pack_into("<L", data, central + 16, crc)
    struct.pack_into("<L", data, central + 24, len(prefix))
    return bytes(data)


class ZipBasics(WorkDirTestCase):
    def test_secret_in_entry(self):
        p = self.write("a.zip", build_zip([("docs/readme.txt", "hello\n"),
                                           ("cfg/app.ini", secret_text())]))
        r = scan_paths([p])
        self.assertEqual(r.completeness, COMPLETE)
        kinds = {t.target_id: t for t in r.targets}
        self.assertEqual(kinds[r.findings[0].target_id].kind, KIND_ARCHIVE_ENTRY)
        parent = kinds[r.findings[0].target_id].parent_id
        self.assertEqual(kinds[parent].kind, KIND_ARCHIVE)
        self.assertEqual(r.counts["archive_entries_scanned"], 2)

    def test_location_callback_reports_member_privately(self):
        name = f"dir/{MEMBER_CANARY}.txt"
        p = self.write("b.zip", build_zip([(name, secret_text())]))
        got = []
        r = scan_paths([p], location_callback=lambda *a: got.append(a))
        self.assertIn(name, [a[2] for a in got])
        self.assertNotIn(MEMBER_CANARY, json.dumps(r.to_dict()))

    def test_zip_detected_by_magic_without_suffix(self):
        p = self.write("archive.bin", build_zip([("x.txt", secret_text())]))
        r = scan_paths([p])
        self.assertEqual(len(r.findings), 1)

    def test_directory_entries_and_stored(self):
        data = build_zip([("d/", b""), ("d/x.txt", token("npm") + "\n", zipfile.ZIP_STORED)])
        r = scan_paths([self.write("c.zip", data)])
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual([f.rule_id for f in r.findings], ["token.npm"])

    def test_zip_inside_directory(self):
        self.write("tree/sub/in.zip", build_zip([("t.txt", secret_text())]))
        r = scan_paths([self.path("tree")])
        self.assertEqual(len(r.findings), 1)

    def test_input_archive_unchanged(self):
        self.write("u.zip", build_zip([("x.txt", secret_text())]))
        before = self.tree_digest()
        scan_paths([self.path("u.zip")])
        self.assertEqual(self.tree_digest(), before)


class ZipProblems(WorkDirTestCase):
    def scan_bytes(self, data, name="t.zip", policy=None):
        return scan_paths([self.write(name, data)], policy=policy)

    def test_nested_archive(self):
        inner = build_zip([("x.txt", secret_text())])
        r = self.scan_bytes(build_zip([("inner.zip", inner)]))
        self.assertEqual(codes(r), {"ZIP_NESTED_ARCHIVE"})
        self.assertEqual(r.findings, [])
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_encrypted_flag(self):
        data = bytearray(build_zip([("x.txt", secret_text())], method=zipfile.ZIP_STORED))
        # Set general-purpose bit 0 in local and central headers.
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            data[i + off] |= 0x01
        r = self.scan_bytes(bytes(data))
        self.assertEqual(codes(r), {"ZIP_ENCRYPTED_ENTRY"})
        self.assertEqual(r.findings, [])

    def test_unsupported_compression(self):
        r = self.scan_bytes(build_zip([("x.txt", secret_text(), zipfile.ZIP_BZIP2)]))
        self.assertEqual(codes(r), {"ZIP_UNSUPPORTED_COMPRESSION"})

    def test_crc_mismatch(self):
        data = bytearray(build_zip([("x.txt", "A" * 100 + "\n")], method=zipfile.ZIP_STORED))
        i = data.find(b"A" * 100)
        data[i + 5] = ord("B")
        r = self.scan_bytes(bytes(data))
        self.assertEqual(codes(r), {"ZIP_CRC_MISMATCH"})

    def test_duplicate_names(self):
        r = self.scan_bytes(build_zip([("a.txt", "1\n"), ("a.txt", "2\n"), ("A.TXT", "3\n")]))
        self.assertEqual(codes(r), {"ZIP_DUPLICATE_NAME"})
        self.assertEqual(sum(1 for i in r.issues if i.code == "ZIP_DUPLICATE_NAME"), 2)

    def test_unsafe_names(self):
        for name in ("../evil.txt", "/abs.txt", "C:/x.txt", "a/../../b.txt",
                     "con.txt", "trailing. /x.txt"):
            with self.subTest(name=name):
                r = self.scan_bytes(build_zip([(name, secret_text())]), name="n.zip")
                self.assertIn("ZIP_UNSAFE_NAME", codes(r))
                # Content of unsafe-named entries is still scanned.
                self.assertEqual(len(r.findings), 1)

    def test_backslash_and_nul_raw_names(self):
        data = build_zip([("a_b.txt", "x\n"), ("c_d.txt", "y\n")])
        data = data.replace(b"a_b.txt", b"a\\b.txt").replace(b"c_d.txt", b"c\x00d.txt")
        r = self.scan_bytes(data)
        self.assertEqual({i.code for i in r.issues}, {"ZIP_UNSAFE_NAME"})
        self.assertEqual(len(r.issues), 2)

    def test_symlink_and_special_entries(self):
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (0o120777 << 16)
        fifo = zipfile.ZipInfo("fifo")
        fifo.create_system = 3
        fifo.external_attr = (0o010644 << 16)
        r = self.scan_bytes(build_zip([link, fifo]))
        self.assertEqual(codes(r), {"ZIP_LINK_ENTRY", "ZIP_SPECIAL_ENTRY"})

    def test_directory_flags_are_validated_before_plain_dir_shortcut(self):
        link = zipfile.ZipInfo("linkdir/")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        self.assertEqual(codes(self.scan_bytes(build_one_info(link))),
                         {"ZIP_LINK_ENTRY"})

        encrypted = bytearray(build_zip([("encdir/", b"", zipfile.ZIP_STORED)]))
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = encrypted.find(signature)
            encrypted[pos + offset] |= 0x01
        self.assertEqual(codes(self.scan_bytes(bytes(encrypted))),
                         {"ZIP_ENCRYPTED_ENTRY"})

        unsupported = bytearray(build_zip([("odd/", b"", zipfile.ZIP_STORED)]))
        for signature, offset in ((b"PK\x03\x04", 8), (b"PK\x01\x02", 10)):
            pos = unsupported.find(signature)
            struct.pack_into("<H", unsupported, pos + offset, 12)
        self.assertEqual(codes(self.scan_bytes(bytes(unsupported))),
                         {"ZIP_UNSUPPORTED_COMPRESSION"})

        commented = zipfile.ZipInfo("commented/")
        commented.comment = b"not scanned"
        self.assertEqual(codes(self.scan_bytes(build_one_info(commented))),
                         {"ZIP_COMMENT_NOT_SCANNED"})

    def test_unknown_and_malformed_extra_fields_are_incomplete(self):
        info = zipfile.ZipInfo("extra.txt")
        info.extra = struct.pack("<HH", 0xCAFE, 12) + b"password=abc"
        result = self.scan_bytes(build_one_info(info, b"hello\n"))
        self.assertEqual(codes(result), {"ZIP_UNSUPPORTED_FEATURE"})
        self.assertEqual(result.completeness, INCOMPLETE)

        malformed = bytearray(build_one_info(info, b"hello\n"))
        local = malformed.find(b"PK\x03\x04")
        name_len = struct.unpack_from("<H", malformed, local + 26)[0]
        extra_start = local + 30 + name_len
        struct.pack_into("<H", malformed, extra_start + 2, 0xFFFF)
        corrupt = self.scan_bytes(bytes(malformed))
        self.assertIn("ZIP_CORRUPT", codes(corrupt))

    def test_preamble_and_trailer_never_complete(self):
        ordinary = build_zip([("x.txt", "ok\n")])
        self.assertIn("ZIP_UNSUPPORTED_FEATURE",
                      codes(self.scan_bytes(b"prefix" + ordinary)))
        self.assertIn("ZIP_CORRUPT", codes(self.scan_bytes(ordinary + b"trailer")))

    def test_understated_stored_and_deflate_scan_true_plaintext(self):
        prefix = b"hello\n"
        tail = secret_text(71).encode()
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(method=method):
                result = self.scan_bytes(forge_understated(method, prefix, tail))
                self.assertEqual(result.completeness, INCOMPLETE)
                self.assertEqual(len(result.findings), 1)
                self.assertTrue(codes(result) & {"ZIP_CORRUPT", "ZIP_CRC_MISMATCH"})

    def test_truncated_and_garbage(self):
        good = build_zip([("x.txt", secret_text())])
        r = self.scan_bytes(good[: len(good) // 2])
        self.assertEqual(codes(r), {"ZIP_CORRUPT"})
        r = self.scan_bytes(b"not a zip at all " * 10, name="g.zip")
        self.assertEqual(codes(r), {"ZIP_CORRUPT"})

    def test_archive_comment_flagged(self):
        r = self.scan_bytes(build_zip([("x.txt", "ok\n")], comment=b"note " + SECRET_CANARY.encode()))
        self.assertEqual(codes(r), {"ZIP_COMMENT_NOT_SCANNED"})
        self.assertNotIn(SECRET_CANARY, json.dumps(r.to_dict()))

    def test_depth_limit_inside_archive(self):
        r = self.scan_bytes(build_zip([("a/b/c/d/e.txt", secret_text())]),
                            policy=Policy(max_depth=3))
        self.assertEqual(codes(r), {"DEPTH_LIMIT"})


class ZipBounds(WorkDirTestCase):
    def scan_bytes(self, data, name="t.zip", policy=None):
        return scan_paths([self.write(name, data)], policy=policy)

    def test_entry_declared_too_large(self):
        r = self.scan_bytes(build_zip([("big.txt", "A" * (2 * MIB))]),
                            policy=Policy(max_file_bytes=MIB))
        self.assertEqual(codes(r), {"ZIP_ENTRY_TOO_LARGE"})

    def test_bomb_with_understated_size_is_bounded(self):
        """Declared sizes are lies: actual stream is bounded and flagged."""
        data = bytearray(build_zip([("bomb.txt", "A" * (8 * MIB))]))
        for sig, off in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
            i = data.find(sig)
            struct.pack_into("<L", data, i + off, 1000)
        r = self.scan_bytes(bytes(data), policy=Policy(max_file_bytes=MIB))
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertTrue(codes(r) & {"ZIP_CRC_MISMATCH", "ZIP_ENTRY_TOO_LARGE", "ZIP_CORRUPT"})
        # Aggregate bytes also include repeated physical ZIP metadata and
        # compressed reads; decoded plaintext itself is bounded separately.
        self.assertLessEqual(r.counts["bytes_scanned"], MIB + 128 * 1024)

    def test_bomb_total_decompressed_limit(self):
        entries = [(f"f{i}.txt", "B" * (600 * 1024)) for i in range(5)]
        r = self.scan_bytes(build_zip(entries), policy=Policy(max_total_bytes=2 * MIB))
        self.assertIn("TOTAL_BYTES_LIMIT", codes(r))
        self.assertLessEqual(r.counts["bytes_scanned"], 2 * MIB)

    def test_entry_count_limit_before_parse(self):
        entries = [(f"e{i}.txt", "x\n") for i in range(20)]
        r = self.scan_bytes(build_zip(entries), policy=Policy(max_entries=10))
        self.assertEqual(codes(r), {"ENTRY_COUNT_LIMIT"})
        self.assertEqual(r.counts["archive_entries_scanned"], 0)

    def test_oversized_central_directory_rejected_before_zipfile(self):
        size = zipscan.MAX_CENTRAL_DIRECTORY_BYTES + MIB
        cd_size = zipscan.MAX_CENTRAL_DIRECTORY_BYTES + 1
        body = b"\x00" * (size - 22)
        eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, cd_size, 0, 0)
        r = self.scan_bytes(body + eocd, name="huge-cd.zip")
        self.assertEqual(codes(r), {"ZIP_CENTRAL_DIRECTORY_LIMIT"})

    def test_reader_refuses_unvalidated_large_reads(self):
        class H:
            def seek(self, pos):
                pass

            def read(self, n):
                return b"\x00" * n

        reader = zipscan.BoundedReader(H(), 10 * MIB, lambda: None)
        with self.assertRaises(OSError):
            reader.read(5 * MIB)
        reader.allowed_large = (0, 5 * MIB)
        self.assertEqual(len(reader.read(5 * MIB)), 5 * MIB)

    def test_deflate_decoder_respects_requested_output_bound(self):
        compressor = zlib.compressobj(level=9, wbits=-15)
        compressed = compressor.compress(b"A" * 100000) + compressor.flush()
        info = zipfile.ZipInfo("bounded.txt")
        info.compress_type = zipfile.ZIP_DEFLATED
        info.compress_size = len(compressed)
        info.file_size = 100000
        info.CRC = zlib.crc32(b"A" * 100000)
        raw = io.BytesIO(compressed)
        reader = zipscan.BoundedReader(raw, len(compressed), lambda: None)

        real_factory = zlib.decompressobj
        limits = []

        class Spy:
            def __init__(self):
                self.inner = real_factory(-15)

            def decompress(self, data, max_length=0):
                limits.append(max_length)
                return self.inner.decompress(data, max_length)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        with mock.patch.object(zipscan.zlib, "decompressobj", return_value=Spy()):
            stream = zipscan._EntryStream(reader, info, 0)
            self.assertEqual(stream.read(2), b"AA")
        self.assertTrue(limits)
        self.assertLessEqual(max(limits), 2)
        self.assertEqual(stream.actual_size, 2)
        self.assertEqual(len(stream._buffer), 0)

    def test_deflate_recomputes_combined_budget_after_physical_read(self):
        plain = b"A" * 100000
        compressor = zlib.compressobj(level=9, wbits=-15)
        compressed = compressor.compress(plain) + compressor.flush()
        info = zipfile.ZipInfo("combined.txt")
        info.compress_type = zipfile.ZIP_DEFLATED
        info.compress_size = len(compressed)
        info.file_size = len(plain)
        info.CRC = zlib.crc32(plain)

        class H(io.BytesIO):
            def __init__(self, data):
                super().__init__(data)
                self.requests = []

            def read(self, n=-1):
                self.requests.append(n)
                return super().read(n)

        handle = H(compressed)
        cap = len(compressed) + 3
        state = {"used": 0}

        def take(n):
            if state["used"] + n > cap:
                raise StopScan("TOTAL_BYTES_LIMIT")
            state["used"] += n

        reader = zipscan.BoundedReader(
            handle, len(compressed), lambda: None, take_bytes=take,
            bytes_left=lambda: cap - state["used"])
        real_factory = zlib.decompressobj
        limits = []

        class Spy:
            def __init__(self):
                self.inner = real_factory(-15)

            def decompress(self, data, max_length=0):
                limits.append(max_length)
                return self.inner.decompress(data, max_length)

            def __getattr__(self, name):
                return getattr(self.inner, name)

        with mock.patch.object(zipscan.zlib, "decompressobj", return_value=Spy()):
            stream = zipscan._EntryStream(reader, info, 0)
            output = stream.read(100)

        post_physical_remaining = cap - state["used"]
        self.assertTrue(limits)
        self.assertLessEqual(max(limits), post_physical_remaining + 1)
        self.assertLessEqual(len(output), post_physical_remaining + 1)
        self.assertLessEqual(state["used"] + len(output), cap + 1)
        self.assertLessEqual(max(handle.requests), cap + 1)
        with self.assertRaises(StopScan):
            take(len(output))

    def test_stored_reserves_physical_and_plaintext_shares(self):
        data = b"S" * 100
        info = zipfile.ZipInfo("stored.txt")
        info.compress_type = zipfile.ZIP_STORED
        info.compress_size = len(data)
        info.file_size = len(data)
        info.CRC = zlib.crc32(data)

        class H(io.BytesIO):
            def __init__(self, payload):
                super().__init__(payload)
                self.requests = []

            def read(self, n=-1):
                self.requests.append(n)
                return super().read(n)

        handle = H(data)
        cap = 9
        state = {"used": 0}

        def take(n):
            if state["used"] + n > cap:
                raise StopScan("TOTAL_BYTES_LIMIT")
            state["used"] += n

        reader = zipscan.BoundedReader(
            handle, len(data), lambda: None, take_bytes=take,
            bytes_left=lambda: cap - state["used"])
        stream = zipscan._EntryStream(reader, info, 0)
        output = stream.read(100)

        self.assertEqual(len(output), 5)
        self.assertEqual(max(handle.requests), 5)
        self.assertEqual(state["used"], 5)
        self.assertEqual(state["used"] + len(output), cap + 1)
        with self.assertRaises(StopScan):
            take(len(output))

    def test_reader_actual_request_has_only_one_byte_sentinel(self):
        class H:
            def __init__(self):
                self.requests = []

            def seek(self, pos):
                pass

            def read(self, n):
                self.requests.append(n)
                return b"x" * n

        handle = H()
        state = {"used": 0}

        def take(n):
            if state["used"] + n > 1:
                raise StopScan("TOTAL_BYTES_LIMIT")
            state["used"] += n

        reader = zipscan.BoundedReader(
            handle, 10000, lambda: None, take_bytes=take,
            bytes_left=lambda: 1 - state["used"])
        with self.assertRaises(StopScan):
            reader.read(4096)
        self.assertLessEqual(max(handle.requests), 2)

    def test_multi_disk_unsupported(self):
        data = bytearray(build_zip([("x.txt", "ok\n")]))
        i = data.rfind(b"PK\x05\x06")
        struct.pack_into("<H", data, i + 4, 1)
        r = self.scan_bytes(bytes(data))
        self.assertEqual(codes(r), {"ZIP_UNSUPPORTED_FEATURE"})

    def test_archive_size_over_total_budget(self):
        r = self.scan_bytes(build_zip([("x.txt", "C" * 300_000)], method=zipfile.ZIP_STORED),
                            policy=Policy(max_total_bytes=100_000))
        self.assertEqual(codes(r), {"TOTAL_BYTES_LIMIT"})
