"""Traversal, limits, cancellation, timeouts, mutation, callbacks, redaction."""

import json
import os
import threading
import time
from unittest import mock

from tests import (MEMBER_CANARY, PATH_CANARY, SECRET_CANARY, WorkDirTestCase, codes,
                   synthetic, token)
import shareguard
from shareguard import context as context_mod, platform_support
from shareguard.model import (CANCELLED, COMPLETE, ERROR, INCOMPLETE, KIND_DIRECTORY,
                              KIND_FILE, ScanResult)
from shareguard.policy import Policy
from shareguard.scanner import scan_paths


def secret_line(seed=1):
    return f'api_key = "{SECRET_CANARY}{synthetic(10, seed)}"\n'




class PublicPlatformBoundary(WorkDirTestCase):
    def test_public_api_rejects_before_scanner_or_input_access(self):
        raw = self.path("must-not-be-opened-" + PATH_CANARY)
        with mock.patch.object(
                platform_support, "is_public_platform_supported", return_value=False), \
                mock.patch("shareguard.scanner.scan_paths",
                           side_effect=AssertionError("scanner called")) as backend:
            result = shareguard.scan_paths([raw], policy=Policy())

        backend.assert_not_called()
        self.assertEqual(result.completeness, ERROR)
        self.assertEqual(codes(result), {"UNSUPPORTED_PLATFORM"})
        self.assertEqual(result.targets, [])
        self.assertEqual(result.to_dict()["counts"]["bytes_scanned"], 0)
        self.assertNotIn(PATH_CANARY, json.dumps(result.to_dict()))

    def test_internal_scanner_remains_synthetic_regression_backend(self):
        path = self.write("internal/a.txt", secret_line())
        with mock.patch.object(
                platform_support, "is_public_platform_supported", return_value=False):
            result = scan_paths([path])
        self.assertEqual(result.completeness, COMPLETE)
        self.assertEqual(len(result.findings), 1)

class Traversal(WorkDirTestCase):
    def test_directory_tree_scan(self):
        self.write("root/a.txt", "nothing here\n")
        self.write("root/sub/b.cfg", secret_line())
        self.write("root/sub/deeper/c.env", f"TOKEN={token('github')}\n")
        r = scan_paths([self.path("root")])
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual(r.counts["files_scanned"], 3)
        self.assertEqual(r.counts["directories_scanned"], 3)
        self.assertEqual(sorted(f.rule_id for f in r.findings),
                         ["assignment.api-key", "token.github"])
        kinds = {t.target_id: t.kind for t in r.targets}
        root = [t for t in r.targets if t.root_index == 0][0]
        self.assertEqual(root.kind, KIND_DIRECTORY)
        for f in r.findings:
            self.assertEqual(kinds[f.target_id], KIND_FILE)

    def test_multiple_roots_and_root_index(self):
        a = self.write("x/a.txt", "clean\n")
        b = self.write("y/b.txt", secret_line())
        r = scan_paths([a, b])
        roots = sorted((t.root_index, t.target_id) for t in r.targets if t.root_index is not None)
        self.assertEqual([i for i, _ in roots], [0, 1])
        self.assertEqual(r.findings[0].target_id, roots[1][1])

    def test_missing_path_incomplete(self):
        r = scan_paths([self.path("does-not-exist-" + PATH_CANARY)])
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertEqual(codes(r), {"PATH_NOT_FOUND"})
        self.assertNotIn(PATH_CANARY, json.dumps(r.to_dict()))

    def test_single_string_path_is_one_root(self):
        """Regression: a str must not be iterated into per-character roots
        (a lone backslash would otherwise select the drive root)."""
        self.write("one/a.txt", secret_line())
        seen = []
        r = scan_paths(self.path("one"), location_callback=lambda *a: seen.append(a))
        self.assertEqual([t.root_index for t in r.targets if t.root_index is not None], [0])
        self.assertTrue(all(a[1].startswith(self.work) for a in seen))
        self.assertEqual(len(r.findings), 1)

    def test_parent_traversal_spelling_is_rejected(self):
        self.write("scope/a.txt", "ok\n")
        ambiguous = os.path.join(self.path("scope"), "..", "scope", "a.txt")
        result = scan_paths([ambiguous])
        self.assertEqual(codes(result), {"PATH_UNSUPPORTED"})
        self.assertEqual(result.counts["files_scanned"], 0)

    def test_root_iterable_is_bounded_and_iterator_errors_are_sanitized(self):
        calls = []

        def endless():
            index = 0
            while True:
                calls.append(index)
                yield self.path(f"missing-{index}")
                index += 1

        result = scan_paths(endless(), policy=Policy(max_entries=3))
        self.assertEqual(codes(result), {"ENTRY_COUNT_LIMIT"})
        self.assertEqual(len(calls), 4)
        self.assertEqual(result.targets, [])

        class Broken:
            def __iter__(self):
                yield self.path if False else self
                raise RuntimeError(SECRET_CANARY)

        broken = scan_paths(Broken(), policy=Policy(max_entries=3))
        self.assertEqual(codes(broken), {"PATH_UNSUPPORTED"})
        self.assertNotIn(SECRET_CANARY, json.dumps(broken.to_dict()))

    def test_no_input_is_error(self):
        r = scan_paths([])
        self.assertEqual(r.completeness, ERROR)
        self.assertEqual(codes(r), {"NO_INPUT"})

    def test_invalid_policy_is_error(self):
        r = scan_paths([self.work], policy={"max_file_bytes": 10**12})
        self.assertEqual(r.completeness, ERROR)
        self.assertEqual(codes(r), {"POLICY_INVALID"})

    def test_input_files_unchanged(self):
        self.write("in/a.txt", secret_line())
        self.write("in/b.txt", "x" * 70000 + "\n")
        before = self.tree_digest()
        scan_paths([self.path("in")])
        self.assertEqual(self.tree_digest(), before)


class Limits(WorkDirTestCase):
    def test_file_too_large(self):
        self.write("big.txt", "a" * 2048)
        r = scan_paths([self.path("big.txt")], policy=Policy(max_file_bytes=1024))
        self.assertEqual(codes(r), {"FILE_TOO_LARGE"})
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_sniff_read_respects_per_file_limit_plus_one(self):
        class Handle:
            is_dir = False

            def __init__(self):
                self.pos = 0
                self.requests = []

            def snapshot(self):
                return (1, 2, 100, 3, 4, False)

            def read(self, n):
                self.requests.append(n)
                available = max(0, 100 - self.pos)
                count = min(n, available)
                self.pos += count
                return b"a" * count

            def seek(self, offset, whence=0):
                self.pos = offset
                return self.pos

            def close(self):
                pass

        handle = Handle()
        with mock.patch("shareguard.scanner.safeio.open_root", return_value=handle):
            result = scan_paths(["synthetic.txt"], policy=Policy(max_file_bytes=1))
        self.assertEqual(codes(result), {"FILE_TOO_LARGE"})
        self.assertLessEqual(max(handle.requests), 2)
        self.assertLessEqual(result.counts["bytes_scanned"], 2)

    def test_known_pdf_and_office_container_are_explicitly_incomplete(self):
        pdf = self.write("tiny.pdf", b"%PDF-1.4\nsynthetic\n")
        office = self.write("tiny.docx", b"PK\x05\x06" + b"\x00" * 18)
        for path in (pdf, office):
            with self.subTest(path=os.path.basename(path)):
                result = scan_paths([path])
                self.assertEqual(codes(result), {"UNSUPPORTED_ARCHIVE"})
                self.assertEqual(result.completeness, INCOMPLETE)

    def test_total_bytes_limit(self):
        for i in range(5):
            self.write(f"d/f{i}.txt", "b" * 3000)
        r = scan_paths([self.path("d")], policy=Policy(max_total_bytes=10_000))
        self.assertIn("TOTAL_BYTES_LIMIT", codes(r))
        self.assertLessEqual(r.counts["bytes_scanned"], 10_000)

    def test_entry_count_limit(self):
        for i in range(6):
            self.write(f"d/f{i}.txt", "c\n")
        r = scan_paths([self.path("d")], policy=Policy(max_entries=3))
        self.assertIn("ENTRY_COUNT_LIMIT", codes(r))
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_depth_limit(self):
        self.write("d/1/2/3/deep.txt", secret_line())
        r = scan_paths([self.path("d")], policy=Policy(max_depth=2))
        self.assertIn("DEPTH_LIMIT", codes(r))
        self.assertEqual(r.findings, [])

    def test_findings_limit(self):
        self.write("many.txt", "".join(f"{token('npm', i)}\n" for i in range(10)))
        r = scan_paths([self.path("many.txt")], policy=Policy(max_findings=3))
        self.assertIn("FINDINGS_LIMIT", codes(r))
        self.assertEqual(len(r.findings), 3)

    def test_issues_limit(self):
        for i in range(8):
            self.write(f"d/bin{i}.dat", b"\x00\x01\x02" * 10)
        r = scan_paths([self.path("d")], policy=Policy(max_issues=3))
        self.assertIn("ISSUES_LIMIT", codes(r))
        self.assertLessEqual(len(r.issues), 3)
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_policy_cannot_exceed_ceiling(self):
        from shareguard.policy import PolicyError
        for field, value in (("max_file_bytes", 16 * 1024 * 1024 + 1),
                             ("max_total_bytes", 257 * 1024 * 1024),
                             ("max_entries", 10_001), ("max_depth", 33),
                             ("file_timeout_seconds", 5.01),
                             ("scan_timeout_seconds", 121), ("max_line_chars", 2**21)):
            with self.subTest(field=field):
                with self.assertRaises(PolicyError) as cm:
                    Policy(**{field: value})
                self.assertNotIn(str(value), str(cm.exception))


class CancelAndTime(WorkDirTestCase):
    def make_files(self, n=20):
        for i in range(n):
            self.write(f"d/f{i:02d}.txt", secret_line(i))

    def test_cancel_before_start(self):
        self.make_files(3)
        ev = threading.Event()
        ev.set()
        r = scan_paths([self.path("d")], cancel_event=ev)
        self.assertEqual(r.completeness, CANCELLED)

    def test_cancel_during_scan(self):
        self.make_files(20)
        ev = threading.Event()
        seen = []

        def progress(p):
            seen.append(p)
            if len(seen) == 5:
                ev.set()

        r = scan_paths([self.path("d")], cancel_event=ev, callback=progress)
        self.assertEqual(r.completeness, CANCELLED)
        self.assertLess(r.counts["files_scanned"], 20)
        for p in seen:
            self.assertEqual(set(p), {"current_target", "targets", "entries", "bytes",
                                      "findings", "issues"})

    def test_cancel_inside_large_file_is_prompt(self):
        self.write("big.txt", ("q" * 99 + "\n") * 150_000)  # ~15 MB
        ev = threading.Event()
        calls = []
        real_feed = context_mod.TextScanner.feed

        def feed(self_, data):
            calls.append(1)
            if len(calls) == 3:
                ev.set()
            return real_feed(self_, data)

        with mock.patch.object(context_mod.TextScanner, "feed", feed):
            r = scan_paths([self.path("big.txt")], cancel_event=ev)
        self.assertEqual(r.completeness, CANCELLED)
        self.assertLess(len(calls), 10)

    def test_scan_timeout(self):
        self.make_files(10)

        def slow(*_args):
            time.sleep(0.05)

        r = scan_paths([self.path("d")], policy=Policy(scan_timeout_seconds=0.12),
                       location_callback=slow)
        self.assertIn("SCAN_TIME_LIMIT", codes(r))
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_file_timeout(self):
        self.write("slow.txt", "a\n" * 1000)
        real_feed = context_mod.TextScanner.feed

        def slow_feed(self_, data):
            time.sleep(0.06)
            return real_feed(self_, data)

        with mock.patch.object(context_mod.TextScanner, "feed", slow_feed):
            self.write("slow.txt", ("line\n" * 30000))
            r = scan_paths([self.path("slow.txt")],
                           policy=Policy(file_timeout_seconds=0.05))
        self.assertEqual(codes(r), {"FILE_TIME_LIMIT"})

    def test_broken_cancel_object_stops(self):
        self.make_files(2)

        class Bad:
            def is_set(self):
                raise RuntimeError("boom " + SECRET_CANARY)

        r = scan_paths([self.path("d")], cancel_event=Bad())
        self.assertEqual(r.completeness, CANCELLED)
        self.assertNotIn(SECRET_CANARY, json.dumps(r.to_dict()))


class Mutation(WorkDirTestCase):
    def test_file_growing_during_read(self):
        p = self.write("grow.txt", "x" * 200_000 + "\n")
        real_feed = context_mod.TextScanner.feed
        state = {"done": False}

        def feed(self_, data):
            if not state["done"]:
                state["done"] = True
                with open(p, "a", encoding="ascii") as fh:
                    fh.write("appended\n")
            return real_feed(self_, data)

        with mock.patch.object(context_mod.TextScanner, "feed", feed):
            r = scan_paths([p])
        self.assertIn("MUTATION_DETECTED", codes(r))
        self.assertEqual(r.completeness, INCOMPLETE)

    def test_directory_changed_during_scan(self):
        self.write("d/a.txt", "a\n")
        self.write("d/b.txt", "b\n")
        created = []

        def progress(p):
            if p["targets"] == 3 and not created:
                created.append(self.write("d/late.txt", secret_line()))

        r = scan_paths([self.path("d")], callback=progress)
        self.assertIn("MUTATION_DETECTED", codes(r))


class Callbacks(WorkDirTestCase):
    def test_location_callback_private_and_not_in_result(self):
        self.write(f"{PATH_CANARY}/n.txt", secret_line())
        got = []
        r = scan_paths([self.path(PATH_CANARY)],
                       location_callback=lambda *a: got.append(a))
        self.assertTrue(any(PATH_CANARY in a[1] for a in got))
        tids = {a[0] for a in got}
        self.assertEqual(tids, {t.target_id for t in r.targets})
        blob = json.dumps(r.to_dict())
        self.assertNotIn(PATH_CANARY, blob)
        self.assertNotIn(SECRET_CANARY, blob)

    def test_callback_exceptions_suppressed(self):
        self.write("d/a.txt", secret_line())

        def bad(*_a):
            raise ValueError(SECRET_CANARY)

        r = scan_paths([self.path("d")], callback=bad, location_callback=bad)
        self.assertEqual(r.completeness, COMPLETE)
        self.assertEqual(len(r.findings), 1)


class Redaction(WorkDirTestCase):
    def test_result_never_contains_paths_names_or_values(self):
        name = f"{PATH_CANARY}-{MEMBER_CANARY}.txt"
        self.write(f"{PATH_CANARY}/{name}", secret_line() + token("github") + "\n")
        self.write(f"{PATH_CANARY}/bad-{SECRET_CANARY}.bin", b"\x00\x01" * 50)
        r = scan_paths([self.path(PATH_CANARY)])
        blob = json.dumps(r.to_dict())
        for canary in (PATH_CANARY, MEMBER_CANARY, SECRET_CANARY, token("github"),
                       self.work):
            self.assertNotIn(canary, blob)
        again = ScanResult.from_dict(json.loads(blob))
        self.assertEqual(again.to_dict(), r.to_dict())

    def test_internal_error_is_sanitized(self):
        self.write("d/a.txt", "a\n")
        with mock.patch("shareguard.scanner._scan_file",
                        side_effect=RuntimeError(SECRET_CANARY + self.work)):
            r = scan_paths([self.path("d")])
        self.assertIn("INTERNAL_ERROR", codes(r))
        self.assertEqual(r.completeness, INCOMPLETE)
        self.assertNotIn(SECRET_CANARY, json.dumps(r.to_dict()))

    def test_unexpected_top_level_failure_is_error(self):
        with mock.patch("shareguard.scanner._scan_root",
                        side_effect=MemoryError(SECRET_CANARY)):
            r = scan_paths([self.work])
        self.assertEqual(r.completeness, ERROR)
        self.assertEqual(codes(r), {"INTERNAL_ERROR"})
