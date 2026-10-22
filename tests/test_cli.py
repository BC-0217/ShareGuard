"""CLI behaviour: exit codes, sanitized output, report export, GUI launch."""

import contextlib
import io
import json
import multiprocessing
import os
import subprocess
import struct
import sys
import threading
import time
import types
from unittest import mock

from tests import (PATH_CANARY, ROOT, SECRET_CANARY, SRC, WorkDirTestCase, synthetic,
                   token)
from shareguard import __version__, cli, platform_support
from shareguard.model import ScanResult
from shareguard.policy import Policy


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


def _crash_worker(*_args):
    os._exit(17)


def _hang_worker(*_args):
    time.sleep(10)


def _partial_frame_worker(result_conn, _scope_conn, *_args):
    if os.name == "nt":
        # Windows named pipes preserve messages, so send an incomplete logical
        # JSON payload and stall the private channel.
        result_conn.send_bytes(b'{"schema":')
    else:
        # POSIX Connection uses a length-prefixed byte stream: send only the
        # frame header and keep the owned child alive.
        os.write(result_conn.fileno(), struct.pack("!i", 1024))
    time.sleep(10)




class PlatformSupportContract(WorkDirTestCase):
    def _supported(self, os_name="nt", sys_platform="win32", pointer=8,
                   major=10, build=19045):
        version = types.SimpleNamespace(major=major, build=build)
        with mock.patch.object(platform_support.os, "name", os_name), \
                mock.patch.object(platform_support.sys, "platform", sys_platform), \
                mock.patch.object(platform_support.struct, "calcsize",
                                  return_value=pointer), \
                mock.patch.object(platform_support.sys, "getwindowsversion",
                                  return_value=version, create=True):
            return platform_support.is_public_platform_supported()

    def test_windows_10_11_x64_gate(self):
        self.assertTrue(self._supported())
        self.assertTrue(self._supported(build=22000))
        self.assertFalse(self._supported(pointer=4))
        self.assertFalse(self._supported(major=6, build=7601))
        self.assertFalse(self._supported(os_name="posix", sys_platform="linux"))


class ExitCodes(WorkDirTestCase):
    def setUp(self):
        super().setUp()
        self.clean = self.write(f"clean-{PATH_CANARY}/a.txt", "nothing\n")
        self.dirty = self.write(f"dirty-{PATH_CANARY}/b.txt",
                                f'password = "{SECRET_CANARY}{synthetic(9, 1)}"\n'
                                + token("github") + "\n")
        self.binary = self.write(f"bin-{PATH_CANARY}/c.bin", b"\x00\x01\x02")

    def assert_clean_output(self, *texts):
        for t in texts:
            for canary in (PATH_CANARY, SECRET_CANARY, token("github"), self.work):
                self.assertNotIn(canary, t)

    def test_complete_no_findings_0(self):
        code, out, err = run(["scan", self.clean])
        self.assertEqual(code, 0)
        self.assertIn("Completeness: complete", out)
        self.assert_clean_output(out, err)

    def test_complete_findings_1(self):
        code, out, err = run(["scan", self.dirty])
        self.assertEqual(code, 1)
        self.assertIn("token.github", out)
        self.assert_clean_output(out, err)

    def test_incomplete_2(self):
        code, out, err = run(["scan", self.binary, self.dirty])
        self.assertEqual(code, 2)
        self.assertIn("BINARY_CONTENT", out)
        self.assert_clean_output(out, err)

    def test_missing_path_2_without_echo(self):
        code, out, err = run(["scan", self.path(f"missing-{PATH_CANARY}")])
        self.assertEqual(code, 2)
        self.assert_clean_output(out, err)

    def test_unsupported_platform_rejects_before_worker_or_report_access(self):
        destination = self.path("must-not-exist.json")
        raw = self.path("must-not-open-" + PATH_CANARY)
        with mock.patch.object(
                cli.platform_support, "is_public_platform_supported",
                return_value=False), \
                mock.patch.object(cli, "_run_scan",
                                  side_effect=AssertionError("worker started")) as worker:
            code, out, err = run(
                ["scan", "--json", "--report", destination, raw])
        worker.assert_not_called()
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(out)["completeness"], "error")
        self.assertEqual(
            [item["code"] for item in json.loads(out)["issues"]],
            ["UNSUPPORTED_PLATFORM"])
        self.assertFalse(os.path.exists(destination))
        self.assert_clean_output(out, err)

    def test_cancel_3(self):
        cancelled = cli._synthetic_result(Policy(), "cancelled")
        with mock.patch.object(cli, "_run_scan", return_value=cancelled):
            code, out, err = run(["scan", "--json", self.clean])
        self.assertEqual(code, 3)
        self.assertEqual(json.loads(out)["completeness"], "cancelled")

    def test_error_4_policy_over_ceiling(self):
        code, out, err = run(["scan", "--max-file-mib", "17", self.clean])
        self.assertEqual(code, 4)
        self.assertIn("POLICY_INVALID", err)
        self.assertEqual(out, "")

    def test_exit_code_mapping(self):
        base = ScanResult(scan_id="0" * 16, completeness="complete",
                          policy=Policy().to_dict())
        self.assertEqual(cli.exit_code(base), 0)
        cases = (
            (cli._synthetic_result(Policy(), "incomplete", "SCAN_TIME_LIMIT"), 2),
            (cli._synthetic_result(Policy(), "cancelled"), 3),
            (cli._synthetic_result(Policy(), "error", "INTERNAL_ERROR"), 4),
        )
        for result, expected in cases:
            self.assertEqual(cli.exit_code(result), expected)
            self.assertEqual(cli.exit_code(result.to_dict()), expected)


class WorkerIsolation(WorkDirTestCase):
    def test_actual_spawn_worker_honors_preaccepted_cancel(self):
        path = self.write("many/a.txt", "x\n" * 1000)
        context = multiprocessing.get_context("spawn")
        result_recv, result_send = context.Pipe(duplex=False)
        scope_recv, scope_send = context.Pipe(duplex=False)
        event = context.Event()
        event.set()
        process = context.Process(
            target=cli._scan_worker,
            args=(result_send, scope_send, [path], Policy().to_dict(), event),
            daemon=True,
        )
        process.start()
        result_send.close()
        scope_send.close()
        try:
            self.assertTrue(result_recv.poll(5))
            self.assertTrue(scope_recv.poll(5))
            payload = result_recv.recv_bytes(cli._MAX_WORKER_MESSAGE)
            scope_payload = scope_recv.recv_bytes(cli._MAX_SCOPE_MESSAGE)
            result = cli._decode_worker_message(payload, scope_payload, Policy())
        finally:
            result_recv.close()
            scope_recv.close()
            process.join(2)
            if process.is_alive():
                process.terminate()
                process.join(2)
        self.assertFalse(process.is_alive())
        self.assertEqual(result.completeness, "cancelled")

    def test_dead_worker_returns_sanitized_error_without_unbounded_join(self):
        path = self.write("a.txt", "ok\n")
        started = time.monotonic()
        with mock.patch.object(cli, "_scan_worker", _crash_worker):
            result = cli._run_scan([path], Policy(scan_timeout_seconds=0.2))
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result.completeness, "error")
        self.assertEqual([issue.code for issue in result.issues], ["INTERNAL_ERROR"])

    def test_hung_worker_is_terminated_with_finite_deadline(self):
        path = self.write("a.txt", "ok\n")
        started = time.monotonic()
        with mock.patch.object(cli, "_scan_worker", _hang_worker), \
                mock.patch.object(cli, "_STARTUP_GRACE_SECONDS", 0.05), \
                mock.patch.object(cli, "_CANCEL_GRACE_SECONDS", 0.05), \
                mock.patch.object(cli, "_TERMINATE_GRACE_SECONDS", 0.5):
            result = cli._run_scan([path], Policy(scan_timeout_seconds=0.05))
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result.completeness, "incomplete")
        self.assertEqual([issue.code for issue in result.issues], ["SCAN_TIME_LIMIT"])


class PartialFrameIsolation(WorkDirTestCase):
    def test_partial_frame_stall_cannot_block_main_deadline(self):
        path = self.write("a.txt", "ok\n")
        started = time.monotonic()
        with mock.patch.object(cli, "_scan_worker", _partial_frame_worker), \
                mock.patch.object(cli, "_STARTUP_GRACE_SECONDS", 0.05), \
                mock.patch.object(cli, "_CANCEL_GRACE_SECONDS", 0.05), \
                mock.patch.object(cli, "_TERMINATE_GRACE_SECONDS", 0.5):
            result = cli._run_scan([path], Policy(scan_timeout_seconds=0.05))
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(result.completeness, "incomplete")
        self.assertEqual([issue.code for issue in result.issues], ["SCAN_TIME_LIMIT"])
        self.assertFalse(any(
            thread.name.startswith("shareguard-cli-recv")
            for thread in threading.enumerate()))

    def test_repeated_calls_leave_no_owned_children_or_receivers(self):
        path = self.write("repeat.txt", "ok\n")
        for _ in range(3):
            self.assertEqual(cli._run_scan([path], Policy()).completeness, "complete")
        self.assertFalse(any(
            child.name == "shareguard-cli-scan"
            for child in multiprocessing.active_children()))
        self.assertFalse(any(
            thread.name.startswith("shareguard-cli-recv")
            for thread in threading.enumerate()))


class OutputSanitizing(WorkDirTestCase):
    def test_json_output_roundtrips_and_has_no_canaries(self):
        p = self.write(f"{PATH_CANARY}/k.txt", token("aws") + "\n")
        code, out, err = run(["scan", "--json", self.path(PATH_CANARY)])
        self.assertEqual(code, 1)
        data = json.loads(out)
        ScanResult.from_dict(data)
        self.assertNotIn(PATH_CANARY, out)
        self.assertNotIn(token("aws"), out)

    def test_usage_errors_do_not_echo_values(self):
        for argv in (["scan", "--max-depth", SECRET_CANARY, "x"],
                     ["scan", f"--{SECRET_CANARY}", "x"],
                     [f"{SECRET_CANARY}"],
                     ["scan"],
                     ["scan", "--file-timeout", "nan", "x"],
                     ["scan", "--max-entries", "-5", "x"],
                     ["--max", "x"]):
            with self.subTest(argv=argv):
                code, out, err = run(argv)
                self.assertEqual(code, 4)
                self.assertNotIn(SECRET_CANARY, out + err)
                self.assertIn("USAGE_INVALID", err)

    def test_version(self):
        code, out, err = run(["--version"])
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"shareguard {__version__}")

    def test_help(self):
        code, out, err = run(["scan", "--help"])
        self.assertEqual(code, 0)
        self.assertIn("--report", out)
        code, out, err = run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn(platform_support.PUBLIC_PLATFORM, out)

    def test_help_and_version_remain_available_when_unsupported(self):
        with mock.patch.object(
                cli.platform_support, "is_public_platform_supported",
                return_value=False):
            self.assertEqual(run(["--version"])[0], 0)
            self.assertEqual(run(["scan", "--help"])[0], 0)


class ReportOption(WorkDirTestCase):
    def test_report_written(self):
        src = self.write("in/a.txt", "ok\n")
        dest = self.path("out.json")
        code, out, err = run(["scan", "--report", dest, self.path("in")])
        self.assertEqual(code, 0)
        with open(dest, encoding="ascii") as fh:
            ScanResult.from_dict(json.load(fh))

    def test_report_failure_exit_4_and_no_overwrite(self):
        self.write("in/a.txt", "ok\n")
        dest = self.write("existing.json", "keep")
        code, out, err = run(["scan", "--report", dest, self.path("in")])
        self.assertEqual(code, 4)
        self.assertIn("REPORT_DESTINATION_EXISTS", err)
        with open(dest, encoding="ascii") as fh:
            self.assertEqual(fh.read(), "keep")

    def test_report_into_scanned_dir_refused(self):
        self.write(f"in-{PATH_CANARY}/a.txt", "ok\n")
        dest = self.path(f"in-{PATH_CANARY}", "r.json")
        code, out, err = run(["scan", "--report", dest, self.path(f"in-{PATH_CANARY}")])
        self.assertEqual(code, 4)
        self.assertIn("REPORT_DESTINATION_INSIDE_INPUT", err)
        self.assertNotIn(PATH_CANARY, out + err)
        self.assertFalse(os.path.exists(dest))


class GuiLaunch(WorkDirTestCase):
    def test_no_args_launches_gui_main(self):
        fake = types.ModuleType("shareguard.gui")
        fake.main = lambda: 0
        with mock.patch.dict(sys.modules, {"shareguard.gui": fake}):
            import shareguard
            with mock.patch.object(shareguard, "gui", fake, create=True):
                code, out, err = run([])
        self.assertEqual(code, 0)

    def test_gui_failure_sanitized(self):
        fake = types.ModuleType("shareguard.gui")

        def boom():
            raise RuntimeError(SECRET_CANARY)

        fake.main = boom
        with mock.patch.dict(sys.modules, {"shareguard.gui": fake}):
            import shareguard
            with mock.patch.object(shareguard, "gui", fake, create=True):
                code, out, err = run([])
        self.assertEqual(code, 4)
        self.assertNotIn(SECRET_CANARY, out + err)


class ModuleEntryPoint(WorkDirTestCase):
    def run_module(self, *args):
        env = dict(os.environ, PYTHONPATH=SRC, PYTHONIOENCODING="utf-8")
        return subprocess.run([sys.executable, "-m", "shareguard", *args], cwd=self.work,
                              capture_output=True, text=True, env=env, timeout=60)

    def test_python_m_version_and_scan(self):
        res = self.run_module("--version")
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.strip(), f"shareguard {__version__}")
        self.write(f"{PATH_CANARY}/x.txt", token("slack") + "\n")
        res = self.run_module("scan", "--json", self.path(PATH_CANARY))
        self.assertNotIn(PATH_CANARY, res.stdout + res.stderr)
        payload = json.loads(res.stdout)
        if platform_support.is_public_platform_supported():
            self.assertEqual(res.returncode, 1)
            self.assertEqual(payload["outcome"], "findings")
        else:
            self.assertEqual(res.returncode, 4)
            self.assertEqual(
                [item["code"] for item in payload["issues"]],
                ["UNSUPPORTED_PLATFORM"])
