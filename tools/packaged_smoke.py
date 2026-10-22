"""Smoke-test a built Windows release folder with synthetic fixtures.

    python tools/packaged_smoke.py dist/<run>/ShareGuard-0.1.0-windows-x64
        [--selftest dist/<run>/ShareGuardSelfTest]

Checks (all with a stripped environment: no PYTHONPATH/PYTHONHOME, PATH
limited to the Windows system folder, working directory outside the build):

* CLI exit codes 0/1/2/4, JSON output, report creation and no-overwrite,
  and that no fixture path or canary text appears in any output;
* the frozen GUI self-test executable (real Tk window, real spawned scan,
  cancel, reveal, export, network audit) - a separate build of the same
  code, used because the release GUI has no scripted mode;
* the release GUI executable starts, shows a visible top-level window owned
  by its own process and exits on WM_CLOSE (native Win32 check);
* PE subsystems: GUI = windows (no console), CLI = console;
* no build-machine absolute paths (repository root, user profile) inside
  any packaged file, searched as UTF-8 and UTF-16LE bytes.

Prints a JSON summary without paths.  Exit code 0 only if every check passes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = "SGCANARY5520"


def stripped_env():
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    env = {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "PATH": os.path.join(system_root, "System32"),
        "TEMP": tempfile.gettempdir(),
        "TMP": tempfile.gettempdir(),
    }
    for key in ("USERPROFILE", "LOCALAPPDATA", "APPDATA", "HOMEDRIVE", "HOMEPATH", "SystemDrive"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def make_fixtures(base):
    clean = os.path.join(base, "clean.txt")
    with open(clean, "w", encoding="utf-8") as handle:
        handle.write("nothing here\n")
    secret_dir = os.path.join(base, "dir_" + CANARY)
    os.mkdir(secret_dir)
    secret = os.path.join(secret_dir, "key_" + CANARY + ".pem")
    with open(secret, "w", encoding="utf-8") as handle:
        handle.write("x\n" + "-----BEGIN " + "PRIVATE KEY-----\n" + CANARY + "\n")
    missing = os.path.join(base, "missing_" + CANARY)
    bulk = os.path.join(base, "bulk")
    os.mkdir(bulk)
    line = ("lorem ipsum " * 10 + "\n") * 40
    for index in range(4000):
        with open(os.path.join(bulk, "f%04d.txt" % index), "w", encoding="utf-8") as handle:
            handle.write(line)
    return {"clean": clean, "secret": secret, "secret_dir": secret_dir, "missing": missing, "bulk": bulk}


def pe_subsystem(path):
    with open(path, "rb") as handle:
        data = handle.read(4096)
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[offset:offset + 4] != b"PE\0\0":
        return None
    optional = offset + 24
    return {2: "windows", 3: "console"}.get(struct.unpack_from("<H", data, optional + 68)[0], "other")


def run(command, cwd, timeout=120):
    completed = subprocess.run(command, cwd=cwd, env=stripped_env(), capture_output=True, timeout=timeout)
    return completed.returncode, completed.stdout.decode("utf-8", "replace"), completed.stderr.decode("utf-8", "replace")


class Checks:
    def __init__(self, secrets):
        self.results = {}
        self.secrets = [s for s in secrets if s]

    def check(self, name, ok, detail=None):
        self.results[name] = {"ok": bool(ok)} if detail is None else {"ok": bool(ok), "detail": detail}

    def clean_text(self, name, *texts):
        leaked = [s for s in self.secrets if any(s.lower() in t.lower() for t in texts)]
        self.check(name, not leaked, None if not leaked else "%d leaked marker(s)" % len(leaked))

    @property
    def passed(self):
        return all(item["ok"] for item in self.results.values())


def cli_checks(checks, cli, fx, work):
    rc, out, err = run([cli, "--version"], work)
    checks.check("cli_version", rc == 0 and "0.1.0" in out, rc)
    rc, out, err = run([cli, "scan", fx["clean"]], work)
    checks.check("cli_clean_exit_0", rc == 0, rc)
    rc, out, err = run([cli, "scan", fx["secret_dir"]], work)
    checks.check("cli_findings_exit_1", rc == 1, rc)
    checks.clean_text("cli_findings_output_sanitized", out, err)
    rc, out, err = run([cli, "scan", fx["clean"], fx["missing"]], work)
    checks.check("cli_incomplete_exit_2", rc == 2 and "PATH_NOT_FOUND" in out, rc)
    checks.clean_text("cli_incomplete_output_sanitized", out, err)
    rc, out, err = run([cli, "scan", "--json", fx["secret_dir"]], work)
    try:
        parsed = json.loads(out)
        json_ok = rc == 1 and parsed.get("schema") == "shareguard.result/1" and parsed["counts"]["findings"] >= 1
    except (ValueError, KeyError, TypeError):
        json_ok = False
    checks.check("cli_json", json_ok, rc)
    checks.clean_text("cli_json_sanitized", out, err)
    report = os.path.join(work, "report.json")
    rc, out, err = run([cli, "scan", fx["secret_dir"], "--report", report], work)
    report_text = open(report, encoding="utf-8").read() if os.path.exists(report) else ""
    checks.check("cli_report_written", rc == 1 and bool(report_text), rc)
    checks.clean_text("cli_report_sanitized", report_text)
    rc, out, err = run([cli, "scan", fx["secret_dir"], "--report", report], work)
    checks.check("cli_report_no_overwrite", rc == 4 and "REPORT_DESTINATION_EXISTS" in err, rc)
    rc, out, err = run([cli, "scan", "--bogus-" + CANARY], work)
    checks.check("cli_usage_error_exit_4", rc == 4, rc)
    checks.clean_text("cli_usage_error_no_echo", out, err)


def selftest_checks(checks, exe, fx, work):
    out = os.path.join(work, "selftest.json")
    report = os.path.join(work, "gui-report.json")
    command = [exe, out, "--scan", fx["clean"], fx["secret_dir"], fx["missing"], "--cancel", fx["bulk"], "--report", report]
    process = subprocess.Popen(command, cwd=work, env=stripped_env())
    try:
        process.wait(timeout=150)
    except subprocess.TimeoutExpired:
        process.kill()  # only the process started here
        process.wait()
        checks.check("gui_selftest_finished", False, "timeout")
        return
    if not os.path.exists(out):
        checks.check("gui_selftest_finished", False, process.returncode)
        return
    text = open(out, encoding="utf-8").read()
    summary = json.loads(text)
    checks.check("gui_selftest_finished", process.returncode == 0, process.returncode)
    checks.clean_text("gui_selftest_summary_sanitized", text)
    expect = {
        "frozen": True,
        "window_viewable": True,
        "default_language": "ko",
        "scan_finished": True,
        "scan_exit_code": 2,
        "worker_reaped": True,
        "location_available_for_selected": True,
        "reveal_dialog_shown": True,
        "report_unverified_code": "REPORT_IDENTITY_UNVERIFIED",
        "report_scan_finished": True,
        "report_worker_reaped": True,
        "export_ready": True,
        "scope_message_received": True,
        "report_code": None,
        "report_second_write_code": "REPORT_DESTINATION_EXISTS",
        "report_renamed_root_code": "REPORT_IDENTITY_UNVERIFIED",
        "report_renamed_destination_absent": True,
        "cancel_finished": True,
        "cancel_exit_code": 3,
        "cancel_worker_reaped": True,
        "large_result_finished": True,
        "large_result_rows": 10000,
        "forced_cancel_finished": True,
        "forced_cancel_exit_code": 3,
        "forced_cancel_worker_reaped": True,
        "shutdown_reaped": True,
        "locations_after_shutdown": 0,
        "helper_threads_after_shutdown": [],
        "gui_network_events": [],
        "worker_audit_files": 4,
        "worker_network_events": [],
        "failures": [],
        "passed": True,
    }
    for key, value in expect.items():
        checks.check("gui_selftest_" + key, summary.get(key) == value, summary.get(key))
    checks.check("gui_selftest_findings", (summary.get("finding_rows") or 0) >= 1)
    checks.check("gui_selftest_issue_reason", "PATH_NOT_FOUND" in (summary.get("issue_codes") or []))
    for key in ("max_ui_gap_seconds_during_cancel", "max_ui_gap_seconds_large_result", "max_ui_gap_seconds_forced_cancel"):
        value = summary.get(key)
        checks.check("gui_selftest_" + key, isinstance(value, (int, float)) and 0 <= value < 0.5, value)
    if os.path.exists(report):
        checks.clean_text("gui_selftest_report_sanitized", open(report, encoding="utf-8").read())


def native_window_check(checks, exe, work):
    if os.name != "nt":
        checks.check("gui_native_window", False, "windows only")
        return
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [enum_proc, wintypes.LPARAM]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]

    process = subprocess.Popen([exe], cwd=work, env=stripped_env())
    found = []

    def callback(hwnd, _):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value == process.pid and user32.IsWindowVisible(hwnd):
            buffer = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buffer, 256)
            if buffer.value.startswith("ShareGuard"):
                found.append(hwnd)
        return True

    deadline = time.monotonic() + 20
    while not found and time.monotonic() < deadline and process.poll() is None:
        user32.EnumWindows(enum_proc(callback), 0)
        time.sleep(0.2)
    checks.check("gui_native_window_visible", bool(found))
    if found:
        user32.PostMessageW(found[0], 0x0010, 0, 0)  # WM_CLOSE
    try:
        process.wait(timeout=15)
        checks.check("gui_native_close", process.returncode == 0, process.returncode)
    except subprocess.TimeoutExpired:
        process.kill()  # only the process started here
        process.wait()
        checks.check("gui_native_close", False, "timeout")


def external_prerequisite_checks(checks, release):
    """The public archive must rely on the documented installed VC runtime."""
    names = {"vcruntime140.dll", "vcruntime140_1.dll"}
    bundled = 0
    for _, _, files in os.walk(release):
        bundled += sum(1 for name in files if name.casefold() in names)
    checks.check("vc_runtime_is_external_prerequisite", bundled == 0, {"bundled_files": bundled})


def privacy_scan(checks, release):
    markers = {ROOT, ROOT.replace("\\", "/"), os.path.expanduser("~")}
    needles = []
    for marker in markers:
        if len(marker) > 3:
            for text in (marker, marker.lower()):
                needles.append(text.encode("utf-8"))
                needles.append(text.encode("utf-16-le"))
    hits = 0
    scanned = 0
    for folder, _, names in os.walk(release):
        for name in names:
            with open(os.path.join(folder, name), "rb") as handle:
                data = handle.read()
            scanned += 1
            if any(needle in data for needle in needles):
                hits += 1
    checks.check("package_no_build_paths", hits == 0, {"files_scanned": scanned, "files_with_build_paths": hits})
    for label, exe in (("gui", os.path.join(release, "ShareGuard", "ShareGuard.exe")),
                       ("cli", os.path.join(release, "cli", "shareguard.exe"))):
        result = code_filename_scan(exe, markers)
        if result is None:
            checks.check("code_filenames_" + label, False, "required PyInstaller reader unavailable")
        else:
            complete = (
                result["absolute_or_build_paths"] == 0
                and result["entry_modules"] > 0
                and result["pyz_archives"] > 0
                and result["pyz_modules"] > 0
                and result["entry_decode_failures"] == 0
                and result["pyz_decode_failures"] == 0
            )
            checks.check("code_filenames_" + label, complete, result)


def code_filename_scan(exe, markers):
    """Decompress the embedded archives and inspect every ``co_filename``.

    The raw byte search above cannot see inside compressed PYZ entries, so
    this uses PyInstaller's own archive readers (a development tool) when it
    is installed.  Returns counts only.
    """
    try:
        from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader
    except ImportError:
        return None
    import marshal
    import re
    import types

    absolute = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")
    lowered = [m.lower() for m in markers if len(m) > 3]
    filenames = set()

    def walk(code):
        filenames.add(code.co_filename)
        for const in code.co_consts:
            if isinstance(const, types.CodeType):
                walk(const)

    def load(data):
        for start in (0, 16):
            try:
                obj = marshal.loads(data[start:])
            except (ValueError, EOFError, TypeError):
                continue
            if isinstance(obj, types.CodeType):
                return obj
        return None

    archive = CArchiveReader(exe)
    entry_modules = 0
    entry_failures = 0
    pyz_archives = 0
    pyz_modules = 0
    pyz_failures = 0
    for name, entry in archive.toc.items():
        typecode = entry[-1]
        if typecode in ("m", "s"):
            code = load(archive.extract(name))
            if code is None:
                entry_failures += 1
            else:
                walk(code)
                entry_modules += 1
        elif typecode == "z":
            pyz_archives += 1
            pyz = ZlibArchiveReader(exe, archive._start_offset + entry[0])
            for member in pyz.toc:
                code = pyz.extract(member)
                if isinstance(code, types.CodeType):
                    walk(code)
                    pyz_modules += 1
                else:
                    pyz_failures += 1
    bad = [f for f in filenames if absolute.match(f) or any(m in f.lower() for m in lowered)]
    return {
        "entry_modules": entry_modules,
        "pyz_archives": pyz_archives,
        "pyz_modules": pyz_modules,
        "entry_decode_failures": entry_failures,
        "pyz_decode_failures": pyz_failures,
        "distinct_filenames": len(filenames),
        "absolute_or_build_paths": len(bad),
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("release")
    parser.add_argument("--selftest", help="self-test build folder (default: next to the release folder)")
    args = parser.parse_args(argv)
    release = os.path.abspath(args.release)
    if args.selftest is None:
        args.selftest = os.path.join(os.path.dirname(release), "ShareGuardSelfTest")
    gui_exe = os.path.join(release, "ShareGuard", "ShareGuard.exe")
    cli_exe = os.path.join(release, "cli", "shareguard.exe")
    selftest_exe = os.path.join(os.path.abspath(args.selftest), "ShareGuardSelfTest.exe")

    artifacts = os.path.join(ROOT, "artifacts")
    os.makedirs(artifacts, exist_ok=True)
    base = tempfile.mkdtemp(prefix="packaged-smoke-", dir=artifacts)
    work = os.path.join(base, "work")
    os.mkdir(work)
    started = time.monotonic()
    try:
        fx = make_fixtures(base)
        checks = Checks([CANARY, base, ROOT])
        checks.check("pe_gui_windows_subsystem", pe_subsystem(gui_exe) == "windows")
        checks.check("pe_cli_console_subsystem", pe_subsystem(cli_exe) == "console")
        cli_checks(checks, cli_exe, fx, work)
        if os.path.exists(selftest_exe):
            selftest_checks(checks, selftest_exe, fx, work)
        else:
            checks.check("gui_selftest_present", False, "self-test build missing")
        native_window_check(checks, gui_exe, work)
        external_prerequisite_checks(checks, release)
        privacy_scan(checks, release)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    summary = {
        "passed": checks.passed,
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "checks": checks.results,
    }
    print(json.dumps(summary, indent=1, sort_keys=True))
    return 0 if checks.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
