"""Actual mapped-Tk client-bounds regression for the supported minimum GUI size."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import gc
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)

    _get_client_rect = _user32.GetClientRect
    _get_client_rect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    _get_client_rect.restype = wintypes.BOOL

    _get_process_window_station = _user32.GetProcessWindowStation
    _get_process_window_station.argtypes = []
    _get_process_window_station.restype = wintypes.HANDLE

    _get_user_object_information = _user32.GetUserObjectInformationW
    _get_user_object_information.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _get_user_object_information.restype = wintypes.BOOL

    _open_input_desktop = _user32.OpenInputDesktop
    _open_input_desktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    _open_input_desktop.restype = wintypes.HANDLE

    _get_thread_desktop = _user32.GetThreadDesktop
    _get_thread_desktop.argtypes = [wintypes.DWORD]
    _get_thread_desktop.restype = wintypes.HANDLE

    _close_desktop = _user32.CloseDesktop
    _close_desktop.argtypes = [wintypes.HANDLE]
    _close_desktop.restype = wintypes.BOOL

    _get_current_thread_id = _kernel32.GetCurrentThreadId
    _get_current_thread_id.argtypes = []
    _get_current_thread_id.restype = wintypes.DWORD

    def _typed_api(dll, name, argtypes, restype):
        function = getattr(dll, name, None)
        if function is not None:
            function.argtypes = argtypes
            function.restype = restype
        return function

    _get_current_process_id = _typed_api(
        _kernel32, "GetCurrentProcessId", [], wintypes.DWORD
    )
    _process_id_to_session_id = _typed_api(
        _kernel32,
        "ProcessIdToSessionId",
        [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)],
        wintypes.BOOL,
    )
    _wts_get_active_console_session_id = _typed_api(
        _kernel32, "WTSGetActiveConsoleSessionId", [], wintypes.DWORD
    )
    _wts_query_session_information = _typed_api(
        _wtsapi32,
        "WTSQuerySessionInformationW",
        [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.INT,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD),
        ],
        wintypes.BOOL,
    )
    _wts_free_memory = _typed_api(
        _wtsapi32, "WTSFreeMemory", [ctypes.c_void_p], None
    )
    _get_foreground_window = _typed_api(
        _user32, "GetForegroundWindow", [], wintypes.HWND
    )
    _get_window_thread_process_id = _typed_api(
        _user32,
        "GetWindowThreadProcessId",
        [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)],
        wintypes.DWORD,
    )
    _get_ancestor = _typed_api(
        _user32, "GetAncestor", [wintypes.HWND, wintypes.UINT], wintypes.HWND
    )
    _window_from_point = _typed_api(
        _user32, "WindowFromPoint", [wintypes.POINT], wintypes.HWND
    )
    _get_window_rect = _typed_api(
        _user32,
        "GetWindowRect",
        [wintypes.HWND, ctypes.POINTER(wintypes.RECT)],
        wintypes.BOOL,
    )
    _get_dpi_for_window = _typed_api(
        _user32, "GetDpiForWindow", [wintypes.HWND], wintypes.UINT
    )
    _get_thread_dpi_awareness_context = _typed_api(
        _user32, "GetThreadDpiAwarenessContext", [], wintypes.HANDLE
    )
    _get_awareness_from_dpi_awareness_context = _typed_api(
        _user32,
        "GetAwarenessFromDpiAwarenessContext",
        [wintypes.HANDLE],
        wintypes.INT,
    )

    class _USEROBJECTFLAGS(ctypes.Structure):
        _fields_ = [
            ("fInherit", wintypes.BOOL),
            ("fReserved", wintypes.BOOL),
            ("dwFlags", wintypes.DWORD),
        ]

else:
    _get_client_rect = None


_UOI_FLAGS = 1
_UOI_NAME = 2
_WSF_VISIBLE = 0x0001
_DESKTOP_READOBJECTS = 0x0001
_GA_ROOT = 2
_WTS_CURRENT_SESSION = 0xFFFFFFFF
_WTS_CONNECT_STATE = 8
_WTS_ACTIVE = 0
_INVALID_SESSION_ID = 0xFFFFFFFF
_PHYSICAL_HIT_SKIP_REASON = (
    "physical screen hit test requires a visible window station and "
    "matching active input desktop"
)
_PHYSICAL_CHILD_TIMEOUT_SECONDS = 25
_PHYSICAL_DIAGNOSTIC_PREFIX = "SHAREGUARD_NATIVE_HIT_DIAGNOSTIC "
_PHYSICAL_GATE_FIELDS = frozenset(
    {
        "window_station_observable",
        "window_station_visible",
        "input_desktop_accessible",
        "thread_desktop_handle_available",
        "desktop_names_observable",
        "input_desktop_matches_thread",
        "input_desktop_handle_closed",
    }
)
_PHYSICAL_ELIGIBILITY_FIELDS = (
    "window_station_observable",
    "window_station_visible",
    "input_desktop_accessible",
    "thread_desktop_handle_available",
    "desktop_names_observable",
    "input_desktop_matches_thread",
)
_PHYSICAL_BUTTON_NAMES = frozenset(
    {"add_files", "add_folder", "clear", "scan", "reveal", "save", "cancel"}
)
_PHYSICAL_COMBINATIONS = frozenset(
    (size, language, theme)
    for size in ((720, 480), (900, 620))
    for language in ("ko", "en")
    for theme in ("light", "dark")
)
_PHYSICAL_CHILD_CODE = """\
import sys
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root / "src"))
sys.path.insert(0, str(root))
from tests.test_gui_native_bounds import _run_physical_child
raise SystemExit(_run_physical_child(sys.argv[2]))
"""


def _user_object_name(handle):
    needed = wintypes.DWORD()
    _get_user_object_information(
        handle, _UOI_NAME, None, 0, ctypes.byref(needed)
    )
    if not needed.value:
        return None
    char_count = (needed.value + ctypes.sizeof(ctypes.c_wchar) - 1) // ctypes.sizeof(
        ctypes.c_wchar
    )
    buffer = ctypes.create_unicode_buffer(char_count)
    if not _get_user_object_information(
        handle,
        _UOI_NAME,
        ctypes.cast(buffer, ctypes.c_void_p),
        needed.value,
        ctypes.byref(needed),
    ):
        return None
    return buffer.value


def physical_hit_preconditions():
    """Return interactive-desktop eligibility and identity-free diagnostics."""
    diagnostics = {
        "window_station_observable": False,
        "window_station_visible": False,
        "input_desktop_accessible": False,
        "thread_desktop_handle_available": False,
        "desktop_names_observable": False,
        "input_desktop_matches_thread": False,
        "input_desktop_handle_closed": True,
    }
    if os.name != "nt":
        return False, diagnostics

    station = _get_process_window_station()
    if not station:
        return False, diagnostics

    flags = _USEROBJECTFLAGS()
    needed = wintypes.DWORD()
    if _get_user_object_information(
        station,
        _UOI_FLAGS,
        ctypes.byref(flags),
        ctypes.sizeof(flags),
        ctypes.byref(needed),
    ):
        diagnostics["window_station_observable"] = True
        diagnostics["window_station_visible"] = bool(flags.dwFlags & _WSF_VISIBLE)

    input_desktop = _open_input_desktop(0, False, _DESKTOP_READOBJECTS)
    if not input_desktop:
        return False, diagnostics

    diagnostics["input_desktop_accessible"] = True
    diagnostics["input_desktop_handle_closed"] = False
    eligible = False
    try:
        thread_desktop = _get_thread_desktop(_get_current_thread_id())
        diagnostics["thread_desktop_handle_available"] = bool(thread_desktop)
        input_name = _user_object_name(input_desktop)
        thread_name = _user_object_name(thread_desktop) if thread_desktop else None
        diagnostics["desktop_names_observable"] = bool(
            input_name is not None and thread_name is not None
        )
        diagnostics["input_desktop_matches_thread"] = bool(
            diagnostics["desktop_names_observable"]
            and input_name.casefold() == thread_name.casefold()
        )
        eligible = bool(
            diagnostics["window_station_observable"]
            and diagnostics["window_station_visible"]
            and diagnostics["input_desktop_accessible"]
            and diagnostics["thread_desktop_handle_available"]
            and diagnostics["desktop_names_observable"]
            and diagnostics["input_desktop_matches_thread"]
        )
    finally:
        if not _close_desktop(input_desktop):
            raise ctypes.WinError(ctypes.get_last_error())
        diagnostics["input_desktop_handle_closed"] = True

    return eligible, diagnostics


def _wts_current_session_active():
    buffer = ctypes.c_void_p()
    size = wintypes.DWORD()
    observable = bool(
        _wts_query_session_information(
            None,
            _WTS_CURRENT_SESSION,
            _WTS_CONNECT_STATE,
            ctypes.byref(buffer),
            ctypes.byref(size),
        )
    )
    try:
        active = bool(
            observable
            and buffer.value
            and size.value >= ctypes.sizeof(ctypes.c_int)
            and ctypes.cast(buffer, ctypes.POINTER(ctypes.c_int)).contents.value
            == _WTS_ACTIVE
        )
    finally:
        if buffer.value:
            _wts_free_memory(buffer)
    return observable, active


def _window_owner_is_ours(hwnd):
    owner = wintypes.DWORD()
    return bool(
        hwnd
        and _get_window_thread_process_id(hwnd, ctypes.byref(owner))
        and owner.value == _get_current_process_id()
    )


def _rect_values(hwnd, client=False):
    rect = wintypes.RECT()
    getter = _get_client_rect if client else _get_window_rect
    if not hwnd or not getter(hwnd, ctypes.byref(rect)):
        return None
    return [rect.left, rect.top, rect.right, rect.bottom]


def physical_hit_diagnostic(root, widget, center_x, center_y, os_gate_booleans):
    """Collect safe booleans and numeric geometry for only our GUI."""
    containing = None
    try:
        root_handle = wintypes.HWND(root.winfo_id())
        root_outer = _get_ancestor(root_handle, _GA_ROOT)
        foreground = _get_foreground_window()
        point_window = _window_from_point(wintypes.POINT(center_x, center_y))
        containing = root.winfo_containing(center_x, center_y)

        wts_observable, wts_active = _wts_current_session_active()
        process_session = wintypes.DWORD()
        process_session_observable = bool(
            _process_id_to_session_id(
                _get_current_process_id(), ctypes.byref(process_session)
            )
        )
        active_console = _wts_get_active_console_session_id()
        process_is_active_console = bool(
            process_session_observable
            and active_console != _INVALID_SESSION_ID
            and process_session.value == active_console
        )

        awareness = None
        if (
            _get_thread_dpi_awareness_context is not None
            and _get_awareness_from_dpi_awareness_context is not None
        ):
            context = _get_thread_dpi_awareness_context()
            awareness = (
                int(_get_awareness_from_dpi_awareness_context(context))
                if context
                else None
            )

        diagnostic = {
            "schema": "shareguard.native-hit-diagnostic/1",
            "os_gate_booleans": {
                key: bool(value) for key, value in os_gate_booleans.items()
            },
            "wts_current_session_state_observable": wts_observable,
            "wts_current_session_active": wts_active,
            "process_session_observable": process_session_observable,
            "process_is_active_console": process_is_active_console,
            "foreground_owner_is_our_pid": _window_owner_is_ours(foreground),
            "root_native_outer_is_foreground": bool(
                root_outer and foreground and root_outer == foreground
            ),
            "window_from_point_is_null": not bool(point_window),
            "window_from_point_owner_is_our_pid": _window_owner_is_ours(
                point_window
            ),
            "tk_containing_is_none": containing is None,
            "tk_containing_is_our_widget": containing is widget,
            "tk_containing_is_our_root": containing is root,
            "own_root_outer_rect": _rect_values(root_outer),
            "own_root_client_rect": _rect_values(root_handle, client=True),
            "own_widget_screen_rect": [
                widget.winfo_rootx(),
                widget.winfo_rooty(),
                widget.winfo_rootx() + widget.winfo_width(),
                widget.winfo_rooty() + widget.winfo_height(),
            ],
            "dpi_for_own_root": (
                int(_get_dpi_for_window(root_outer))
                if _get_dpi_for_window is not None and root_outer
                else None
            ),
            "thread_dpi_awareness": awareness,
        }
    finally:
        containing = None
        widget = None
        root = None
    return diagnostic


def emit_physical_hit_diagnostic(
    root, widget, center_x, center_y, os_gate_booleans, button_name
):
    diagnostic = None
    try:
        diagnostic = physical_hit_diagnostic(
            root, widget, center_x, center_y, os_gate_booleans
        )
        diagnostic["button"] = button_name
        print(
            "SHAREGUARD_NATIVE_HIT_DIAGNOSTIC "
            + json.dumps(diagnostic, sort_keys=True, separators=(",", ":")),
            file=sys.stderr,
            flush=True,
        )
    finally:
        diagnostic = None
        widget = None
        root = None


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
    def test_logical_bounds_invoke_and_localization_at_supported_sizes(self):
        self._run_matrix("logical", check_physical_hits=False)

    def test_physical_screen_hits_at_supported_sizes(self):
        self._run_physical_in_fresh_child()

    def _child_physical_screen_hits_at_supported_sizes(self):
        eligible, diagnostics = physical_hit_preconditions()
        precondition_path = (
            self._artifact_directory() / "ui-native-hit-preconditions.json"
        )
        precondition_path.write_text(
            json.dumps(
                {
                    "schema": "shareguard.ui-native-hit-preconditions/1",
                    "safe_booleans_only": True,
                    "diagnostics": diagnostics,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        if not eligible:
            self.skipTest(_PHYSICAL_HIT_SKIP_REASON)
        self._run_matrix(
            "physical-hit",
            check_physical_hits=True,
            os_preconditions=diagnostics,
        )

    def _artifact_directory(self):
        return Path(getattr(self, "_artifact_dir", ROOT / "artifacts"))

    def _run_physical_in_fresh_child(self):
        artifact_root = (ROOT / "artifacts").resolve()
        artifact_root.mkdir(parents=True, exist_ok=True)
        run_dir = Path(
            tempfile.mkdtemp(prefix="native-physical-", dir=artifact_root)
        ).resolve()
        if run_dir.parent != artifact_root or run_dir.is_symlink():
            raise AssertionError("fresh physical artifact directory containment failed")

        command = [
            sys.executable,
            "-I",
            "-c",
            _PHYSICAL_CHILD_CODE,
            str(ROOT),
            str(run_dir),
        ]
        try:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=_PHYSICAL_CHILD_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", "replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", "replace")
            (run_dir / "child-stdout.txt").write_text(stdout, encoding="utf-8")
            (run_dir / "child-stderr.txt").write_text(stderr, encoding="utf-8")
            raise AssertionError("fresh physical child exceeded 25 seconds")

        (run_dir / "child-stdout.txt").write_text(
            completed.stdout, encoding="utf-8"
        )
        (run_dir / "child-stderr.txt").write_text(
            completed.stderr, encoding="utf-8"
        )
        self._verify_fresh_child(
            run_dir, completed.returncode, completed.stderr
        )

    @staticmethod
    def _safe_child_counts(result, returncode):
        counts = {"returncode": returncode}
        if not isinstance(result, dict):
            counts["result_available"] = False
            return counts
        counts.update(
            {
                "result_available": True,
                "tests_run": result.get("tests_run"),
                "child_invocations": result.get("child_invocations"),
                "failures": result.get("failures"),
                "errors": result.get("errors"),
                "skip_count": (
                    len(result.get("skips"))
                    if isinstance(result.get("skips"), list)
                    else None
                ),
                "expected_failures": result.get("expected_failures"),
                "unexpected_successes": result.get("unexpected_successes"),
                "successful": result.get("successful"),
            }
        )
        return counts

    @staticmethod
    def _forward_safe_child_diagnostics(child_stderr):
        expected_keys = {
            "schema",
            "os_gate_booleans",
            "wts_current_session_state_observable",
            "wts_current_session_active",
            "process_session_observable",
            "process_is_active_console",
            "foreground_owner_is_our_pid",
            "root_native_outer_is_foreground",
            "window_from_point_is_null",
            "window_from_point_owner_is_our_pid",
            "tk_containing_is_none",
            "tk_containing_is_our_widget",
            "tk_containing_is_our_root",
            "own_root_outer_rect",
            "own_root_client_rect",
            "own_widget_screen_rect",
            "dpi_for_own_root",
            "thread_dpi_awareness",
            "button",
        }
        boolean_keys = expected_keys - {
            "schema",
            "os_gate_booleans",
            "own_root_outer_rect",
            "own_root_client_rect",
            "own_widget_screen_rect",
            "dpi_for_own_root",
            "thread_dpi_awareness",
            "button",
        }
        for line in child_stderr.splitlines():
            if not line.startswith(_PHYSICAL_DIAGNOSTIC_PREFIX):
                continue
            try:
                payload = json.loads(line[len(_PHYSICAL_DIAGNOSTIC_PREFIX) :])
            except (TypeError, ValueError):
                continue
            if not isinstance(payload, dict):
                continue
            gates = payload.get("os_gate_booleans")
            rects = (
                payload.get("own_root_outer_rect"),
                payload.get("own_root_client_rect"),
                payload.get("own_widget_screen_rect"),
            )
            if (
                set(payload) != expected_keys
                or payload.get("schema") != "shareguard.native-hit-diagnostic/1"
                or payload.get("button") not in _PHYSICAL_BUTTON_NAMES
                or not isinstance(gates, dict)
                or set(gates) != _PHYSICAL_GATE_FIELDS
                or not all(type(value) is bool for value in gates.values())
                or not all(type(payload[key]) is bool for key in boolean_keys)
                or not all(
                    rect is None
                    or (
                        isinstance(rect, list)
                        and len(rect) == 4
                        and all(type(value) is int for value in rect)
                    )
                    for rect in rects
                )
                or not all(
                    value is None or type(value) is int
                    for value in (
                        payload.get("dpi_for_own_root"),
                        payload.get("thread_dpi_awareness"),
                    )
                )
            ):
                continue
            print(
                _PHYSICAL_DIAGNOSTIC_PREFIX
                + json.dumps(payload, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
                flush=True,
            )

    def _verify_fresh_child(self, run_dir, returncode, child_stderr):
        result = None

        def fail(message):
            self._forward_safe_child_diagnostics(child_stderr)
            counts = self._safe_child_counts(result, returncode)
            raise AssertionError(
                "%s; child_counts=%s"
                % (message, json.dumps(counts, sort_keys=True, separators=(",", ":")))
            )

        def require(condition, message):
            if not condition:
                fail(message)

        def load_json(filename):
            path = run_dir / filename
            require(path.is_file(), "fresh child artifact is missing: " + filename)
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                fail("fresh child artifact is unreadable: " + filename)
            require(isinstance(loaded, dict), "fresh child artifact is not an object")
            return loaded

        result_path = run_dir / "child-result.json"
        require(result_path.is_file(), "fresh physical child result is missing")
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            fail("fresh physical child result is unreadable")
        require(isinstance(result, dict), "fresh child result is not an object")
        require(
            set(result)
            == {
                "schema",
                "child_marker",
                "child_invocations",
                "tests_run",
                "failures",
                "errors",
                "skips",
                "expected_failures",
                "unexpected_successes",
                "successful",
            },
            "fresh child result schema mismatch",
        )
        require(
            result.get("schema") == "shareguard.native-physical-child/1",
            "fresh child result schema version mismatch",
        )
        for field in (
            "child_invocations",
            "tests_run",
            "failures",
            "errors",
            "expected_failures",
            "unexpected_successes",
        ):
            require(type(result.get(field)) is int, "fresh child count type mismatch")
        require(type(result.get("successful")) is bool, "fresh child outcome type mismatch")
        require(
            isinstance(result.get("skips"), list)
            and all(isinstance(reason, str) for reason in result["skips"]),
            "fresh child skip summary mismatch",
        )
        require(result["tests_run"] == 1, "fresh child did not run exactly once")
        require(result["child_invocations"] == 1, "recursive child execution")
        require(
            result.get("child_marker")
            == "_child_physical_screen_hits_at_supported_sizes",
            "unexpected fresh child marker",
        )
        require(result["expected_failures"] == 0, "unexpected expected failure")
        require(result["unexpected_successes"] == 0, "unexpected unittest success")
        require(result["errors"] == 0, "fresh physical child errored")
        require(result["failures"] == 0, "fresh physical child failed")
        require(returncode == 0, "fresh physical child exited nonzero")
        require(result["successful"] is True, "fresh child was not successful")

        unittest_output_path = run_dir / "unittest-output.txt"
        require(unittest_output_path.is_file(), "fresh child unittest summary is missing")
        try:
            unittest_output = unittest_output_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            fail("fresh child unittest summary is unreadable")
        require("Ran 1 test in " in unittest_output, "fresh child unittest count missing")
        require("\nOK" in unittest_output, "fresh child unittest outcome missing")

        precondition = load_json("ui-native-hit-preconditions.json")
        require(
            set(precondition) == {"schema", "safe_booleans_only", "diagnostics"},
            "fresh child OS-precondition schema mismatch",
        )
        require(
            precondition.get("schema")
            == "shareguard.ui-native-hit-preconditions/1",
            "fresh child OS-precondition version mismatch",
        )
        require(
            precondition.get("safe_booleans_only") is True,
            "fresh child OS-precondition privacy marker mismatch",
        )
        gates = precondition.get("diagnostics")
        require(
            isinstance(gates, dict)
            and set(gates) == _PHYSICAL_GATE_FIELDS
            and all(type(value) is bool for value in gates.values()),
            "fresh child OS-gate fields mismatch",
        )
        require(
            gates["input_desktop_handle_closed"] is True,
            "fresh child input desktop handle was not closed",
        )
        eligible = all(gates[field] for field in _PHYSICAL_ELIGIBILITY_FIELDS)

        skips = result["skips"]
        if skips:
            require(len(skips) == 1, "unexpected fresh child skip count")
            require(
                skips[0] == _PHYSICAL_HIT_SKIP_REASON,
                "unexpected fresh child skip reason",
            )
            require(not eligible, "eligible fresh child reported a physical-hit skip")
            require(
                "(skipped=1)" in unittest_output,
                "fresh child unittest skip summary mismatch",
            )
            (run_dir / "parent-verification.json").write_text(
                json.dumps(
                    {
                        "schema": "shareguard.native-physical-parent/1",
                        "outcome": "skipped",
                        "child_invocations": 1,
                        "unittest_tests_run": 1,
                        "all_eligibility_conditions": False,
                        "reason": _PHYSICAL_HIT_SKIP_REASON,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            self.skipTest(_PHYSICAL_HIT_SKIP_REASON)

        require(eligible, "fresh child OS gate was not fully satisfied")
        require("(skipped=" not in unittest_output, "unexpected unittest skip summary")
        measurement = load_json("ui-native-physical-hit.json")
        lifecycle = load_json("ui-native-lifecycle-physical-hit.json")

        require(
            set(measurement)
            == {
                "schema",
                "measurements_only",
                "test_outcome_source",
                "evidence_kind",
                "cases",
                "button_cases",
                "physical_hit_checks",
                "minimum_client",
                "normal_client",
                "combinations",
                "os_preconditions",
            },
            "fresh child measurement schema mismatch",
        )
        require(
            measurement.get("schema")
            == "shareguard.ui-native-bounds-measurements/1",
            "fresh child measurement version mismatch",
        )
        require(
            measurement.get("measurements_only") is True
            and measurement.get("test_outcome_source") == "unittest result"
            and measurement.get("evidence_kind") == "physical-hit",
            "fresh child measurement provenance mismatch",
        )
        require(
            measurement.get("minimum_client") == [720, 480]
            and measurement.get("normal_client") == [900, 620],
            "fresh child supported-client sizes mismatch",
        )
        require(measurement.get("cases") == 8, "fresh child case count mismatch")
        require(
            measurement.get("button_cases") == 56,
            "fresh child button count mismatch",
        )
        require(
            measurement.get("physical_hit_checks") == 56,
            "fresh child physical-hit count mismatch",
        )
        require(
            measurement.get("os_preconditions") == gates,
            "fresh child measurement OS gates mismatch",
        )
        combinations = measurement.get("combinations")
        require(
            isinstance(combinations, list) and len(combinations) == 8,
            "fresh child combination list mismatch",
        )

        seen = set()
        hit_count = 0
        for row in combinations:
            require(isinstance(row, dict), "fresh child combination is not an object")
            require(
                set(row)
                == {
                    "requested",
                    "client",
                    "settle_samples",
                    "language",
                    "theme",
                    "buttons",
                    "rendered_rows",
                },
                "fresh child combination schema mismatch",
            )
            requested = row.get("requested")
            client = row.get("client")
            require(
                isinstance(requested, list)
                and len(requested) == 2
                and all(type(value) is int for value in requested),
                "fresh child requested client size mismatch",
            )
            require(client == requested, "fresh child actual client size mismatch")
            combination = (
                tuple(requested),
                row.get("language"),
                row.get("theme"),
            )
            require(
                combination in _PHYSICAL_COMBINATIONS,
                "fresh child contained an unsupported combination",
            )
            require(combination not in seen, "fresh child combination was duplicated")
            seen.add(combination)
            require(row.get("rendered_rows") == 4, "localized row count mismatch")
            buttons = row.get("buttons")
            require(
                isinstance(buttons, dict)
                and set(buttons) == _PHYSICAL_BUTTON_NAMES,
                "fresh child button matrix mismatch",
            )
            width, height = requested
            for name, button in buttons.items():
                require(isinstance(button, dict), "fresh child button is not an object")
                expected_fields = {
                    "rect",
                    "mapped",
                    "viewable",
                    "state",
                    "hit",
                    (
                        "disabled_invoke_suppressed"
                        if name == "cancel"
                        else "invoked"
                    ),
                }
                require(
                    set(button) == expected_fields,
                    "fresh child button measurement schema mismatch",
                )
                rect = button.get("rect")
                require(
                    isinstance(rect, list)
                    and len(rect) == 4
                    and all(type(value) is int for value in rect),
                    "fresh child button rectangle mismatch",
                )
                left, top, right, bottom = rect
                require(
                    0 <= left < right <= width and 0 <= top < bottom <= height,
                    "fresh child button was outside the client",
                )
                require(
                    button.get("mapped") is True
                    and button.get("viewable") is True,
                    "fresh child button was not mapped and viewable",
                )
                require(button.get("hit") is True, "fresh child physical hit failed")
                hit_count += 1
                if name == "cancel":
                    require(
                        button.get("state") == "disabled"
                        and button.get("disabled_invoke_suppressed") is True,
                        "fresh child cancel state or invoke behavior mismatch",
                    )
                else:
                    require(
                        button.get("state") == "normal"
                        and button.get("invoked") is True,
                        "fresh child button state or invoke behavior mismatch",
                    )
        require(seen == _PHYSICAL_COMBINATIONS, "fresh child matrix was incomplete")
        require(hit_count == 56, "fresh child physical-hit total mismatch")

        require(
            set(lifecycle)
            == {
                "schema",
                "evidence_kind",
                "creator_thread_id",
                "callbacks",
                "app_finalized",
                "root_finalized",
                "gc_collected",
                "shutdown_failed",
                "fallback_failed",
            },
            "fresh child lifecycle schema mismatch",
        )
        require(
            lifecycle.get("schema") == "shareguard.ui-native-lifecycle/1"
            and lifecycle.get("evidence_kind") == "physical-hit",
            "fresh child lifecycle provenance mismatch",
        )
        require(
            type(lifecycle.get("creator_thread_id")) is int
            and type(lifecycle.get("gc_collected")) is int,
            "fresh child lifecycle numeric fields mismatch",
        )
        require(
            lifecycle.get("shutdown_failed") is False,
            "fresh child GUI shutdown failed",
        )
        require(
            lifecycle.get("fallback_failed") is False,
            "fresh child fallback destroy failed",
        )
        require(lifecycle.get("app_finalized") is True, "fresh child app was retained")
        require(lifecycle.get("root_finalized") is True, "fresh child root was retained")
        callbacks = lifecycle.get("callbacks")
        require(
            isinstance(callbacks, list)
            and len(callbacks) == 2
            and all(
                isinstance(item, dict)
                and set(item) == {"object", "thread_id"}
                and type(item["thread_id"]) is int
                for item in callbacks
            ),
            "fresh child lifecycle callbacks schema mismatch",
        )
        require(
            sorted(item["object"] for item in callbacks) == ["app", "root"],
            "fresh child lifecycle callbacks mismatch",
        )
        require(
            all(
                item["thread_id"] == lifecycle["creator_thread_id"]
                for item in callbacks
            ),
            "fresh child lifecycle callback thread mismatch",
        )
        (run_dir / "parent-verification.json").write_text(
            json.dumps(
                {
                    "schema": "shareguard.native-physical-parent/1",
                    "outcome": "passed",
                    "child_invocations": 1,
                    "unittest_tests_run": 1,
                    "unittest_failures": 0,
                    "unittest_errors": 0,
                    "unittest_expected_failures": 0,
                    "unittest_unexpected_successes": 0,
                    "combinations": 8,
                    "button_cases": 56,
                    "physical_hit_checks": 56,
                    "all_os_gate_booleans": True,
                    "shutdown_and_fallback_succeeded": True,
                    "app_and_root_finalized": True,
                    "callbacks_on_creator_thread": True,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def _run_matrix(
        self, evidence_label, check_physical_hits, os_preconditions=None
    ):
        import tkinter

        self._evidence_label = evidence_label
        self._os_preconditions = dict(os_preconditions or {})
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
                            width,
                            height,
                            language,
                            theme,
                            invoked,
                            evidence,
                            check_physical_hits=check_physical_hits,
                        )

        output = {
            "schema": "shareguard.ui-native-bounds-measurements/1",
            "measurements_only": True,
            "test_outcome_source": "unittest result",
            "evidence_kind": evidence_label,
            "cases": len(evidence),
            "button_cases": len(evidence) * 7,
            "physical_hit_checks": len(evidence) * 7 if check_physical_hits else 0,
            "minimum_client": [720, 480],
            "normal_client": [900, 620],
            "combinations": evidence,
        }
        if os_preconditions is not None:
            output["os_preconditions"] = dict(os_preconditions)
        filename = (
            "ui-native-physical-hit.json"
            if check_physical_hits
            else "ui-native-bounds.json"
        )
        evidence_path = self._artifact_directory() / filename
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
        self,
        width,
        height,
        language,
        theme,
        invoked,
        evidence,
        *,
        check_physical_hits,
    ):
        essential = None
        widget = None
        diagnostic_widget = None
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
                before = len(invoked)
                widget.invoke()
                measured = {
                    "rect": [left, top, right, bottom],
                    "mapped": bool(widget.winfo_ismapped()),
                    "viewable": bool(widget.winfo_viewable()),
                    "state": str(widget.cget("state")),
                    "invoked": invoked[before:] == [name],
                }
                if check_physical_hits:
                    screen_x = widget.winfo_rootx() + widget.winfo_width() // 2
                    screen_y = widget.winfo_rooty() + widget.winfo_height() // 2
                    measured["hit"] = (
                        self.root.winfo_containing(screen_x, screen_y) is widget
                    )
                row["buttons"][name] = measured

            # Cancel is intentionally disabled after a result. Its geometry,
            # disabled state, and inert invoke remain logical requirements.
            cancel = self.app.btn_cancel
            cancel_left = cancel.winfo_rootx() - self.root.winfo_rootx()
            cancel_top = cancel.winfo_rooty() - self.root.winfo_rooty()
            cancel_right = cancel_left + cancel.winfo_width()
            cancel_bottom = cancel_top + cancel.winfo_height()
            before_cancel = len(invoked)
            cancel.invoke()
            cancel_measured = {
                "rect": [cancel_left, cancel_top, cancel_right, cancel_bottom],
                "mapped": bool(cancel.winfo_ismapped()),
                "viewable": bool(cancel.winfo_viewable()),
                "state": str(cancel.cget("state")),
                "disabled_invoke_suppressed": len(invoked) == before_cancel,
            }
            if check_physical_hits:
                cancel_x = cancel.winfo_rootx() + cancel.winfo_width() // 2
                cancel_y = cancel.winfo_rooty() + cancel.winfo_height() // 2
                cancel_measured["hit"] = (
                    self.root.winfo_containing(cancel_x, cancel_y) is cancel
                )
            row["buttons"]["cancel"] = cancel_measured

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
                self.assertTrue(measured["invoked"], name)
                if check_physical_hits:
                    if not measured["hit"]:
                        diagnostic_widget = essential[name]
                        emit_physical_hit_diagnostic(
                            self.root,
                            diagnostic_widget,
                            diagnostic_widget.winfo_rootx()
                            + diagnostic_widget.winfo_width() // 2,
                            diagnostic_widget.winfo_rooty()
                            + diagnostic_widget.winfo_height() // 2,
                            self._os_preconditions,
                            name,
                        )
                        diagnostic_widget = None
                    self.assertTrue(measured["hit"], name)

            left, top, right, bottom = cancel_measured["rect"]
            self.assertTrue(cancel_measured["mapped"], "cancel")
            self.assertTrue(cancel_measured["viewable"], "cancel")
            self.assertEqual(cancel_measured["state"], "disabled", "cancel")
            self.assertGreaterEqual(left, 0, "cancel")
            self.assertGreaterEqual(top, 0, "cancel")
            self.assertLessEqual(right, actual_width, "cancel")
            self.assertLessEqual(bottom, actual_height, "cancel")
            self.assertTrue(
                cancel_measured["disabled_invoke_suppressed"], "cancel"
            )
            if check_physical_hits:
                if not cancel_measured["hit"]:
                    emit_physical_hit_diagnostic(
                        self.root,
                        cancel,
                        cancel.winfo_rootx() + cancel.winfo_width() // 2,
                        cancel.winfo_rooty() + cancel.winfo_height() // 2,
                        self._os_preconditions,
                        "cancel",
                    )
                self.assertTrue(cancel_measured["hit"], "cancel")

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
            diagnostic_widget = None
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
            "evidence_kind": self._evidence_label,
            "creator_thread_id": self._creator_thread_id,
            "callbacks": list(self._lifecycle_events),
            "app_finalized": app_finalized,
            "root_finalized": root_finalized,
            "gc_collected": collected,
            "shutdown_failed": shutdown_failed,
            "fallback_failed": fallback_failed,
        }
        evidence_path = self._artifact_directory() / (
            "ui-native-lifecycle-%s.json" % self._evidence_label
        )
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


def _validated_child_artifact_directory(raw_path):
    artifact_root = (ROOT / "artifacts").resolve()
    supplied = Path(raw_path)
    if supplied.is_symlink():
        raise AssertionError("child artifact directory must not be a symlink")
    candidate = supplied.resolve(strict=True)
    if (
        candidate.parent != artifact_root
        or not candidate.name.startswith("native-physical-")
        or any(candidate.iterdir())
    ):
        raise AssertionError("child artifact directory is not fresh and owned")
    return candidate


def _run_physical_child(raw_artifact_dir):
    artifact_dir = _validated_child_artifact_directory(raw_artifact_dir)
    case = NativeClientBoundsTests(
        "_child_physical_screen_hits_at_supported_sizes"
    )
    case._artifact_dir = artifact_dir
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(case)
    (artifact_dir / "unittest-output.txt").write_text(
        stream.getvalue(), encoding="utf-8"
    )
    summary = {
        "schema": "shareguard.native-physical-child/1",
        "child_marker": "_child_physical_screen_hits_at_supported_sizes",
        "child_invocations": 1,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skips": [reason for _test, reason in result.skipped],
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
        "successful": result.wasSuccessful(),
    }
    (artifact_dir / "child-result.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    unittest.main()
