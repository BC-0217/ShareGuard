"""Safe filesystem entry points shared by the scanner and report export.

Platform specifics live in ``_winfs`` (Win32 handles + final path checks) and
``_posixfs`` (O_NOFOLLOW + dir_fd traversal). Both raise ``FsError`` carrying a
fixed issue code only.
"""

from __future__ import annotations

import json
import os
import threading
from collections import OrderedDict

if os.name == "nt":
    from . import _winfs as _fs
else:
    from . import _posixfs as _fs

from .model import IssueCode, ScanResult
from .policy import CEILINGS

FsError = _fs.FsError
open_child = _fs.open_child
same_path = _fs.same_path


def abspath(path) -> str:
    """Absolute path without resolving links; ambiguous parent traversal fails."""
    path = os.fspath(path)
    if not isinstance(path, str) or not path or "\x00" in path:
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    if os.name == "nt":
        _fs.check_selectable(path)
        pieces = path.replace("\\", "/").split("/")
    else:
        pieces = path.split("/")
    if ".." in pieces:
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    absolute = os.path.abspath(path)
    _fs.check_selectable(absolute)
    return absolute


def open_root(path):
    """Open a selected root (file or directory) after link/scope checks."""
    return _fs.open_root(abspath(path))


_SCOPE_LOCK = threading.Lock()
_SCOPE_REGISTRY = OrderedDict()
_MAX_SCOPE_RECORDS = 64


def register_result_scopes(scan_id: str, root_count: int, scopes) -> None:
    """Retain numeric root identities only; never retain paths or names."""
    clean = {}
    try:
        if (not isinstance(scan_id, str) or not isinstance(root_count, int)
                or isinstance(root_count, bool) or root_count < 0
                or root_count > CEILINGS["max_entries"]):
            return
        for index, value in dict(scopes).items():
            if (not isinstance(index, int) or not isinstance(value, (tuple, list))
                    or len(value) != 3):
                return
            dev, ino, is_dir = value
            if isinstance(dev, bool) or isinstance(ino, bool):
                return
            if not isinstance(dev, int) or not isinstance(ino, int) or not isinstance(is_dir, bool):
                return
            clean[index] = (dev, ino, is_dir)
    except Exception:
        return
    with _SCOPE_LOCK:
        _SCOPE_REGISTRY[scan_id] = (root_count, clean)
        _SCOPE_REGISTRY.move_to_end(scan_id)
        while len(_SCOPE_REGISTRY) > _MAX_SCOPE_RECORDS:
            _SCOPE_REGISTRY.popitem(last=False)


def clear_result_scopes(scan_id: str) -> None:
    """Forget one session's private numeric root identities."""
    with _SCOPE_LOCK:
        _SCOPE_REGISTRY.pop(scan_id, None)


def export_result_scopes(scan_id: str):
    """Return a JSON-primitive private scope envelope for owned worker IPC."""
    with _SCOPE_LOCK:
        record = _SCOPE_REGISTRY.get(scan_id)
        if record is None:
            return None
        count, scopes = record
        return {
            "root_count": count,
            "scopes": [[index, value[0], value[1], value[2]]
                       for index, value in sorted(scopes.items())],
        }


def import_result_scopes(scan_id: str, envelope) -> bool:
    """Import the private numeric envelope received from our own child."""
    try:
        count = envelope["root_count"]
        items = envelope["scopes"]
        if (not isinstance(envelope, dict) or set(envelope) != {"root_count", "scopes"}
                or isinstance(count, bool) or not isinstance(count, int)
                or count < 0 or count > CEILINGS["max_entries"]
                or not isinstance(items, list) or len(items) > count):
            return False
        scopes = {}
        for item in items:
            if not isinstance(item, list) or len(item) != 4:
                return False
            index, dev, ino, is_dir = item
            if (isinstance(index, bool) or not isinstance(index, int) or index < 0
                    or isinstance(dev, bool) or not isinstance(dev, int)
                    or isinstance(ino, bool) or not isinstance(ino, int)
                    or not isinstance(is_dir, bool) or index in scopes):
                return False
            scopes[index] = (dev, ino, is_dir)
        if any(index >= count for index in scopes):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    register_result_scopes(scan_id, count, scopes)
    return True


# --------------------------------------------------------------------------
# Report export
# --------------------------------------------------------------------------

REPORT_PATH_INVALID = "REPORT_PATH_INVALID"
REPORT_PARENT_MISSING = "REPORT_PARENT_MISSING"
REPORT_PARENT_INVALID = "REPORT_PARENT_INVALID"
REPORT_LINK_REJECTED = "REPORT_LINK_REJECTED"
REPORT_DESTINATION_EXISTS = "REPORT_DESTINATION_EXISTS"
REPORT_DESTINATION_IS_INPUT = "REPORT_DESTINATION_IS_INPUT"
REPORT_DESTINATION_INSIDE_INPUT = "REPORT_DESTINATION_INSIDE_INPUT"
REPORT_IDENTITY_UNVERIFIED = "REPORT_IDENTITY_UNVERIFIED"
REPORT_ACCESS_DENIED = "REPORT_ACCESS_DENIED"
REPORT_WRITE_FAILED = "REPORT_WRITE_FAILED"
REPORT_INVALID_RESULT = "REPORT_INVALID_RESULT"

REPORT_ERROR_CODES = frozenset({
    REPORT_PATH_INVALID, REPORT_PARENT_MISSING, REPORT_PARENT_INVALID,
    REPORT_LINK_REJECTED, REPORT_DESTINATION_EXISTS, REPORT_DESTINATION_IS_INPUT,
    REPORT_DESTINATION_INSIDE_INPUT, REPORT_IDENTITY_UNVERIFIED,
    REPORT_ACCESS_DENIED, REPORT_WRITE_FAILED, REPORT_INVALID_RESULT,
})


class ReportError(Exception):
    """Report export failure; ``str(err)`` is the fixed code only."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

    def __str__(self) -> str:
        return self.code


def serialize_report(result) -> bytes:
    if isinstance(result, dict):
        result = ScanResult.from_dict(result)
    if not isinstance(result, ScanResult):
        raise ValueError("not a scan result")
    # Round-trip through the strict validator so only schema data is written.
    data = ScanResult.from_dict(result.to_dict()).to_dict()
    return (json.dumps(data, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")


def _report_code(exc: FsError, default: str) -> str:
    if exc.code == IssueCode.LINK_REJECTED:
        return REPORT_LINK_REJECTED
    if exc.code == IssueCode.ACCESS_DENIED:
        return REPORT_ACCESS_DENIED
    if exc.code == IssueCode.PATH_NOT_FOUND:
        return REPORT_PARENT_MISSING
    if exc.code == IssueCode.PATH_UNSUPPORTED:
        return REPORT_PATH_INVALID
    if exc.code in REPORT_ERROR_CODES:
        return exc.code
    return default


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _is_within(child: str, parent: str) -> bool:
    c, p = _norm(child), _norm(parent)
    if c == p:
        return True
    p = p.rstrip("\\/")
    return c.startswith(p + os.sep) or (os.altsep is not None and c.startswith(p + os.altsep))


def _variants(path: str) -> set:
    out = {path}
    try:
        out.add(_fs.long_path(path))
    except Exception:
        pass
    try:
        out.add(os.path.realpath(path))
    except (OSError, ValueError):
        pass
    if os.name == "nt":
        out = {_fs.strip_prefix(p) for p in out}
    return out


def _identity(path: str, follow: bool):
    try:
        st = os.stat(path) if follow else os.lstat(path)
    except (OSError, ValueError):
        return None
    if not st.st_ino:
        return None
    return (st.st_dev, st.st_ino)


def _open_inputs(scan_id: str, input_paths):
    """Re-open every selected root and match its scan-time numeric identity."""
    with _SCOPE_LOCK:
        record = _SCOPE_REGISTRY.get(scan_id)
    if record is None:
        raise ReportError(REPORT_IDENTITY_UNVERIFIED)
    root_count, scopes = record
    if set(scopes) != set(range(root_count)):
        # A rejected/missing root has no verified scan-time identity.  Do not
        # revisit any supplied path (which could be a UNC namespace).
        raise ReportError(REPORT_IDENTITY_UNVERIFIED)
    if isinstance(input_paths, (str, bytes, os.PathLike)):
        supplied = [input_paths]
    else:
        try:
            iterator = iter(input_paths or ())
            supplied = []
            for _ in range(root_count + 1):
                try:
                    supplied.append(next(iterator))
                except StopIteration:
                    break
        except Exception:
            raise ReportError(REPORT_IDENTITY_UNVERIFIED) from None
    if len(supplied) != root_count:
        raise ReportError(REPORT_IDENTITY_UNVERIFIED)
    handles = []
    try:
        for index, raw in enumerate(supplied):
            handle = None
            try:
                handle = open_root(raw)
                snapshot = handle.snapshot()
            except (FsError, OSError, TypeError, ValueError):
                if handle is not None:
                    handle.close()
                raise ReportError(REPORT_IDENTITY_UNVERIFIED) from None
            expected = scopes[index]
            actual = (int(snapshot[0]), int(snapshot[1]), bool(handle.is_dir))
            if actual != expected:
                handle.close()
                raise ReportError(REPORT_IDENTITY_UNVERIFIED)
            handles.append(handle)
        return handles
    except BaseException:
        for handle in handles:
            handle.close()
        raise


def _check_inputs(dest: str, verified_dest: str, parent: str, input_handles) -> None:
    dest_variants = _variants(dest) | _variants(verified_dest)
    input_dir_ids = set()
    for handle in input_handles:
        inp = handle.sys_path
        if os.name == "nt":
            inp = _fs.strip_prefix(inp)
        for iv in _variants(inp):
            for dv in dest_variants:
                if _norm(dv) == _norm(iv):
                    raise ReportError(REPORT_DESTINATION_IS_INPUT)
                if handle.is_dir and _is_within(dv, iv):
                    raise ReportError(REPORT_DESTINATION_INSIDE_INPUT)
        snapshot = handle.snapshot()
        if handle.is_dir:
            input_dir_ids.add((int(snapshot[0]), int(snapshot[1])))
    # Handle identities catch local aliases such as bind/substituted mounts.
    path = parent
    while True:
        try:
            ancestor = _fs.open_root(path)
            snapshot = ancestor.snapshot()
        except (FsError, OSError, TypeError, ValueError):
            raise ReportError(REPORT_IDENTITY_UNVERIFIED) from None
        finally:
            if "ancestor" in locals():
                ancestor.close()
                del ancestor
        if (int(snapshot[0]), int(snapshot[1])) in input_dir_ids:
            raise ReportError(REPORT_DESTINATION_INSIDE_INPUT)
        up = os.path.dirname(path)
        if up == path or not up:
            break
        path = up


def write_report(result, destination, input_paths) -> None:
    """Write the sanitized JSON report with exclusive create.

    Raises ``ReportError`` with a fixed code; never overwrites anything.
    """
    try:
        _write_report(result, destination, input_paths)
    except ReportError:
        raise
    except Exception:
        raise ReportError(REPORT_WRITE_FAILED) from None


def _write_report(result, destination, input_paths) -> None:
    try:
        validated = ScanResult.from_dict(result) if isinstance(result, dict) else \
            ScanResult.from_dict(result.to_dict())
        data = serialize_report(validated)
    except (AttributeError, ValueError, TypeError):
        raise ReportError(REPORT_INVALID_RESULT) from None
    try:
        dest = abspath(destination)
    except (FsError, TypeError, ValueError):
        raise ReportError(REPORT_PATH_INVALID) from None
    parent, name = os.path.split(dest)
    if not name or name in (".", ".."):
        raise ReportError(REPORT_PATH_INVALID)
    input_handles = _open_inputs(validated.scan_id, input_paths)
    try:
        try:
            parent_handle = _fs.open_root(parent)
        except FsError as exc:
            raise ReportError(_report_code(exc, REPORT_PARENT_INVALID)) from None
        try:
            if not parent_handle.is_dir:
                raise ReportError(REPORT_PARENT_INVALID)
            verified_parent = parent_handle.sys_path
            if os.name == "nt":
                verified_parent = _fs.strip_prefix(verified_parent)
            verified_dest = os.path.join(verified_parent, name)
            _check_inputs(dest, verified_dest, parent, input_handles)
            if os.path.lexists(dest):
                raise ReportError(REPORT_DESTINATION_EXISTS)
            handle = _create(parent_handle, name)
            try:
                handle.write_all(data)
            except BaseException as exc:
                # Win32 deletion is bound to the retained object handle.  POSIX
                # intentionally leaves a sanitized partial rather than race an
                # unlink-by-name against a replacement.
                handle.mark_delete()
                handle.close()
                if isinstance(exc, (FsError, OSError)):
                    raise ReportError(REPORT_WRITE_FAILED) from None
                raise
            handle.close()
        finally:
            parent_handle.close()
    finally:
        for input_handle in input_handles:
            input_handle.close()


def _create(parent_handle, name: str):
    try:
        return _fs.create_exclusive_at(parent_handle, name)
    except FsError as exc:
        if exc.exists:
            raise ReportError(REPORT_DESTINATION_EXISTS) from None
        if exc.code == "REPORT_IDENTITY_UNVERIFIED":
            raise ReportError(REPORT_IDENTITY_UNVERIFIED) from None
        raise ReportError(_report_code(exc, REPORT_WRITE_FAILED)) from None
