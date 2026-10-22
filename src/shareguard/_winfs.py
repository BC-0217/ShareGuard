"""Win32 handle-based filesystem access (ctypes, stdlib only).

Objects are opened with FILE_FLAG_OPEN_REPARSE_POINT so a link is never
followed; the handle's own attributes, type and final path are then verified.
Handles deny FILE_SHARE_DELETE so the verified path stays bound to the object
(no rename/delete/replace) while it is open.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import stat
from ctypes import wintypes

from .model import IssueCode

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
CREATE_NEW = 1
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_DEVICE = 0x40
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_REMOTE_ATTRS = (FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN
                 | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
FILE_TYPE_DISK = 1
DRIVE_REMOTE = 4
INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2
FILE_BASIC_INFO_CLASS = 0
FILE_DISPOSITION_INFO_CLASS = 4
FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_ACCESS_DENIED = 5
ERROR_FILE_EXISTS = 80
ERROR_INVALID_NAME = 123
ERROR_ALREADY_EXISTS = 183
ERROR_BAD_NETPATH = 53
ERROR_DIRECTORY = 267


class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wintypes.DWORD), ("hi", wintypes.DWORD)]


class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", FILETIME),
        ("ftLastAccessTime", FILETIME),
        ("ftLastWriteTime", FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class FILE_BASIC_INFO(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_longlong),
        ("LastAccessTime", ctypes.c_longlong),
        ("LastWriteTime", ctypes.c_longlong),
        ("ChangeTime", ctypes.c_longlong),
        ("FileAttributes", wintypes.DWORD),
    ]


class FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]


class FILE_DISPOSITION_INFO(ctypes.Structure):
    _fields_ = [("DeleteFile", wintypes.BOOLEAN)]


_CreateFileW = kernel32.CreateFileW
_CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                         wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                         wintypes.HANDLE]
_CreateFileW.restype = wintypes.HANDLE
_CloseHandle = kernel32.CloseHandle
_CloseHandle.argtypes = [wintypes.HANDLE]
_CloseHandle.restype = wintypes.BOOL
_GetFinalPathNameByHandleW = kernel32.GetFinalPathNameByHandleW
_GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                       wintypes.DWORD, wintypes.DWORD]
_GetFinalPathNameByHandleW.restype = wintypes.DWORD
_GetFileInformationByHandle = kernel32.GetFileInformationByHandle
_GetFileInformationByHandle.argtypes = [wintypes.HANDLE,
                                        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
_GetFileInformationByHandle.restype = wintypes.BOOL
_GetFileInformationByHandleEx = kernel32.GetFileInformationByHandleEx
_GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                          wintypes.LPVOID, wintypes.DWORD]
_GetFileInformationByHandleEx.restype = wintypes.BOOL
_SetFileInformationByHandle = kernel32.SetFileInformationByHandle
_SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                        wintypes.LPVOID, wintypes.DWORD]
_SetFileInformationByHandle.restype = wintypes.BOOL
_GetFileType = kernel32.GetFileType
_GetFileType.argtypes = [wintypes.HANDLE]
_GetFileType.restype = wintypes.DWORD
_ReadFile = kernel32.ReadFile
_ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                      ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
_ReadFile.restype = wintypes.BOOL
_WriteFile = kernel32.WriteFile
_WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                       ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
_WriteFile.restype = wintypes.BOOL
_FlushFileBuffers = kernel32.FlushFileBuffers
_FlushFileBuffers.argtypes = [wintypes.HANDLE]
_FlushFileBuffers.restype = wintypes.BOOL
_SetFilePointerEx = kernel32.SetFilePointerEx
_SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong,
                              ctypes.POINTER(ctypes.c_longlong), wintypes.DWORD]
_SetFilePointerEx.restype = wintypes.BOOL
_GetLongPathNameW = kernel32.GetLongPathNameW
_GetLongPathNameW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
_GetLongPathNameW.restype = wintypes.DWORD
_GetDriveTypeW = kernel32.GetDriveTypeW
_GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
_GetDriveTypeW.restype = wintypes.UINT
_GetFileAttributesW = kernel32.GetFileAttributesW
_GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
_GetFileAttributesW.restype = wintypes.DWORD


class FsError(Exception):
    """Filesystem failure carrying only a fixed issue code."""

    def __init__(self, code: str, winerror: int = 0):
        super().__init__(code)
        self.code = code
        self.winerror = winerror

    @property
    def exists(self) -> bool:
        return self.winerror in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS)


def _error_code(winerror: int) -> str:
    if winerror in (ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_BAD_NETPATH):
        return IssueCode.PATH_NOT_FOUND
    if winerror == ERROR_ACCESS_DENIED:
        return IssueCode.ACCESS_DENIED
    if winerror == ERROR_INVALID_NAME:
        return IssueCode.PATH_UNSUPPORTED
    return IssueCode.OPEN_FAILED


# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------

def strip_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    if path.startswith("\\\\?\\"):
        return path[4:]
    return path


def long_path(path: str) -> str:
    """Expand 8.3 short names when possible (path must exist)."""
    size = 1024
    while size <= 65536:
        buf = ctypes.create_unicode_buffer(size)
        n = _GetLongPathNameW(path, buf, size)
        if n == 0:
            return path
        if n < size:
            return buf.value
        size = n + 1
    return path


def same_path(a: str, b: str) -> bool:
    return ntpath.normcase(strip_prefix(a)).rstrip("\\") == \
        ntpath.normcase(strip_prefix(b)).rstrip("\\")


def check_selectable(abspath: str) -> None:
    """Pure syntax/namespace and local-drive preflight.

    No API here receives the candidate leaf path.  In particular, UNC/device
    syntax and mapped drives are rejected before lstat, long-path expansion,
    attribute lookup, or CreateFile can traverse an invalid ancestor.
    """
    if not isinstance(abspath, str) or not abspath or "\x00" in abspath:
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    folded = abspath.replace("/", "\\")
    upper = folded.upper()
    if (folded.startswith("\\\\") or folded.startswith("//")
            or upper.startswith("\\\\?\\") or upper.startswith("\\\\.\\")
            or upper.startswith("\\??\\")):
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    drive, rest = ntpath.splitdrive(folded)
    if drive and not rest.startswith("\\"):
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    if ":" in rest:
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    components = [part for part in rest.split("\\") if part]
    if any(part in (".", "..") for part in components):
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    for component in components:
        base = component.rstrip(" .").split(".", 1)[0].upper()
        if base in {"CON", "PRN", "AUX", "NUL"} or (
                len(base) == 4 and base[:3] in {"COM", "LPT"} and base[3] in "123456789"):
            raise FsError(IssueCode.PATH_UNSUPPORTED)
    if drive and _GetDriveTypeW(drive + "\\") == DRIVE_REMOTE:
        raise FsError(IssueCode.PATH_UNSUPPORTED)


def lstat_is_link(st) -> bool:
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT) or stat.S_ISLNK(st.st_mode)


def _path_prefixes(abspath: str, include_self: bool) -> list[str]:
    """Return absolute drive prefixes from root to leaf."""
    folded = abspath.replace("/", "\\")
    drive, rest = ntpath.splitdrive(folded)
    prefixes = [drive + "\\"]
    current = prefixes[0]
    for component in (part for part in rest.split("\\") if part):
        current = ntpath.join(current, component)
        prefixes.append(current)
    if not include_self:
        prefixes = prefixes[:-1]
    return prefixes


def _lstat_prefix(path: str):
    """Inspect exactly one already-reached prefix without following itself."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise FsError(IssueCode.PATH_NOT_FOUND) from None
    except PermissionError:
        raise FsError(IssueCode.IDENTITY_UNVERIFIED) from None
    except OSError:
        raise FsError(IssueCode.IDENTITY_UNVERIFIED) from None
    attrs = getattr(st, "st_file_attributes", 0)
    if lstat_is_link(st):
        raise FsError(IssueCode.LINK_REJECTED)
    if attrs & (FILE_ATTRIBUTE_DEVICE | _REMOTE_ATTRS):
        raise FsError(IssueCode.SPECIAL_FILE)
    return st


def check_ancestors(abspath: str, include_self: bool) -> None:
    """Validate the chain top-down, stopping before any invalid descendant."""
    prefixes = _path_prefixes(abspath, include_self)
    for index, path in enumerate(prefixes):
        st = _lstat_prefix(path)
        if index < len(prefixes) - 1 and not stat.S_ISDIR(st.st_mode):
            raise FsError(IssueCode.PATH_NOT_FOUND)


# --------------------------------------------------------------------------
# Handle wrapper
# --------------------------------------------------------------------------

def final_path(handle) -> str:
    size = 1024
    while size <= 65536:
        buf = ctypes.create_unicode_buffer(size)
        n = _GetFinalPathNameByHandleW(handle, buf, size, 0)
        if n == 0:
            raise FsError(IssueCode.IDENTITY_UNVERIFIED)
        if n < size:
            return buf.value
        size = n + 1
    raise FsError(IssueCode.IDENTITY_UNVERIFIED)


def _close(handle) -> None:
    if handle not in (None, INVALID_HANDLE_VALUE):
        _CloseHandle(handle)


class WinHandle:
    """Verified open file or directory handle."""

    def __init__(self, handle, sys_path: str, is_dir: bool):
        self._h = handle
        self.sys_path = sys_path
        self.is_dir = is_dir

    def close(self) -> None:
        h, self._h = self._h, None
        _close(h)

    @property
    def closed(self) -> bool:
        return self._h is None

    def info(self) -> BY_HANDLE_FILE_INFORMATION:
        info = BY_HANDLE_FILE_INFORMATION()
        if not _GetFileInformationByHandle(self._h, ctypes.byref(info)):
            raise FsError(IssueCode.IDENTITY_UNVERIFIED)
        return info

    def snapshot(self) -> tuple:
        info = self.info()
        basic = FILE_BASIC_INFO()
        if not _GetFileInformationByHandleEx(self._h, FILE_BASIC_INFO_CLASS,
                                             ctypes.byref(basic), ctypes.sizeof(basic)):
            raise FsError(IssueCode.IDENTITY_UNVERIFIED)
        size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
        index = (info.nFileIndexHigh << 32) | info.nFileIndexLow
        return (info.dwVolumeSerialNumber, index, size, basic.LastWriteTime,
                basic.ChangeTime, bool(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))

    def size(self) -> int:
        info = self.info()
        return (info.nFileSizeHigh << 32) | info.nFileSizeLow

    def read(self, n: int) -> bytes:
        if n <= 0:
            return b""
        buf = ctypes.create_string_buffer(n)
        got = wintypes.DWORD(0)
        if not _ReadFile(self._h, buf, n, ctypes.byref(got), None):
            raise FsError(IssueCode.READ_ERROR)
        return buf.raw[: got.value]

    def seek(self, offset: int, whence: int = 0) -> int:
        method = {0: FILE_BEGIN, 1: FILE_CURRENT, 2: FILE_END}[whence]
        newpos = ctypes.c_longlong(0)
        if not _SetFilePointerEx(self._h, offset, ctypes.byref(newpos), method):
            raise OSError("seek failed")
        return newpos.value

    def tell(self) -> int:
        return self.seek(0, 1)

    def write_all(self, data: bytes) -> None:
        view = memoryview(data)
        while view:
            chunk = view[: 1 << 20]
            done = wintypes.DWORD(0)
            buf = ctypes.create_string_buffer(bytes(chunk), len(chunk))
            if not _WriteFile(self._h, buf, len(chunk), ctypes.byref(done), None):
                raise FsError("REPORT_WRITE_FAILED")
            if done.value == 0:
                raise FsError("REPORT_WRITE_FAILED")
            view = view[done.value:]
        if not _FlushFileBuffers(self._h):
            raise FsError("REPORT_WRITE_FAILED")

    def mark_delete(self) -> bool:
        disp = FILE_DISPOSITION_INFO(True)
        return bool(_SetFileInformationByHandle(self._h, FILE_DISPOSITION_INFO_CLASS,
                                                ctypes.byref(disp), ctypes.sizeof(disp)))

    def list_names(self, limit: int) -> list:
        """Return up to ``limit`` + 1 child names (caller detects overflow)."""
        names = []
        try:
            with os.scandir(self.sys_path) as it:
                for entry in it:
                    names.append(entry.name)
                    if len(names) > limit:
                        break
        except OSError:
            raise FsError(IssueCode.DIRECTORY_READ_ERROR) from None
        return names


def _open_raw(sys_path: str, access: int, disposition: int, extra_flags: int = 0,
              *, backup_semantics: bool = False):
    flags = (FILE_FLAG_OPEN_REPARSE_POINT
             | (extra_flags & ~FILE_FLAG_BACKUP_SEMANTICS))
    if backup_semantics:
        flags |= FILE_FLAG_BACKUP_SEMANTICS
    h = _CreateFileW(sys_path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                     disposition, flags, None)
    if h in (None, INVALID_HANDLE_VALUE):
        err = ctypes.get_last_error()
        raise FsError(_error_code(err), err)
    return h


def _verify_handle(h, expected_path: str) -> bool:
    """Verify type/attributes/final path; returns is_dir."""
    if _GetFileType(h) != FILE_TYPE_DISK:
        raise FsError(IssueCode.SPECIAL_FILE)
    tag = FILE_ATTRIBUTE_TAG_INFO()
    if not _GetFileInformationByHandleEx(h, FILE_ATTRIBUTE_TAG_INFO_CLASS,
                                         ctypes.byref(tag), ctypes.sizeof(tag)):
        raise FsError(IssueCode.IDENTITY_UNVERIFIED)
    attrs = tag.FileAttributes
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
        raise FsError(IssueCode.LINK_REJECTED)
    if attrs & (FILE_ATTRIBUTE_DEVICE | _REMOTE_ATTRS):
        raise FsError(IssueCode.SPECIAL_FILE)
    if not same_path(final_path(h), expected_path):
        raise FsError(IssueCode.IDENTITY_UNVERIFIED)
    return bool(attrs & FILE_ATTRIBUTE_DIRECTORY)


def _handle_binding(h) -> tuple[int, int, int]:
    """Return stable object identity plus attributes for cross-handle binding."""
    info = BY_HANDLE_FILE_INFORMATION()
    if not _GetFileInformationByHandle(h, ctypes.byref(info)):
        raise FsError(IssueCode.IDENTITY_UNVERIFIED)
    index = (info.nFileIndexHigh << 32) | info.nFileIndexLow
    return info.dwVolumeSerialNumber, index, info.dwFileAttributes


def open_verified(sys_path: str, expected_path: str,
                  access: int = GENERIC_READ, *,
                  expected_is_dir: bool) -> WinHandle:
    """Open verified metadata first, then a separately verified data handle.

    A zero-access metadata handle pins the object first. Directory capability
    requires FILE_FLAG_BACKUP_SEMANTICS on Windows, but regular-file data and
    report-write handles never receive that flag. The metadata pin stays open
    until both handles match in type, identity, attributes, and final path.
    """
    metadata = None
    data = None
    try:
        metadata = _open_raw(
            sys_path, 0, OPEN_EXISTING,
            backup_semantics=expected_is_dir)
        metadata_is_dir = _verify_handle(metadata, expected_path)
        if metadata_is_dir != expected_is_dir:
            raise FsError(IssueCode.IDENTITY_UNVERIFIED)
        metadata_binding = _handle_binding(metadata)
        metadata_final = final_path(metadata)

        if access == 0:
            handle = WinHandle(metadata, metadata_final, metadata_is_dir)
            metadata = None
            return handle

        data = _open_raw(
            sys_path, access, OPEN_EXISTING,
            backup_semantics=metadata_is_dir)
        data_is_dir = _verify_handle(data, expected_path)
        data_binding = _handle_binding(data)
        if (data_is_dir != metadata_is_dir
                or data_binding != metadata_binding):
            raise FsError(IssueCode.IDENTITY_UNVERIFIED)
        data_final = final_path(data)
        handle = WinHandle(data, data_final, data_is_dir)
        data = None
        return handle
    finally:
        if data is not None:
            _close(data)
        if metadata is not None:
            _close(metadata)


def _pin_ancestor_chain(abspath: str) -> tuple[list[WinHandle], bool]:
    """Validate and bind each directory prefix before inspecting deeper paths."""
    prefixes = _path_prefixes(abspath, include_self=True)
    guards = []
    try:
        for path in prefixes[:-1]:
            st = _lstat_prefix(path)
            if not stat.S_ISDIR(st.st_mode):
                raise FsError(IssueCode.PATH_NOT_FOUND)
            guard = open_verified(
                path, long_path(path), access=0, expected_is_dir=True)
            if not guard.is_dir:
                guard.close()
                raise FsError(IssueCode.IDENTITY_UNVERIFIED)
            guards.append(guard)
        # Ancestors are now held without FILE_SHARE_DELETE.  Only now may the
        # leaf itself be queried.
        leaf_st = _lstat_prefix(prefixes[-1])
        return guards, stat.S_ISDIR(leaf_st.st_mode)
    except BaseException:
        for guard in reversed(guards):
            guard.close()
        raise


def open_root(abspath: str) -> WinHandle:
    check_selectable(abspath)
    guards, leaf_is_dir = _pin_ancestor_chain(abspath)
    try:
        expected = long_path(abspath)
        handle = open_verified(
            abspath, expected, expected_is_dir=leaf_is_dir)
        # Re-check while every ancestor guard and the leaf handle are held.
        try:
            check_ancestors(abspath, include_self=False)
        except BaseException:
            handle.close()
            raise
        return handle
    finally:
        for guard in reversed(guards):
            guard.close()


def open_child(parent: WinHandle, name: str) -> WinHandle:
    if not name or name in (".", "..") or any(c in name for c in "\\/:\x00"):
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    before = parent.snapshot()
    if not same_path(final_path(parent._h), parent.sys_path):
        raise FsError(IssueCode.IDENTITY_UNVERIFIED)
    sys_path = ntpath.join(parent.sys_path, name)
    selectable = strip_prefix(sys_path)
    check_selectable(selectable)
    # The verified parent remains pinned while the child itself is inspected
    # without following it.  Reject recall/offline/device/reparse attributes
    # before GENERIC_READ can trigger an open of that leaf.
    child_st = _lstat_prefix(selectable)
    child = open_verified(
        sys_path, sys_path, expected_is_dir=stat.S_ISDIR(child_st.st_mode))
    try:
        if parent.snapshot() != before or not same_path(final_path(parent._h), parent.sys_path):
            raise FsError(IssueCode.MUTATION_DETECTED)
    except BaseException:
        child.close()
        raise
    return child


def create_exclusive_at(parent: WinHandle, name: str) -> WinHandle:
    if not name or name in (".", "..") or any(c in name for c in "\\/:\x00"):
        raise FsError("REPORT_PATH_INVALID")
    before = parent.snapshot()
    if not parent.is_dir or not same_path(final_path(parent._h), parent.sys_path):
        raise FsError("REPORT_IDENTITY_UNVERIFIED")
    sys_path = ntpath.join(parent.sys_path, name)
    check_selectable(strip_prefix(sys_path))
    handle = create_exclusive(sys_path, sys_path)
    try:
        if (parent.snapshot()[:2] != before[:2]
                or not same_path(final_path(parent._h), parent.sys_path)):
            raise FsError("REPORT_IDENTITY_UNVERIFIED")
    except BaseException:
        handle.mark_delete()
        handle.close()
        raise
    return handle


def create_exclusive(abspath: str, expected_path: str) -> WinHandle:
    """Create a new file (fails if anything exists there) and verify it."""
    h = _open_raw(abspath, GENERIC_WRITE | DELETE, CREATE_NEW, FILE_ATTRIBUTE_NORMAL)
    handle = WinHandle(h, abspath, False)
    try:
        if _GetFileType(h) != FILE_TYPE_DISK or not same_path(final_path(h), expected_path):
            raise FsError("REPORT_IDENTITY_UNVERIFIED")
    except BaseException:
        handle.mark_delete()
        handle.close()
        raise
    return handle
