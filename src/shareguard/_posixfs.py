"""POSIX descriptor-based filesystem access.

Every component is opened relative to its verified parent descriptor with
O_NOFOLLOW, so symlinks anywhere on the path are rejected and traversal can
never leave the opened directory tree. Non-regular, non-directory objects are
rejected from lstat information before they are ever opened.
"""

from __future__ import annotations

import errno
import os
import stat

from .model import IssueCode

_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIR_FLAGS = os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC
_SUPPORTS_DIRFD = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd


class FsError(Exception):
    def __init__(self, code: str, errnum: int = 0):
        super().__init__(code)
        self.code = code
        self.errnum = errnum

    @property
    def exists(self) -> bool:
        return self.errnum == errno.EEXIST


def _code_for(exc: OSError) -> str:
    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
        return IssueCode.PATH_NOT_FOUND
    if exc.errno in (errno.EACCES, errno.EPERM):
        return IssueCode.ACCESS_DENIED
    if exc.errno == errno.ELOOP:
        return IssueCode.LINK_REJECTED
    return IssueCode.OPEN_FAILED


def check_selectable(abspath: str) -> None:
    if "\x00" in abspath:
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    if not _SUPPORTS_DIRFD or not _O_NOFOLLOW:
        # Cannot provide descriptor-relative no-follow traversal: fail closed.
        raise FsError(IssueCode.IDENTITY_UNVERIFIED)


def same_path(a: str, b: str) -> bool:
    return os.path.normpath(a) == os.path.normpath(b)


def long_path(path: str) -> str:
    return path


def _ident(st) -> tuple:
    return (st.st_dev, st.st_ino)


class PosixHandle:
    def __init__(self, fd: int, sys_path: str, is_dir: bool):
        self._fd = fd
        self.sys_path = sys_path
        self.is_dir = is_dir
        self._created_in = None  # (parent_fd, name) for files we created

    @property
    def fd(self) -> int:
        return self._fd

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)
        if self._created_in is not None:
            pfd, self._created_in = self._created_in[0], None
            os.close(pfd)

    @property
    def closed(self) -> bool:
        return self._fd is None

    def snapshot(self) -> tuple:
        try:
            st = os.fstat(self._fd)
        except OSError:
            raise FsError(IssueCode.IDENTITY_UNVERIFIED) from None
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
                stat.S_ISDIR(st.st_mode))

    def size(self) -> int:
        return os.fstat(self._fd).st_size

    def read(self, n: int) -> bytes:
        try:
            return os.read(self._fd, n)
        except OSError:
            raise FsError(IssueCode.READ_ERROR) from None

    def seek(self, offset: int, whence: int = 0) -> int:
        return os.lseek(self._fd, offset, whence)

    def tell(self) -> int:
        return os.lseek(self._fd, 0, os.SEEK_CUR)

    def write_all(self, data: bytes) -> None:
        view = memoryview(data)
        try:
            while view:
                n = os.write(self._fd, view[: 1 << 20])
                if n <= 0:
                    raise FsError("REPORT_WRITE_FAILED")
                view = view[n:]
            os.fsync(self._fd)
        except OSError:
            raise FsError("REPORT_WRITE_FAILED") from None

    def mark_delete(self) -> bool:
        # POSIX has no stdlib atomic unlink-if-inode primitive.  A stat/unlink
        # sequence can delete an attacker's replacement, so leave the sanitized
        # partial file and report failure instead.
        return False

    def list_names(self, limit: int) -> list:
        names = []
        try:
            dup = os.dup(self._fd)
            try:
                with os.scandir(dup) as it:
                    for entry in it:
                        names.append(entry.name)
                        if len(names) > limit:
                            break
            finally:
                os.close(dup)
        except OSError:
            raise FsError(IssueCode.DIRECTORY_READ_ERROR) from None
        return names


def _open_at(parent_fd: int, name: str, sys_path: str) -> PosixHandle:
    try:
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise FsError(_code_for(exc), exc.errno) from None
    if stat.S_ISLNK(st.st_mode):
        raise FsError(IssueCode.LINK_REJECTED)
    if stat.S_ISDIR(st.st_mode):
        flags, is_dir = _DIR_FLAGS, True
    elif stat.S_ISREG(st.st_mode):
        flags, is_dir = _FILE_FLAGS, False
    else:
        raise FsError(IssueCode.SPECIAL_FILE)
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise FsError(_code_for(exc), exc.errno) from None
    try:
        fst = os.fstat(fd)
        if _ident(fst) != _ident(st) or stat.S_IFMT(fst.st_mode) != stat.S_IFMT(st.st_mode):
            raise FsError(IssueCode.MUTATION_DETECTED)
    except BaseException:
        os.close(fd)
        raise
    return PosixHandle(fd, sys_path, is_dir)


def _open_dir_chain(abspath: str):
    """Open every directory component of ``abspath`` with O_NOFOLLOW.

    Returns (parent_fd, last_name)."""
    parts = [p for p in abspath.split("/") if p]
    try:
        fd = os.open("/", _DIR_FLAGS)
    except OSError as exc:
        raise FsError(_code_for(exc), exc.errno) from None
    current = "/"
    try:
        for part in parts[:-1]:
            child = _open_at(fd, part, os.path.join(current, part))
            if not child.is_dir:
                child.close()
                raise FsError(IssueCode.PATH_NOT_FOUND)
            os.close(fd)
            fd = child._fd
            child._fd = None
            current = os.path.join(current, part)
    except BaseException:
        os.close(fd)
        raise
    return fd, (parts[-1] if parts else None)


def open_root(abspath: str) -> PosixHandle:
    check_selectable(abspath)
    fd, last = _open_dir_chain(abspath)
    try:
        if last is None:
            return PosixHandle(os.dup(fd), "/", True)
        return _open_at(fd, last, abspath)
    finally:
        os.close(fd)


def open_child(parent: PosixHandle, name: str) -> PosixHandle:
    if not name or name in (".", "..") or "/" in name or "\x00" in name:
        raise FsError(IssueCode.PATH_UNSUPPORTED)
    return _open_at(parent.fd, name, os.path.join(parent.sys_path, name))


def create_exclusive_at(parent: PosixHandle, name: str) -> PosixHandle:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
    try:
        fd = os.open(name, flags, 0o600, dir_fd=parent.fd)
    except OSError as exc:
        raise FsError(_code_for(exc), exc.errno) from None
    handle = PosixHandle(fd, os.path.join(parent.sys_path, name), False)
    handle._created_in = (os.dup(parent.fd), name)
    return handle
