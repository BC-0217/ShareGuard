"""Strict bounded ZIP scanning without extraction or temporary plaintext.

The central directory is structurally bounded before :mod:`zipfile` may
materialise entries.  Stored and raw-DEFLATE payloads are then decoded by a
small independent reader, so declared uncompressed sizes cannot make
`ZipExtFile` truncate hidden trailing plaintext.
"""

from __future__ import annotations

import stat
import struct
import zipfile
import zlib

from .context import READ_CHUNK, StopScan, StopTarget
from .model import KIND_ARCHIVE_ENTRY, IssueCode
from .textscan import SNIFF_BYTES, is_unsupported_container, sniff_archive

MAX_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
_SMALL_READ = 256 * 1024
_EOCD = struct.Struct("<4s4H2LH")
_CD_HEADER_SIZE = 46
_LOCAL = struct.Struct("<4s5H3L2H")
_SUPPORTED_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
_AES_METHOD = 99
_DOS_REPARSE = 0x400
_ALLOWED_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0800
_RESERVED_NAMES = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)


class ZipProblem(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class BoundedReader:
    """Seekable handle view with bounded/accounted physical reads."""

    def __init__(self, handle, size: int, check, take_bytes=None, bytes_left=None):
        self._h = handle
        self._size = size
        self._pos = 0
        self._check = check
        self._take_bytes = take_bytes
        self._bytes_left = bytes_left
        self.allowed_large = None

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            pos = offset
        elif whence == 1:
            pos = self._pos + offset
        elif whence == 2:
            pos = self._size + offset
        else:
            raise OSError("bad whence")
        if pos < 0 or pos > self._size:
            raise OSError("invalid seek")
        self._pos = pos
        return pos

    def bytes_left(self):
        """Return the live aggregate budget, or None when not budgeted."""
        if self._bytes_left is None:
            return None
        return max(0, int(self._bytes_left()))

    def read(self, n=-1) -> bytes:
        self._check()
        remaining = max(0, self._size - self._pos)
        if n is None or n < 0 or n > remaining:
            n = remaining
        requested = n
        if requested > _SMALL_READ and (self._pos, requested) != self.allowed_large:
            raise OSError("unvalidated large read")
        budget_left = self.bytes_left()
        if budget_left is not None:
            n = min(n, budget_left + 1)
        parts = []
        got = 0
        self._h.seek(self._pos)
        while got < n:
            self._check()
            data = self._h.read(min(n - got, READ_CHUNK))
            if not data:
                break
            if self._take_bytes is not None:
                self._take_bytes(len(data))
            parts.append(data)
            got += len(data)
        self._pos += got
        return b"".join(parts)


def locate_central_directory(reader: BoundedReader, size: int):
    """Return (offset, size, declared_records, comment_length).

    Prepended bytes, trailing bytes, multi-disk and ZIP64 are deliberately
    unsupported rather than silently skipped.
    """
    if size < _EOCD.size:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    tail_start = max(0, size - (1 << 16) - _EOCD.size)
    reader.seek(tail_start)
    tail = reader.read(size - tail_start)
    index = tail.rfind(b"PK\x05\x06")
    if index < 0 or index + _EOCD.size > len(tail):
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    eocd_pos = tail_start + index
    rec = tail[index:index + _EOCD.size]
    (_sig, disk, disk_cd, n_disk, n_total, cd_size, cd_offset,
     comment_len) = _EOCD.unpack(rec)
    if eocd_pos + _EOCD.size + comment_len != size:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    if disk != 0 or disk_cd != 0 or n_disk != n_total:
        raise ZipProblem(IssueCode.ZIP_UNSUPPORTED_FEATURE)
    if (n_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF
            or (eocd_pos >= 20 and tail[index - 20:index - 16] == b"PK\x06\x07")):
        raise ZipProblem(IssueCode.ZIP_UNSUPPORTED_FEATURE)
    if cd_size > MAX_CENTRAL_DIRECTORY_BYTES:
        raise ZipProblem(IssueCode.ZIP_CENTRAL_DIRECTORY_LIMIT)
    if cd_offset + cd_size != eocd_pos:
        code = IssueCode.ZIP_UNSUPPORTED_FEATURE if cd_offset + cd_size < eocd_pos else \
            IssueCode.ZIP_CORRUPT
        raise ZipProblem(code)
    return cd_offset, cd_size, n_total, comment_len


def count_records(reader: BoundedReader, start_dir: int, cd_size: int,
                  declared: int, limit: int) -> int:
    reader.allowed_large = (start_dir, cd_size)
    reader.seek(start_dir)
    cd = reader.read(cd_size)
    if len(cd) != cd_size:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    pos = 0
    count = 0
    while pos < cd_size:
        reader._check()
        if pos + _CD_HEADER_SIZE > cd_size or cd[pos:pos + 4] != b"PK\x01\x02":
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        name_len, extra_len, comment_len = struct.unpack_from("<3H", cd, pos + 28)
        record_size = _CD_HEADER_SIZE + name_len + extra_len + comment_len
        if record_size < _CD_HEADER_SIZE or pos + record_size > cd_size:
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        pos += record_size
        count += 1
        if count > limit:
            raise ZipProblem(IssueCode.ENTRY_COUNT_LIMIT)
    if pos != cd_size or count != declared:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    return count


def unsafe_name(name: str) -> bool:
    if not name or len(name) > 4096:
        return True
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
        return True
    if "\\" in name or ":" in name or name.startswith("/"):
        return True
    for part in name.rstrip("/").split("/"):
        if part in ("", ".", "..") or len(part) > 255:
            return True
        if part != part.rstrip(" ."):
            return True
        if part.split(".")[0].upper() in _RESERVED_NAMES:
            return True
    return False


def _entry_kind_problem(info: zipfile.ZipInfo):
    mode = (info.external_attr >> 16) & 0xFFFF
    fmt = stat.S_IFMT(mode)
    if fmt == stat.S_IFLNK:
        return IssueCode.ZIP_LINK_ENTRY
    if fmt not in (0, stat.S_IFREG, stat.S_IFDIR):
        return IssueCode.ZIP_SPECIAL_ENTRY
    if info.create_system == 0 and info.external_attr & _DOS_REPARSE:
        return IssueCode.ZIP_LINK_ENTRY
    return None


def _is_plain_directory(info: zipfile.ZipInfo) -> bool:
    return (info.orig_filename.endswith("/") and info.file_size == 0
            and info.compress_size == 0)


def _map_zip_exception(exc: BaseException) -> str:
    if isinstance(exc, ZipProblem):
        return exc.code
    if isinstance(exc, zipfile.BadZipFile) and "CRC" in str(exc):
        return IssueCode.ZIP_CRC_MISMATCH
    if isinstance(exc, NotImplementedError):
        return IssueCode.ZIP_UNSUPPORTED_FEATURE
    return IssueCode.ZIP_CORRUPT


def _validate_extra(extra: bytes) -> None:
    pos = 0
    while pos < len(extra):
        if pos + 4 > len(extra):
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        _kind, length = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + length > len(extra):
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        pos += length
    if pos != len(extra):
        raise ZipProblem(IssueCode.ZIP_CORRUPT)


def _local_data_span(reader: BoundedReader, info: zipfile.ZipInfo,
                     start_dir: int) -> tuple[int, int, bool]:
    offset = info.header_offset
    if not isinstance(offset, int) or offset < 0 or offset + _LOCAL.size > start_dir:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    reader.seek(offset)
    header = reader.read(_LOCAL.size)
    if len(header) != _LOCAL.size:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    (sig, _version, flags, method, _mtime, _mdate, crc, compressed,
     uncompressed, name_len, extra_len) = _LOCAL.unpack(header)
    if sig != b"PK\x03\x04":
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    if flags & 0x0008:
        raise ZipProblem(IssueCode.ZIP_UNSUPPORTED_FEATURE)
    if (flags != info.flag_bits or method != info.compress_type
            or crc != info.CRC or compressed != info.compress_size
            or uncompressed != info.file_size):
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    reader.seek(offset + _LOCAL.size)
    local_name = reader.read(name_len)
    extra = reader.read(extra_len)
    if len(local_name) != name_len or len(extra) != extra_len:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    try:
        decoded = local_name.decode("utf-8" if flags & 0x0800 else "cp437")
    except UnicodeDecodeError:
        raise ZipProblem(IssueCode.ZIP_CORRUPT) from None
    if decoded != info.orig_filename:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    _validate_extra(extra)
    _validate_extra(info.extra)
    data_offset = offset + _LOCAL.size + name_len + extra_len
    end = data_offset + info.compress_size
    if end < data_offset or end > start_dir:
        raise ZipProblem(IssueCode.ZIP_CORRUPT)
    return data_offset, end, bool(extra or info.extra)


def _prepare_spans(reader: BoundedReader, infos, start_dir: int) -> dict:
    spans = []
    offsets = {}
    for info in infos:
        reader._check()
        data_offset, end, has_extra = _local_data_span(reader, info, start_dir)
        start = info.header_offset
        spans.append((start, end))
        offsets[id(info)] = (data_offset, has_extra)
    spans.sort()
    expected = 0
    for start, end in spans:
        if start != expected or end < start:
            raise ZipProblem(IssueCode.ZIP_UNSUPPORTED_FEATURE)
        expected = end
    if expected != start_dir:
        raise ZipProblem(IssueCode.ZIP_UNSUPPORTED_FEATURE)
    return offsets


class _EntryStream:
    """Independent bounded stored/raw-DEFLATE decoder."""

    def __init__(self, reader: BoundedReader, info: zipfile.ZipInfo, data_offset: int):
        self._reader = reader
        self._info = info
        self._reader.seek(data_offset)
        self._compressed_left = info.compress_size
        self._tail = b""
        self._buffer = bytearray()
        self._done = False
        self._decoder = zlib.decompressobj(-15) if info.compress_type == zipfile.ZIP_DEFLATED else None
        self.actual_size = 0
        self.crc = 0

    def _read_compressed(self, limit=READ_CHUNK) -> bytes:
        if self._compressed_left <= 0:
            return b""
        data = self._reader.read(min(READ_CHUNK, self._compressed_left, max(1, limit)))
        if not data:
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        self._compressed_left -= len(data)
        return data

    def _live_output_limit(self, requested: int) -> int:
        """Cap newly decoded output against the live post-read budget.

        Bytes already buffered are decoded plaintext not yet charged by the
        caller, so they reserve the same aggregate allowance.
        """
        requested = max(1, requested)
        remaining = self._reader.bytes_left()
        if remaining is None:
            return requested
        return min(requested, max(0, remaining + 1 - len(self._buffer)))

    def _pump(self, output_limit: int) -> bool:
        if self._done:
            return False
        output_limit = max(1, output_limit)
        if self._decoder is None:
            remaining = self._reader.bytes_left()
            if remaining is None:
                read_limit = output_limit
            else:
                # Stored bytes count once as physical input and again as
                # inspected plaintext. Reserve both shares before reading.
                combined = remaining + 1 - len(self._buffer)
                if combined <= 0:
                    return False
                read_limit = combined // 2
                if read_limit <= 0:
                    # Consume at most the one physical sentinel; the reader's
                    # accounting raises before any plaintext can be produced.
                    self._read_compressed(1)
                    return False
                read_limit = min(output_limit, read_limit)
            data = self._read_compressed(read_limit)
            if data:
                self._buffer.extend(data)
            if self._compressed_left == 0:
                self._done = True
            return bool(data) or self._done

        if self._tail:
            data, self._tail = self._tail, b""
        else:
            data = self._read_compressed()

        # _read_compressed accounts physical bytes immediately. Recompute from
        # that live value; a pre-read allowance is stale and could let zlib
        # overproduce beyond the combined physical+decoded aggregate budget.
        live_limit = self._live_output_limit(output_limit)
        if live_limit <= 0:
            if data:
                self._tail = data
            return False
        if not data:
            if self._decoder.eof:
                self._done = True
                return True
            try:
                out = self._decoder.decompress(b"", live_limit)
            except zlib.error:
                raise ZipProblem(IssueCode.ZIP_CORRUPT) from None
            if out:
                self._buffer.extend(out)
                return True
            if self._decoder.eof:
                self._done = True
                return True
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        try:
            out = self._decoder.decompress(data, live_limit)
        except zlib.error:
            raise ZipProblem(IssueCode.ZIP_CORRUPT) from None
        self._tail = self._decoder.unconsumed_tail
        if self._decoder.unused_data:
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        if out:
            self._buffer.extend(out)
        if self._decoder.eof and not self._tail:
            if self._compressed_left != 0:
                raise ZipProblem(IssueCode.ZIP_CORRUPT)
            self._done = True
        elif not out and not self._tail and self._compressed_left == 0:
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        return bool(out) or bool(self._tail) or self._done

    def read(self, n=-1) -> bytes:
        if n is None or n < 0:
            n = READ_CHUNK
        if n == 0:
            return b""
        while len(self._buffer) < n and not self._done:
            if not self._pump(n - len(self._buffer)):
                break
        take = min(n, len(self._buffer))
        data = bytes(self._buffer[:take])
        del self._buffer[:take]
        if data:
            self.actual_size += len(data)
            self.crc = zlib.crc32(data, self.crc)
        return data

    def validate(self) -> tuple[bool, bool]:
        if not self._done or self._buffer:
            raise ZipProblem(IssueCode.ZIP_CORRUPT)
        return self.actual_size == self._info.file_size, self.crc == self._info.CRC


def _drain_entry(ctx, stream: _EntryStream, deadline: float) -> None:
    while True:
        ctx.check(deadline)
        want = min(
            READ_CHUNK,
            ctx.policy.max_file_bytes - stream.actual_size + 1,
            ctx.bytes_left() + 1,
        )
        data = stream.read(max(1, want))
        if not data:
            return
        ctx.take_bytes(len(data))
        if stream.actual_size > ctx.policy.max_file_bytes:
            raise StopTarget(IssueCode.ZIP_ENTRY_TOO_LARGE)


def scan_zip(ctx, handle, archive_tid: str, depth: int, size: int,
             display_path, deadline: float) -> None:
    """Scan one physical ZIP whose container size was already bounded."""
    reader = BoundedReader(
        handle,
        size,
        lambda: ctx.check(deadline),
        take_bytes=ctx.take_bytes,
        bytes_left=ctx.bytes_left,
    )
    try:
        start_dir, cd_size, declared, _comment_len = locate_central_directory(reader, size)
        records = count_records(
            reader, start_dir, cd_size, declared, ctx.remaining_entries())
        zf = zipfile.ZipFile(reader)
    except (StopScan, StopTarget):
        raise
    except Exception as exc:
        ctx.add_issue(_map_zip_exception(exc), archive_tid)
        return
    try:
        infos = list(zf.infolist())
        if len(infos) != records:
            ctx.add_issue(IssueCode.ZIP_CORRUPT, archive_tid)
            return
        offsets = _prepare_spans(reader, infos, start_dir)
        if zf.comment:
            ctx.add_issue(IssueCode.ZIP_COMMENT_NOT_SCANNED, archive_tid)
        seen_names = set()
        for info in infos:
            ctx.check(deadline)
            _scan_entry(
                ctx, reader, info, offsets[id(info)][0], offsets[id(info)][1],
                archive_tid, depth, display_path, seen_names, deadline)
    except (StopScan, StopTarget):
        raise
    except Exception as exc:
        ctx.add_issue(_map_zip_exception(exc), archive_tid)
    finally:
        zf.close()


def _scan_entry(ctx, reader, info, data_offset, has_extra, archive_tid, depth,
                display_path, seen_names, deadline) -> None:
    policy = ctx.policy
    name = info.orig_filename
    dup_key = name.replace("\\", "/").rstrip("/").casefold()
    duplicate = dup_key in seen_names
    seen_names.add(dup_key)

    kind_problem = _entry_kind_problem(info)
    encrypted = bool(info.flag_bits & 0x1 or info.compress_type == _AES_METHOD)
    unsupported_flags = info.flag_bits & ~_ALLOWED_FLAGS
    unsupported_method = info.compress_type not in _SUPPORTED_METHODS
    if info.compress_type == zipfile.ZIP_STORED and info.flag_bits & 0x0006:
        unsupported_flags = True
    unsupported_extra = bool(has_extra)
    unsafe = unsafe_name(name)
    commented = bool(info.comment)
    plain_directory = _is_plain_directory(info)

    # Only a completely ordinary directory may avoid a result target.  Every
    # feature/kind check above runs first, closing the old "dir/" bypass.
    if (plain_directory and not duplicate and not unsafe and not commented
            and kind_problem is None and not encrypted and not unsupported_flags
            and not unsupported_method and not unsupported_extra):
        ctx.take_entry(archive_tid)
        return

    tid = ctx.new_target(KIND_ARCHIVE_ENTRY, archive_tid, None, display_path, name)
    ctx.take_entry(tid)
    if duplicate:
        ctx.add_issue(IssueCode.ZIP_DUPLICATE_NAME, tid)
    if unsafe:
        ctx.add_issue(IssueCode.ZIP_UNSAFE_NAME, tid)
    if commented:
        ctx.add_issue(IssueCode.ZIP_COMMENT_NOT_SCANNED, tid)
    if kind_problem:
        ctx.add_issue(kind_problem, tid)
        return
    if encrypted:
        ctx.add_issue(IssueCode.ZIP_ENCRYPTED_ENTRY, tid)
        return
    if unsupported_flags:
        ctx.add_issue(IssueCode.ZIP_UNSUPPORTED_FEATURE, tid)
        return
    if unsupported_method:
        ctx.add_issue(IssueCode.ZIP_UNSUPPORTED_COMPRESSION, tid)
        return
    if unsupported_extra:
        ctx.add_issue(IssueCode.ZIP_UNSUPPORTED_FEATURE, tid)
        return
    if plain_directory:
        return

    entry_depth = depth + 1 + name.rstrip("/").count("/")
    if entry_depth > policy.max_depth:
        ctx.add_issue(IssueCode.DEPTH_LIMIT, tid)
        return
    if info.file_size > policy.max_file_bytes:
        ctx.add_issue(IssueCode.ZIP_ENTRY_TOO_LARGE, tid)
        return

    stream = _EntryStream(reader, info, data_offset)
    completed = False
    try:
        first_want = min(
            SNIFF_BYTES,
            policy.max_file_bytes + 1,
            ctx.bytes_left() + 1,
        )
        first = stream.read(max(1, first_want))
        nested = bool(sniff_archive(first)) or name.lower().endswith(".zip")
        unsupported_container = is_unsupported_container(name, first)
        if nested or unsupported_container:
            ctx.take_bytes(len(first))
            _drain_entry(ctx, stream, deadline)
            ctx.add_issue(
                IssueCode.ZIP_NESTED_ARCHIVE if nested
                else IssueCode.UNSUPPORTED_ARCHIVE,
                tid,
            )
        else:
            completed = ctx.scan_stream(
                tid, first, stream.read, policy.max_file_bytes, deadline,
                IssueCode.ZIP_ENTRY_TOO_LARGE)
            if not completed:
                _drain_entry(ctx, stream, deadline)
        size_ok, crc_ok = stream.validate()
        if not size_ok:
            ctx.add_issue(IssueCode.ZIP_CORRUPT, tid)
        if not crc_ok:
            ctx.add_issue(IssueCode.ZIP_CRC_MISMATCH, tid)
    except StopTarget as exc:
        ctx.add_issue(exc.code, tid)
        return
    except StopScan:
        raise
    except Exception as exc:
        ctx.add_issue(_map_zip_exception(exc), tid)
        return
    if completed:
        ctx.archive_entries_scanned += 1
