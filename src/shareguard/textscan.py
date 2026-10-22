"""Incremental text decoding and bounded line-window scanning.

Bytes are fed in chunks. Encoding is decided from the first bytes (BOM or
UTF-16 heuristics); undecidable/binary content stops the scan with an issue.
Matches are mapped to 1-based line numbers. Lines longer than
``max_line_chars`` are scanned in overlapping windows and reported as
``LINE_TOO_LONG`` (incomplete).
"""

from __future__ import annotations

import bisect
import codecs
from array import array

from .model import IssueCode
from .rules import MAX_MATCH_CHARS, iter_matches

SNIFF_BYTES = 4096

_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_OTHER_ARCHIVE_MAGIC = (
    b"\x1f\x8b",                  # gzip
    b"\xfd7zXZ\x00",              # xz
    b"7z\xbc\xaf\x27\x1c",        # 7z
    b"Rar!\x1a\x07",              # rar
    b"\x28\xb5\x2f\xfd",          # zstd
    b"MSCF",                      # cab
)

UNSUPPORTED_CONTAINER_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".odt", ".ods", ".odp",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp",
    ".heic", ".ico", ".svg",
})

_CONTROL_BYTES = frozenset(
    list(range(0x00, 0x08)) + list(range(0x0E, 0x1B)) + list(range(0x1C, 0x20)) + [0x7F]
)


def sniff_archive(head: bytes) -> str | None:
    """Return 'zip', 'other' or None from leading bytes."""
    if head.startswith(_ZIP_MAGIC):
        return "zip"
    if head.startswith(_OTHER_ARCHIVE_MAGIC):
        return "other"
    if head[:3] == b"BZh" and head[3:4].isdigit() and head[4:10] == b"1AY&SY":
        return "other"
    return None


def is_unsupported_container(name: str, head: bytes) -> bool:
    import os

    return head.startswith(b"%PDF-") or os.path.splitext(name.lower())[1] in \
        UNSUPPORTED_CONTAINER_EXTENSIONS


def _looks_like_text(data: bytes, encoding: str) -> bool:
    """BOM-less UTF-16 guess must decode to mostly non-control text."""
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        # A surrogate pair may be cut at the sample end; retry shorter.
        try:
            text = data[:-2].decode(encoding)
        except UnicodeDecodeError:
            return False
    if not text:
        return False
    controls = sum(1 for ch in text
                   if (ord(ch) < 0x20 and ch not in "\t\n\r\f") or 0x7F <= ord(ch) <= 0x9F
                   or ord(ch) in (0xFFFE, 0xFFFF))
    return controls * 20 <= len(text)


def detect_encoding(sample: bytes):
    """Return (encoding or None, issue code or None)."""
    if sample.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return None, IssueCode.UNSUPPORTED_ENCODING  # UTF-32
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig", None
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16", None
    if b"\x00" in sample:
        head = sample[: SNIFF_BYTES - (SNIFF_BYTES % 2)]
        even, odd = head[0::2], head[1::2]
        if len(odd) >= 2:
            ze = even.count(0) / len(even)
            zo = odd.count(0) / len(odd)
            candidate = None
            if zo >= 0.3 and ze <= 0.05:
                candidate = "utf-16-le"
            elif ze >= 0.3 and zo <= 0.05:
                candidate = "utf-16-be"
            if candidate and _looks_like_text(head[: len(odd) * 2], candidate):
                return candidate, None
        return None, IssueCode.BINARY_CONTENT
    if sample:
        controls = sum(1 for b in sample if b in _CONTROL_BYTES)
        if controls * 10 > len(sample):
            return None, IssueCode.BINARY_CONTENT
    return "utf-8", None


class StopContent(Exception):
    """Content scanning for this target cannot continue."""


class TextScanner:
    """Feed bytes; reports matches via ``on_match(rule, line, confidence)``.

    ``on_issue(code)`` receives fixed issue codes; ``checkpoint()`` is called
    before each regex pass and may raise to abort (time limit / cancel).
    """

    def __init__(self, max_line_chars, on_match, on_issue, checkpoint):
        self._max_line = max_line_chars
        self._overlap = max(1, min(MAX_MATCH_CHARS, max_line_chars // 2))
        self._on_match = on_match
        self._on_issue = on_issue
        self._checkpoint = checkpoint
        self._pending = b""
        self._encoding = None
        self._decoder = None
        self._replace = False
        self._carry = ""
        self._line = 1
        self._issued = set()
        self.stopped = False

    # -- public ---------------------------------------------------------
    def feed(self, data: bytes) -> bool:
        """Feed bytes. Returns False once scanning of this content stopped."""
        if self.stopped:
            return False
        if self._decoder is None:
            self._pending += data
            if len(self._pending) < SNIFF_BYTES:
                return True
            data, self._pending = self._pending, b""
            if not self._start(data):
                return False
        self._process(self._decode(data, final=False))
        return not self.stopped

    def finish(self) -> None:
        if self.stopped:
            return
        if self._decoder is None:
            data, self._pending = self._pending, b""
            if not data:
                return
            if not self._start(data):
                return
            self._process(self._decode(data, final=False))
            if self.stopped:
                return
        self._process(self._decode(b"", final=True))
        if self.stopped:
            return
        if self._carry:
            self._scan_block(self._carry, cut=None)
            self._carry = ""

    # -- internals -------------------------------------------------------
    def _issue(self, code):
        if code not in self._issued:
            self._issued.add(code)
            self._on_issue(code)

    def _stop(self, code):
        self._issue(code)
        self.stopped = True

    def _start(self, sample: bytes) -> bool:
        encoding, code = detect_encoding(sample)
        if encoding is None:
            self._stop(code)
            return False
        self._encoding = encoding
        self._decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
        return True

    def _decode(self, data: bytes, final: bool) -> str:
        if not self._replace:
            state = self._decoder.getstate()
            try:
                text = self._decoder.decode(data, final)
            except UnicodeDecodeError:
                self._issue(IssueCode.UNSUPPORTED_ENCODING)
                self._replace = True
                decoder = codecs.getincrementaldecoder(self._encoding)(errors="replace")
                decoder.setstate(state)
                self._decoder = decoder
                text = self._decoder.decode(data, final)
        else:
            text = self._decoder.decode(data, final)
        if "\x00" in text:
            self._stop(IssueCode.BINARY_CONTENT)
            return ""
        return text

    def _process(self, text: str) -> None:
        if not text:
            return
        window = self._carry + text
        nl = window.rfind("\n")
        if nl >= 0:
            block = window[: nl + 1]
            if len(block) > self._max_line and self._longest_line(block) > self._max_line:
                self._issue(IssueCode.LINE_TOO_LONG)
            self._scan_block(block, cut=None)
            self._carry = window[nl + 1:]
        else:
            self._carry = window
        while len(self._carry) > self._max_line:
            self._issue(IssueCode.LINE_TOO_LONG)
            cut = len(self._carry) - self._overlap
            self._scan_block(self._carry, cut=cut)
            self._carry = self._carry[cut:]

    @staticmethod
    def _longest_line(block: str) -> int:
        longest = 0
        start = 0
        while True:
            idx = block.find("\n", start)
            if idx < 0:
                return max(longest, len(block) - start)
            longest = max(longest, idx - start)
            start = idx + 1

    def _scan_block(self, block: str, cut) -> None:
        """Scan ``block``; when ``cut`` is set only report matches starting
        before it (the rest is re-scanned in the next window)."""
        self._checkpoint()
        # Keep matching lazy: an adversarial line may contain far more matches
        # than the configured finding cap.  A compact newline index gives exact
        # line numbers without first materialising every Match object.
        newlines = array("I", (i for i, ch in enumerate(block) if ch == "\n"))
        for index, match in enumerate(iter_matches(block)):
            if index % 64 == 0:
                self._checkpoint()
            if cut is not None and match.start >= cut:
                continue
            line = self._line + bisect.bisect_left(newlines, match.start)
            self._on_match(match.rule, line, match.confidence)
        if cut is None:
            self._line += len(newlines)
