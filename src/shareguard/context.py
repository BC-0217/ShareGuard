"""Per-scan mutable state: budgets, deadlines, cancellation and collected
sanitized results. Only fixed codes, rule metadata and counters are stored.
"""

from __future__ import annotations

import time

from .model import Finding, Issue, IssueCode, Target
from .policy import Policy
from .textscan import TextScanner

READ_CHUNK = 64 * 1024


class StopScan(Exception):
    """Abort the whole scan. ``code`` is None for cancellation."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class StopTarget(Exception):
    """Abort processing of the current target with a fixed issue code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


class ScanContext:
    def __init__(self, policy: Policy, cancel_event=None, callback=None,
                 location_callback=None, clock=None):
        self.policy = policy
        self._cancel = cancel_event
        self._callback = callback
        self._location_callback = location_callback
        self._clock = clock or time.monotonic
        self.started = self._clock()
        self.deadline = self.started + policy.scan_timeout_seconds
        self.findings: list = []
        self.issues: list = []
        self._targets: dict = {}
        self._finding_index: dict = {}
        self._issue_keys: set = set()
        self._next_id = 1
        self.entries = 0
        self.directories = 0
        self.bytes = 0
        self.files_scanned = 0
        self.directories_scanned = 0
        self.archive_entries_scanned = 0
        self.cancelled = False
        self.root_count = -1
        self.input_scopes: dict = {}

    # -- time / cancellation ----------------------------------------------
    def file_deadline(self) -> float:
        return self._clock() + self.policy.file_timeout_seconds

    def check(self, file_deadline=None) -> None:
        if self._cancel is not None:
            try:
                is_set = bool(self._cancel.is_set())
            except Exception:
                is_set = True  # unusable cancel object: stop rather than run unbounded
            if is_set:
                self.cancelled = True
                raise StopScan(None)
        now = self._clock()
        if now > self.deadline:
            raise StopScan(IssueCode.SCAN_TIME_LIMIT)
        if file_deadline is not None and now > file_deadline:
            raise StopTarget(IssueCode.FILE_TIME_LIMIT)

    # -- targets ------------------------------------------------------------
    def new_target(self, kind, parent_id=None, root_index=None,
                   source_path=None, member_name=None) -> str:
        tid = f"T{self._next_id}"
        self._next_id += 1
        self._targets[tid] = Target(tid, kind, parent_id, root_index)
        if self._location_callback is not None and source_path is not None:
            try:
                self._location_callback(tid, source_path, member_name)
            except Exception:
                pass
        self._progress(tid)
        return tid

    def set_kind(self, tid: str, kind: str) -> None:
        t = self._targets[tid]
        self._targets[tid] = Target(t.target_id, kind, t.parent_id, t.root_index)

    @property
    def targets(self) -> list:
        return list(self._targets.values())

    def take_entry(self, tid) -> None:
        if self.entries >= self.policy.max_entries:
            raise StopScan(IssueCode.ENTRY_COUNT_LIMIT)
        self.entries += 1

    def remaining_entries(self) -> int:
        return self.policy.max_entries - self.entries

    def take_directory(self) -> None:
        if self.directories >= self.policy.max_entries:
            raise StopScan(IssueCode.DIRECTORY_COUNT_LIMIT)
        self.directories += 1

    def reserve_bytes(self, n: int) -> None:
        """Fail early if ``n`` more bytes cannot fit in the total budget."""
        if self.bytes + n > self.policy.max_total_bytes:
            raise StopScan(IssueCode.TOTAL_BYTES_LIMIT)

    def take_bytes(self, n: int) -> None:
        if self.bytes + n > self.policy.max_total_bytes:
            raise StopScan(IssueCode.TOTAL_BYTES_LIMIT)
        self.bytes += n

    def bytes_left(self) -> int:
        return self.policy.max_total_bytes - self.bytes

    # -- results --------------------------------------------------------------
    def add_issue(self, code: str, tid=None, final: bool = False) -> None:
        """Record an issue. The last slot is reserved for ISSUES_LIMIT; when
        the cap is reached the scan stops (unless ``final``)."""
        key = (code, tid)
        if key in self._issue_keys:
            return
        if len(self.issues) >= self.policy.max_issues - 1:
            if (IssueCode.ISSUES_LIMIT, None) not in self._issue_keys:
                self._issue_keys.add((IssueCode.ISSUES_LIMIT, None))
                self.issues.append(Issue(IssueCode.ISSUES_LIMIT, None))
            if final:
                return
            raise StopScan(IssueCode.ISSUES_LIMIT)
        self._issue_keys.add(key)
        self.issues.append(Issue(code, tid))

    def add_finding(self, tid: str, rule, line: int, confidence: str) -> None:
        key = (tid, rule.rule_id, line, confidence)
        idx = self._finding_index.get(key)
        if idx is not None:
            f = self.findings[idx]
            self.findings[idx] = Finding(f.target_id, f.rule_id, f.category,
                                         f.severity, f.confidence, f.line, f.count + 1)
            return
        if len(self.findings) >= self.policy.max_findings:
            raise StopScan(IssueCode.FINDINGS_LIMIT)
        self._finding_index[key] = len(self.findings)
        self.findings.append(Finding(tid, rule.rule_id, rule.category, rule.severity,
                                     confidence, line))

    def _progress(self, tid) -> None:
        if self._callback is None:
            return
        try:
            self._callback({
                "current_target": tid,
                "targets": len(self._targets),
                "entries": self.entries,
                "bytes": self.bytes,
                "findings": len(self.findings),
                "issues": len(self.issues),
            })
        except Exception:
            pass

    # -- content --------------------------------------------------------------
    def scan_stream(self, tid: str, first: bytes, read, max_bytes: int,
                    deadline: float, oversize_code: str) -> bool:
        """Scan ``first`` + chunks from ``read(n)`` as text.

        Counts actual bytes against per-target and total budgets. Returns True
        when the stream was read to its end, False if scanning stopped early
        because of content (binary/unsupported encoding); limit violations
        raise StopTarget/StopScan.
        """
        scanner = TextScanner(
            self.policy.max_line_chars,
            on_match=lambda rule, line, conf: self.add_finding(tid, rule, line, conf),
            on_issue=lambda code: self.add_issue(code, tid),
            checkpoint=lambda: self.check(deadline),
        )
        seen = 0
        chunk = first
        while chunk:
            seen += len(chunk)
            self.take_bytes(len(chunk))
            if seen > max_bytes:
                raise StopTarget(oversize_code)
            if not scanner.feed(chunk):
                return False
            self.check(deadline)
            # Never request more than one byte beyond either budget.
            want = min(READ_CHUNK, max_bytes - seen + 1, self.bytes_left() + 1)
            chunk = read(max(1, want))
        scanner.finish()
        return not scanner.stopped
