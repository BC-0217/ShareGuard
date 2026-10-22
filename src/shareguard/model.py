"""Sanitized scan result model.

Everything here is made of JSON primitives. No raw paths, archive member
names, content, secret hashes or exception text are ever stored.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import __version__
from .policy import CEILINGS, Policy, PolicyError
from .rules import RULES_BY_ID

SCHEMA = "shareguard.result/1"

OUTCOME_FINDINGS = "findings"
OUTCOME_NO_FINDINGS = "no_findings"
OUTCOMES = (OUTCOME_FINDINGS, OUTCOME_NO_FINDINGS)

COMPLETE = "complete"
INCOMPLETE = "incomplete"
CANCELLED = "cancelled"
ERROR = "error"
COMPLETENESS = (COMPLETE, INCOMPLETE, CANCELLED, ERROR)

KIND_FILE = "file"
KIND_DIRECTORY = "directory"
KIND_ARCHIVE = "archive"
KIND_ARCHIVE_ENTRY = "archive_entry"
TARGET_KINDS = (KIND_FILE, KIND_DIRECTORY, KIND_ARCHIVE, KIND_ARCHIVE_ENTRY)

SEVERITIES = ("high", "medium", "low")
CONFIDENCES = ("high", "medium", "low")


class IssueCode:
    """Fixed reason codes. Every issue makes the scan incomplete."""

    # Input selection / filesystem
    PATH_NOT_FOUND = "PATH_NOT_FOUND"
    PATH_UNSUPPORTED = "PATH_UNSUPPORTED"
    LINK_REJECTED = "LINK_REJECTED"
    SPECIAL_FILE = "SPECIAL_FILE"
    ACCESS_DENIED = "ACCESS_DENIED"
    OPEN_FAILED = "OPEN_FAILED"
    READ_ERROR = "READ_ERROR"
    DIRECTORY_READ_ERROR = "DIRECTORY_READ_ERROR"
    IDENTITY_UNVERIFIED = "IDENTITY_UNVERIFIED"
    MUTATION_DETECTED = "MUTATION_DETECTED"
    # Limits
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    TOTAL_BYTES_LIMIT = "TOTAL_BYTES_LIMIT"
    ENTRY_COUNT_LIMIT = "ENTRY_COUNT_LIMIT"
    DIRECTORY_COUNT_LIMIT = "DIRECTORY_COUNT_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    FILE_TIME_LIMIT = "FILE_TIME_LIMIT"
    SCAN_TIME_LIMIT = "SCAN_TIME_LIMIT"
    FINDINGS_LIMIT = "FINDINGS_LIMIT"
    ISSUES_LIMIT = "ISSUES_LIMIT"
    # Content
    BINARY_CONTENT = "BINARY_CONTENT"
    UNSUPPORTED_ENCODING = "UNSUPPORTED_ENCODING"
    LINE_TOO_LONG = "LINE_TOO_LONG"
    UNSUPPORTED_ARCHIVE = "UNSUPPORTED_ARCHIVE"
    # ZIP
    ZIP_CORRUPT = "ZIP_CORRUPT"
    ZIP_CENTRAL_DIRECTORY_LIMIT = "ZIP_CENTRAL_DIRECTORY_LIMIT"
    ZIP_UNSUPPORTED_FEATURE = "ZIP_UNSUPPORTED_FEATURE"
    ZIP_ENCRYPTED_ENTRY = "ZIP_ENCRYPTED_ENTRY"
    ZIP_UNSUPPORTED_COMPRESSION = "ZIP_UNSUPPORTED_COMPRESSION"
    ZIP_NESTED_ARCHIVE = "ZIP_NESTED_ARCHIVE"
    ZIP_CRC_MISMATCH = "ZIP_CRC_MISMATCH"
    ZIP_UNSAFE_NAME = "ZIP_UNSAFE_NAME"
    ZIP_DUPLICATE_NAME = "ZIP_DUPLICATE_NAME"
    ZIP_LINK_ENTRY = "ZIP_LINK_ENTRY"
    ZIP_SPECIAL_ENTRY = "ZIP_SPECIAL_ENTRY"
    ZIP_ENTRY_TOO_LARGE = "ZIP_ENTRY_TOO_LARGE"
    ZIP_COMMENT_NOT_SCANNED = "ZIP_COMMENT_NOT_SCANNED"
    # Scan level
    NO_INPUT = "NO_INPUT"
    POLICY_INVALID = "POLICY_INVALID"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    INTERNAL_ERROR = "INTERNAL_ERROR"


ISSUE_CODES = frozenset(
    value for name, value in vars(IssueCode).items() if name.isupper()
)

# Issue codes that turn the whole scan into an error (scan could not run).
FATAL_CODES = frozenset({
    IssueCode.NO_INPUT,
    IssueCode.POLICY_INVALID,
    IssueCode.UNSUPPORTED_PLATFORM,
})

_TARGET_ID_RE = re.compile(r"^T[1-9][0-9]{0,8}$")
_SCAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_MAX_INT = 2**53
_MAX_TARGETS = CEILINGS["max_entries"] * 2


@dataclass(frozen=True)
class Finding:
    target_id: str
    rule_id: str
    category: str
    severity: str
    confidence: str
    line: int
    count: int = 1

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "line": self.line,
            "count": self.count,
        }

    @classmethod
    def from_dict(cls, d) -> "Finding":
        _require_keys(d, ("target_id", "rule_id", "category", "severity",
                          "confidence", "line", "count"))
        rule = RULES_BY_ID.get(d["rule_id"]) if isinstance(d["rule_id"], str) else None
        if rule is None:
            raise ValueError("unknown rule id")
        if d["category"] != rule.category:
            raise ValueError("category mismatch")
        if d["severity"] != rule.severity or d["confidence"] not in rule.confidences:
            raise ValueError("invalid severity/confidence")
        return cls(
            target_id=_target_id(d["target_id"]),
            rule_id=rule.rule_id,
            category=rule.category,
            severity=d["severity"],
            confidence=d["confidence"],
            line=_int(d["line"], minimum=1),
            count=_int(d["count"], minimum=1),
        )


@dataclass(frozen=True)
class Issue:
    code: str
    target_id: str | None = None

    def to_dict(self) -> dict:
        return {"code": self.code, "target_id": self.target_id}

    @classmethod
    def from_dict(cls, d) -> "Issue":
        _require_keys(d, ("code", "target_id"))
        if not isinstance(d["code"], str) or d["code"] not in ISSUE_CODES:
            raise ValueError("unknown issue code")
        tid = d["target_id"]
        return cls(code=d["code"], target_id=None if tid is None else _target_id(tid))


@dataclass(frozen=True)
class Target:
    target_id: str
    kind: str
    parent_id: str | None = None
    root_index: int | None = None

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id,
            "kind": self.kind,
            "parent_id": self.parent_id,
            "root_index": self.root_index,
        }

    @classmethod
    def from_dict(cls, d) -> "Target":
        _require_keys(d, ("target_id", "kind", "parent_id", "root_index"))
        if d["kind"] not in TARGET_KINDS:
            raise ValueError("unknown target kind")
        parent = d["parent_id"]
        root_index = d["root_index"]
        return cls(
            target_id=_target_id(d["target_id"]),
            kind=d["kind"],
            parent_id=None if parent is None else _target_id(parent),
            root_index=None if root_index is None else _int(root_index, minimum=0),
        )


COUNT_KEYS = (
    "targets", "files_scanned", "directories_scanned", "archive_entries_scanned",
    "bytes_scanned", "findings", "issues", "high", "medium", "low",
)


@dataclass
class ScanResult:
    scan_id: str
    completeness: str
    findings: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    targets: list = field(default_factory=list)
    counts: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    duration_ms: int = 0

    @property
    def outcome(self) -> str:
        return OUTCOME_FINDINGS if self.findings else OUTCOME_NO_FINDINGS

    def to_dict(self) -> dict:
        try:
            raw = self._primitive()
            validated = type(self).from_dict(raw)
            return validated._primitive()
        except (AttributeError, KeyError, TypeError, ValueError):
            raise ValueError("invalid scan result") from None

    def _primitive(self) -> dict:
        return {
            "schema": SCHEMA,
            "tool_version": __version__,
            "scan_id": self.scan_id,
            "outcome": self.outcome,
            "completeness": self.completeness,
            "findings": [f.to_dict() for f in self.findings],
            "issues": [i.to_dict() for i in self.issues],
            "targets": [t.to_dict() for t in self.targets],
            "counts": {k: int(self.counts.get(k, 0)) for k in COUNT_KEYS},
            "policy": dict(self.policy),
            "duration_ms": int(self.duration_ms),
        }

    @classmethod
    def from_dict(cls, d) -> "ScanResult":
        _require_keys(d, ("schema", "tool_version", "scan_id", "outcome",
                          "completeness", "findings", "issues", "targets",
                          "counts", "policy", "duration_ms"))
        if d["schema"] != SCHEMA:
            raise ValueError("unsupported schema")
        if d["tool_version"] != __version__:
            raise ValueError("invalid tool version")
        if not isinstance(d["scan_id"], str) or _SCAN_ID_RE.fullmatch(d["scan_id"]) is None:
            raise ValueError("invalid scan id")
        if not isinstance(d["completeness"], str) or d["completeness"] not in COMPLETENESS:
            raise ValueError("invalid completeness")
        for key in ("findings", "issues", "targets"):
            if not isinstance(d[key], list):
                raise ValueError("invalid list")
        if len(d["findings"]) > CEILINGS["max_findings"]:
            raise ValueError("findings list too large")
        if len(d["issues"]) > CEILINGS["max_issues"]:
            raise ValueError("issues list too large")
        if len(d["targets"]) > _MAX_TARGETS:
            raise ValueError("targets list too large")
        counts = d["counts"]
        if not isinstance(counts, dict) or set(counts) != set(COUNT_KEYS):
            raise ValueError("invalid counts")
        if not isinstance(d["policy"], dict) or set(d["policy"]) != set(CEILINGS):
            raise ValueError("invalid policy")
        try:
            policy = Policy.from_dict(d["policy"]).to_dict()
        except (PolicyError, TypeError, ValueError):
            raise ValueError("invalid policy") from None
        result = cls(
            scan_id=d["scan_id"],
            completeness=d["completeness"],
            findings=[Finding.from_dict(x) for x in d["findings"]],
            issues=[Issue.from_dict(x) for x in d["issues"]],
            targets=[Target.from_dict(x) for x in d["targets"]],
            counts={k: _int(counts[k], minimum=0) for k in COUNT_KEYS},
            policy=policy,
            duration_ms=_int(d["duration_ms"], minimum=0),
        )
        if d["outcome"] != result.outcome:
            raise ValueError("outcome mismatch")
        result._validate_cross_fields()
        return result

    def _validate_cross_fields(self) -> None:
        if len(self.findings) > self.policy["max_findings"]:
            raise ValueError("findings exceed policy")
        if len(self.issues) > self.policy["max_issues"]:
            raise ValueError("issues exceed policy")
        if self.completeness == COMPLETE and self.issues:
            raise ValueError("complete result has issues")
        if self.completeness in (INCOMPLETE, ERROR) and not self.issues:
            raise ValueError("incomplete result has no issue")

        ids = [target.target_id for target in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate target id")
        if ids != [f"T{i}" for i in range(1, len(ids) + 1)]:
            raise ValueError("noncanonical target ids")
        id_set = set(ids)
        root_indexes = set()
        seen = set()
        for target in self.targets:
            if target.root_index is not None:
                if target.parent_id is not None or target.root_index in root_indexes:
                    raise ValueError("invalid root target")
                root_indexes.add(target.root_index)
            elif target.parent_id is None:
                raise ValueError("orphan target")
            if target.parent_id is not None and target.parent_id not in seen:
                raise ValueError("orphan target")
            seen.add(target.target_id)
        if sorted(root_indexes) != list(range(len(root_indexes))):
            raise ValueError("noncanonical root indexes")

        finding_keys = set()
        for finding in self.findings:
            if finding.target_id not in id_set:
                raise ValueError("orphan finding")
            key = (finding.target_id, finding.rule_id, finding.line, finding.confidence)
            if key in finding_keys:
                raise ValueError("duplicate finding")
            finding_keys.add(key)
        issue_keys = set()
        for issue in self.issues:
            if issue.target_id is not None and issue.target_id not in id_set:
                raise ValueError("orphan issue")
            key = (issue.code, issue.target_id)
            if key in issue_keys:
                raise ValueError("duplicate issue")
            issue_keys.add(key)

        severity = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            severity[finding.severity] += finding.count
        expected_counts = {
            "targets": len(self.targets),
            "findings": sum(f.count for f in self.findings),
            "issues": len(self.issues),
            **severity,
        }
        for key, value in expected_counts.items():
            if self.counts[key] != value:
                raise ValueError("count mismatch")
        if self.counts["bytes_scanned"] > self.policy["max_total_bytes"]:
            raise ValueError("byte count exceeds policy")
        kind_counts = {
            KIND_FILE: 0,
            KIND_ARCHIVE: 0,
            KIND_DIRECTORY: 0,
            KIND_ARCHIVE_ENTRY: 0,
        }
        for target in self.targets:
            kind_counts[target.kind] += 1
        if self.counts["files_scanned"] > kind_counts[KIND_FILE] + kind_counts[KIND_ARCHIVE]:
            raise ValueError("file count mismatch")
        if self.counts["directories_scanned"] > kind_counts[KIND_DIRECTORY]:
            raise ValueError("directory count mismatch")
        if self.counts["archive_entries_scanned"] > kind_counts[KIND_ARCHIVE_ENTRY]:
            raise ValueError("archive entry count mismatch")


def _require_keys(d, keys) -> None:
    if not isinstance(d, dict) or set(d) != set(keys):
        raise ValueError("invalid object fields")


def _int(value, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("invalid integer")
    if value < minimum or value > _MAX_INT:
        raise ValueError("integer out of range")
    return value


def _target_id(value) -> str:
    if not isinstance(value, str) or _TARGET_ID_RE.fullmatch(value) is None:
        raise ValueError("invalid target id")
    return value
