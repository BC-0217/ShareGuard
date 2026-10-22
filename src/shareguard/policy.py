"""Bounded scan policy.

Every limit has a hard safety ceiling. Callers may lower limits but can never
raise them above the ceiling.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields

MIB = 1024 * 1024

# Hard ceilings (also the defaults).
CEILINGS = {
    "max_file_bytes": 16 * MIB,
    "max_total_bytes": 256 * MIB,
    "max_entries": 10_000,
    "max_depth": 32,
    "file_timeout_seconds": 5.0,
    "scan_timeout_seconds": 120.0,
    "max_line_chars": 1 * MIB,
    "max_findings": 10_000,
    "max_issues": 10_000,
}

_FLOAT_FIELDS = frozenset({"file_timeout_seconds", "scan_timeout_seconds"})


class PolicyError(ValueError):
    """Invalid policy. The message never echoes the offending value."""


@dataclass(frozen=True)
class Policy:
    max_file_bytes: int = CEILINGS["max_file_bytes"]
    max_total_bytes: int = CEILINGS["max_total_bytes"]
    max_entries: int = CEILINGS["max_entries"]
    max_depth: int = CEILINGS["max_depth"]
    file_timeout_seconds: float = CEILINGS["file_timeout_seconds"]
    scan_timeout_seconds: float = CEILINGS["scan_timeout_seconds"]
    max_line_chars: int = CEILINGS["max_line_chars"]
    max_findings: int = CEILINGS["max_findings"]
    max_issues: int = CEILINGS["max_issues"]

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            _check_value(f.name, value)
            if f.name in _FLOAT_FIELDS:
                object.__setattr__(self, f.name, float(value))

    @classmethod
    def default(cls) -> "Policy":
        return cls()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data) -> "Policy":
        if not isinstance(data, dict):
            raise PolicyError("policy must be an object")
        known = {f.name for f in fields(cls)}
        for key in data:
            if key not in known:
                raise PolicyError("unknown policy field")
        return cls(**data)


def _check_value(name: str, value) -> None:
    ceiling = CEILINGS[name]
    if isinstance(value, bool):
        raise PolicyError(f"{name}: invalid type")
    if name in _FLOAT_FIELDS:
        if not isinstance(value, (int, float)):
            raise PolicyError(f"{name}: invalid type")
        if value != value:  # NaN
            raise PolicyError(f"{name}: invalid value")
    elif not isinstance(value, int):
        raise PolicyError(f"{name}: invalid type")
    if value <= 0:
        raise PolicyError(f"{name}: must be positive")
    if value > ceiling:
        raise PolicyError(f"{name}: exceeds hard ceiling")


def coerce_policy(policy) -> Policy:
    """Accept None, a Policy or a dict."""
    if policy is None:
        return Policy()
    if isinstance(policy, Policy):
        return policy
    return Policy.from_dict(policy)
