"""Public product platform boundary.

ShareGuard 0.1.0 is a Windows 10/11 x64 public product.  The POSIX-capable
scanner backend exists only for development and synthetic regression tests.
There is deliberately no environment variable, command-line switch, or other
runtime bypass for this public boundary.
"""

from __future__ import annotations

import os
import secrets
import struct
import sys

PUBLIC_PLATFORM = "Windows 10/11 x64"
_MIN_WINDOWS_BUILD = 10240


def is_public_platform_supported() -> bool:
    """Return whether this runtime is a supported public-product target.

    Windows 10 and 11 both report NT major version 10.  Pointer width is used
    for the x64 package boundary; platform.machine() is intentionally not
    trusted because it may be blank or affected by process/environment state.
    """
    if os.name != "nt" or sys.platform != "win32":
        return False
    if struct.calcsize("P") != 8:
        return False
    try:
        version = sys.getwindowsversion()
        major = int(version.major)
        build = int(version.build)
    except (AttributeError, TypeError, ValueError, OSError):
        return False
    return major == 10 and build >= _MIN_WINDOWS_BUILD


def unsupported_platform_result(policy=None):
    """Return a fixed sanitized public API result without inspecting inputs."""
    from .model import ERROR, Issue, IssueCode, ScanResult
    from .policy import Policy, PolicyError, coerce_policy

    try:
        effective = coerce_policy(policy)
    except (PolicyError, TypeError, ValueError):
        effective = Policy()
    return ScanResult(
        scan_id=secrets.token_hex(8),
        completeness=ERROR,
        issues=[Issue(IssueCode.UNSUPPORTED_PLATFORM, None)],
        counts={"issues": 1},
        policy=effective.to_dict(),
        duration_ms=0,
    )
