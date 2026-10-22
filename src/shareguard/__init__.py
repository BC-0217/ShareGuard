"""ShareGuard: local pre-sharing sensitive-information scanner.

Not malware detection, key validity checking or a safety certification.
"""

__version__ = "0.1.0"

__all__ = ["__version__", "scan_paths"]


def scan_paths(*args, **kwargs):
    """Scan on the supported Windows 10/11 x64 public-product platform.

    ``shareguard.scanner.scan_paths`` is the explicit internal development
    backend used by synthetic cross-platform core regression tests.
    """
    from . import platform_support

    if not platform_support.is_public_platform_supported():
        policy = kwargs.get("policy", args[1] if len(args) > 1 else None)
        return platform_support.unsupported_platform_result(policy)
    from .scanner import scan_paths as _scan_paths

    return _scan_paths(*args, **kwargs)
