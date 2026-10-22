"""Shared test helpers.

All fixtures are synthetic and created at runtime inside the project's
ignored ``artifacts/test-work`` directory. Credential-like strings are built
from a fixed-seed generator so no realistic secret is ever committed; none of
them is functional.
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import string
import sys
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

WORK_ROOT = os.path.join(ROOT, "artifacts", "test-work")

# Canaries: must never appear in any sanitized output.
PATH_CANARY = "PathCanaryQ7Zp"
SECRET_CANARY = "SecretCanaryW4kd"
MEMBER_CANARY = "MemberCanaryH2vx"

_ALNUM = string.ascii_letters + string.digits


def synthetic(n: int, seed: int, alphabet: str = _ALNUM) -> str:
    """Deterministic random-looking text (synthetic, non-functional)."""
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


def token(kind: str, seed: int = 1) -> str:
    """Build a synthetic string in a public token *format* at runtime."""
    up = string.ascii_uppercase + string.digits
    if kind == "aws":
        return "AK" + "IA" + synthetic(16, seed, up)
    if kind == "github":
        return "gh" + "p_" + synthetic(36, seed)
    if kind == "github_pat":
        return "github" + "_pat_" + synthetic(22, seed) + "_" + synthetic(59, seed + 1)
    if kind == "gitlab":
        return "gl" + "pat-" + synthetic(20, seed)
    if kind == "slack":
        return "xo" + "xb-" + synthetic(12, seed, string.digits) + "-" + \
            synthetic(13, seed + 1, string.digits) + "-" + synthetic(24, seed + 2)
    if kind == "slack_webhook":
        return "https://hooks.slack.com/services/T" + synthetic(9, seed, up) + \
            "/B" + synthetic(9, seed + 1, up) + "/" + synthetic(24, seed + 2)
    if kind == "stripe":
        return "sk" + "_live_" + synthetic(32, seed)
    if kind == "google":
        return "AI" + "za" + synthetic(35, seed)
    if kind == "openai":
        return "sk-" + "proj-" + synthetic(20, seed) + "T3Blbk" + "FJ" + synthetic(20, seed + 1)
    if kind == "anthropic":
        return "sk-" + "ant-api03-" + synthetic(90, seed)
    if kind == "npm":
        return "np" + "m_" + synthetic(36, seed)
    if kind == "pypi":
        return "py" + "pi-AgEIcHlwaS5vcmc" + synthetic(60, seed)
    if kind == "sendgrid":
        return "S" + "G." + synthetic(22, seed) + "." + synthetic(43, seed + 1)
    raise ValueError(kind)


def pem_header(label: str = "RSA ") -> str:
    return "-" * 5 + "BEGIN " + label + "PRIVATE KEY" + "-" * 5


class WorkDirTestCase(unittest.TestCase):
    """Creates a unique project-local work directory per test."""

    def setUp(self):
        os.makedirs(WORK_ROOT, exist_ok=True)
        self.work = os.path.join(WORK_ROOT, uuid.uuid4().hex[:12])
        os.makedirs(self.work)
        self._cleanups_fs = []

    def tearDown(self):
        for fn in reversed(self._cleanups_fs):
            try:
                fn()
            except Exception:
                pass
        _rmtree_own(self.work)

    def path(self, *parts) -> str:
        return os.path.join(self.work, *parts)

    def write(self, rel: str, data, mode: str = "w") -> str:
        p = self.path(*rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(data, bytes):
            with open(p, "wb") as fh:
                fh.write(data)
        else:
            with open(p, mode, encoding="utf-8", newline="") as fh:
                fh.write(data)
        return p

    def tree_digest(self) -> dict:
        """Hashes + metadata of every fixture file (immutability checks)."""
        out = {}
        for dirpath, dirnames, filenames in os.walk(self.work, followlinks=False):
            for name in filenames:
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                    with open(p, "rb") as fh:
                        digest = hashlib.sha256(fh.read()).hexdigest()
                except OSError:
                    continue
                out[p] = (digest, st.st_size, st.st_mtime_ns)
        return out


def _rmtree_own(path: str) -> None:
    """Remove a test work dir without following links/junctions."""
    if not path.startswith(WORK_ROOT):
        return

    def onerror(func, p, exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except Exception:
            pass

    # Unlink junctions/symlinks first so rmtree never descends through them.
    for dirpath, dirnames, filenames in os.walk(path, topdown=True, followlinks=False):
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if os.path.islink(full) or _is_junction(full):
                try:
                    os.rmdir(full) if _is_junction(full) else os.unlink(full)
                except OSError:
                    pass
            else:
                keep.append(d)
        dirnames[:] = keep
    shutil.rmtree(path, onerror=onerror)


def _is_junction(p: str) -> bool:
    fn = getattr(os.path, "isjunction", None)
    if fn is not None:
        return fn(p)
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & 0x400) and not os.path.islink(p)


def make_junction(link: str, target: str) -> bool:
    """Create a Windows directory junction (no admin needed)."""
    if os.name != "nt":
        return False
    try:
        import _winapi

        _winapi.CreateJunction(target, link)
        return True
    except Exception:
        return False


def make_symlink(link: str, target: str, is_dir: bool = False) -> bool:
    try:
        os.symlink(target, link, target_is_directory=is_dir)
        return True
    except (OSError, NotImplementedError):
        return False


def codes(result) -> set:
    return {i.code for i in result.issues}


def rule_ids(result) -> list:
    return sorted(f.rule_id for f in result.findings)
