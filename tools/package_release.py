"""Audit PyInstaller output provenance and assemble a ShareGuard release.

This is a build-time stdlib tool.  It refuses files that are absent from the
fresh PyInstaller COLLECT inventory, outside approved source roots, or outside
the explicit runtime/Tcl-Tk allowlist.  The emitted private build inventory
contains only release-relative names, sizes, hashes and provenance classes --
never developer paths. Microsoft VC runtime DLLs are deliberately omitted and
recorded only by fixed filename as an external installed prerequisite.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import sys
import zipfile


class PackageError(RuntimeError):
    pass


_RUNTIME_EXACT = frozenset(
    {
        "ucrtbase.dll",
        "libcrypto-3.dll",
        "libffi-8.dll",
        "_bz2.pyd",
        "_ctypes.pyd",
        "_decimal.pyd",
        "_hashlib.pyd",
        "_lzma.pyd",
        "_multiprocessing.pyd",
        "_queue.pyd",
        "_socket.pyd",
        "pyexpat.pyd",
        "select.pyd",
        "unicodedata.pyd",
        "base_library.zip",
    }
)
_RUNTIME_PATTERNS = (
    re.compile(r"python3[0-9]{2}\.dll\Z", re.IGNORECASE),
    re.compile(r"api-ms-win-(?:core|crt)-[a-z0-9-]+\.dll\Z", re.IGNORECASE),
)
_TCL_FILE = re.compile(
    r"(?:_tcl_data|_tk_data|tcl8)/[A-Za-z0-9_./+-]+(?:\.(?:tcl|msg|enc|tm|terms|gif|eps)|/README)?\Z"
)
_TCL_TZDATA = re.compile(r"_tcl_data/tzdata/[A-Za-z0-9_+./-]+\Z")
_TCL_INDEX = frozenset({"_tcl_data/tclIndex", "_tk_data/tclIndex"})
_TCL_BINARY = frozenset({"_tkinter.pyd", "tcl86t.dll", "tk86t.dll"})
_DROP_PATTERNS = (
    re.compile(r"tcl8/8\.6/http-[0-9.]+\.tm\Z"),
    re.compile(r"tcl8/8\.5/tcltest-[0-9.]+\.tm\Z"),
)
_ALLOWED_TYPES = frozenset({"EXECUTABLE", "BINARY", "EXTENSION", "DATA"})
_EXTERNAL_VC_RUNTIME = frozenset({"vcruntime140.dll", "vcruntime140_1.dll"})


def _norm_rel(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise PackageError("invalid inventory name")
    value = value.replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise PackageError("absolute inventory name")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise PackageError("unsafe inventory name")
    return "/".join(parts)


def _under(path: str, root: str) -> bool:
    try:
        path = os.path.normcase(os.path.realpath(os.path.abspath(path)))
        root = os.path.normcase(os.path.realpath(os.path.abspath(root)))
        return os.path.commonpath((path, root)) == root
    except (OSError, ValueError):
        return False


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_collect_toc(path: str) -> dict[str, tuple[str, str]]:
    """Read a PyInstaller COLLECT literal as destination -> (source, type)."""
    try:
        with open(path, encoding="utf-8") as handle:
            parsed = ast.literal_eval(handle.read())
    except (OSError, SyntaxError, ValueError) as exc:
        raise PackageError("invalid COLLECT inventory") from exc
    rows = parsed[0] if isinstance(parsed, tuple) and len(parsed) == 1 else parsed
    if not isinstance(rows, list):
        raise PackageError("invalid COLLECT inventory")
    result = {}
    for row in rows:
        if not (isinstance(row, tuple) and len(row) == 3 and all(isinstance(x, str) for x in row)):
            raise PackageError("invalid COLLECT row")
        destination, source, kind = _norm_rel(row[0]), os.path.abspath(row[1]), row[2]
        if kind not in _ALLOWED_TYPES or destination in result or not os.path.isfile(source):
            raise PackageError("invalid COLLECT row")
        if os.path.islink(source):
            raise PackageError("link in COLLECT source")
        result[destination] = (source, kind)
    return result


def _tcl_source_matches(destination: str, source: str, python_root: str) -> bool:
    table = (
        ("_tcl_data/", os.path.join(python_root, "tcl", "tcl8.6")),
        ("_tk_data/", os.path.join(python_root, "tcl", "tk8.6")),
        ("tcl8/", os.path.join(python_root, "tcl", "tcl8")),
    )
    for prefix, source_root in table:
        if destination.startswith(prefix):
            suffix = destination[len(prefix) :]
            expected = os.path.join(source_root, *suffix.split("/"))
            return _under(source, source_root) and os.path.normcase(os.path.realpath(source)) == os.path.normcase(os.path.realpath(expected))
    return False


def classify(destination: str, source: str, kind: str, *, gui: bool, executable: str,
             python_root: str, build_root: str, windows_kits_root: str) -> str:
    """Return a fixed provenance class, or fail closed."""
    name = destination.rsplit("/", 1)[-1]
    if destination == executable and kind == "EXECUTABLE" and _under(source, build_root):
        return "pyinstaller-output"
    if destination == "base_library.zip" and kind == "DATA" and _under(source, build_root):
        return "pyinstaller-output"
    if destination in _TCL_BINARY:
        if not gui or kind not in {"BINARY", "EXTENSION"} or not _under(source, python_root):
            raise PackageError("unapproved Tcl/Tk binary")
        if os.path.normcase(os.path.basename(source)) != os.path.normcase(destination):
            raise PackageError("Tcl/Tk source mismatch")
        return "cpython-tcltk"
    if destination in _TCL_INDEX or _TCL_FILE.fullmatch(destination) or _TCL_TZDATA.fullmatch(destination):
        if not gui or kind != "DATA" or not _tcl_source_matches(destination, source, python_root):
            raise PackageError("unapproved Tcl/Tk data")
        return "cpython-tcltk"
    if destination in _RUNTIME_EXACT or any(pattern.fullmatch(destination) for pattern in _RUNTIME_PATTERNS):
        if kind not in {"BINARY", "EXTENSION"}:
            raise PackageError("runtime type mismatch")
        if os.path.normcase(os.path.basename(source)) != os.path.normcase(name):
            raise PackageError("runtime source mismatch")
        if destination.lower().startswith("api-ms-win-") or destination.lower() == "ucrtbase.dll":
            if not _under(source, windows_kits_root):
                raise PackageError("unapproved Windows runtime source")
            return "windows-ucrt"
        if not _under(source, python_root):
            raise PackageError("unapproved Python runtime source")
        return "cpython-runtime"
    raise PackageError("unaccounted collected file")


def _actual_files(folder: str, executable: str) -> dict[str, str]:
    result = {}
    for current, dirs, names in os.walk(folder):
        dirs.sort()
        for name in sorted(names):
            full = os.path.join(current, name)
            if os.path.islink(full):
                raise PackageError("link in build output")
            rel = _norm_rel(os.path.relpath(full, folder))
            inventory_name = rel[len("_internal/") :] if rel.startswith("_internal/") else rel
            if not rel.startswith("_internal/") and rel != executable:
                raise PackageError("unexpected top-level build output")
            if inventory_name in result:
                raise PackageError("duplicate build output")
            result[inventory_name] = full
    return result


def audit_tree(folder: str, toc_path: str, *, top: str, executable: str, gui: bool,
               python_root: str, build_root: str, windows_kits_root: str):
    """Return (approved rows, known dropped rows) for one fresh PyInstaller tree."""
    toc = load_collect_toc(toc_path)
    actual = _actual_files(folder, executable)
    if set(actual) != set(toc):
        raise PackageError("build output does not match COLLECT inventory")
    approved, dropped, external = [], [], []
    for destination in sorted(toc):
        source, kind = toc[destination]
        if destination.casefold() in _EXTERNAL_VC_RUNTIME:
            if kind != "BINARY" or os.path.normcase(os.path.basename(source)) != os.path.normcase(destination):
                raise PackageError("invalid external VC runtime row")
            external.append(destination)
            continue
        if any(pattern.fullmatch(destination) for pattern in _DROP_PATTERNS):
            dropped.append(destination)
            continue
        provenance = classify(
            destination,
            source,
            kind,
            gui=gui,
            executable=executable,
            python_root=python_root,
            build_root=build_root,
            windows_kits_root=windows_kits_root,
        )
        actual_rel = executable if destination == executable else "_internal/" + destination
        approved.append(
            {
                "top": top,
                "path": actual_rel,
                "source": actual[destination],
                "type": kind,
                "provenance": provenance,
            }
        )
    return approved, dropped, external


def _copy_new(source: str, destination: str) -> None:
    os.makedirs(os.path.dirname(destination), exist_ok=True)
    if os.path.exists(destination):
        raise PackageError("release destination already exists")
    shutil.copyfile(source, destination)


def _inventory_record(release_relative: str, path: str, provenance: str, kind: str) -> dict:
    return {
        "path": _norm_rel(release_relative),
        "size": os.path.getsize(path),
        "sha256": _sha256(path),
        "provenance": provenance,
        "type": kind,
    }


def assemble(args) -> dict:
    release = os.path.abspath(args.release)
    if os.path.exists(args.zip_path) or os.path.exists(args.sums_path) or os.path.exists(args.inventory):
        raise PackageError("packaging output already exists")
    if not os.path.isdir(release) or os.listdir(release):
        raise PackageError("release folder must be a new empty directory")

    rows = []
    dropped = []
    external = []
    specs = (
        (args.gui_dist, args.gui_toc, "ShareGuard", "ShareGuard.exe", True),
        (args.cli_dist, args.cli_toc, "cli", "shareguard.exe", False),
    )
    for folder, toc, top, executable, is_gui in specs:
        approved, omitted, required_external = audit_tree(
            folder,
            toc,
            top=top,
            executable=executable,
            gui=is_gui,
            python_root=args.python_root,
            build_root=args.build_root,
            windows_kits_root=args.windows_kits_root,
        )
        dropped.extend(top + "/" + item for item in omitted)
        external.extend(top + "/" + item for item in required_external)
        for row in approved:
            destination = os.path.join(release, row["top"], *row["path"].split("/"))
            _copy_new(row["source"], destination)
            rows.append(_inventory_record(row["top"] + "/" + row["path"], destination, row["provenance"], row["type"]))

    for source in args.document:
        target = os.path.basename(source)
        destination = os.path.join(release, target)
        _copy_new(source, destination)
        rows.append(_inventory_record(target, destination, "project-document", "DATA"))
    for item in args.license:
        try:
            source, target = item.split("=", 1)
        except ValueError as exc:
            raise PackageError("invalid license mapping") from exc
        target = _norm_rel(target)
        destination = os.path.join(release, "licenses", *target.split("/"))
        _copy_new(source, destination)
        rows.append(_inventory_record("licenses/" + target, destination, "license-text", "DATA"))

    rows.sort(key=lambda row: row["path"])
    payload = {
        "schema": "shareguard.package-inventory/1",
        "files": rows,
        "dropped_known_unused": sorted(dropped),
        "external_prerequisites": [
            {
                "id": "microsoft-visual-cpp-2015-2022-x64-runtime",
                "required": True,
                "omitted_files": sorted(external),
            }
        ],
    }
    with open(args.inventory, "x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=1, sort_keys=True)
        handle.write("\n")

    archive_name = os.path.basename(release)
    with zipfile.ZipFile(args.zip_path, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for row in rows:
            full = os.path.join(release, *row["path"].split("/"))
            info = zipfile.ZipInfo(archive_name + "/" + row["path"], date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(full, "rb") as handle:
                archive.writestr(info, handle.read())

    sums = []
    for path in (args.zip_path, os.path.join(release, "ShareGuard", "ShareGuard.exe"), os.path.join(release, "cli", "shareguard.exe")):
        sums.append((_sha256(path), os.path.relpath(path, os.path.dirname(args.zip_path)).replace(os.sep, "/")))
    with open(args.sums_path, "x", encoding="ascii", newline="\n") as handle:
        handle.write("\n".join("%s  %s" % pair for pair in sums) + "\n")
    return {"files": len(rows), "dropped": len(dropped), "external": len(external), "sums": sums}


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    p.add_argument("--gui-dist", required=True)
    p.add_argument("--cli-dist", required=True)
    p.add_argument("--gui-toc", required=True)
    p.add_argument("--cli-toc", required=True)
    p.add_argument("--python-root", required=True)
    p.add_argument("--build-root", required=True)
    p.add_argument("--windows-kits-root", required=True)
    p.add_argument("--release", required=True)
    p.add_argument("--zip-path", required=True)
    p.add_argument("--sums-path", required=True)
    p.add_argument("--inventory", required=True)
    p.add_argument("--document", action="append", default=[])
    p.add_argument("--license", action="append", default=[])
    return p


def main(argv=None) -> int:
    try:
        result = assemble(parser().parse_args(argv))
    except (OSError, PackageError, ValueError, zipfile.BadZipFile):
        print("release packaging failed", file=sys.stderr)
        return 1
    print("[package] %d allowlisted files; %d known unused Tcl files and %d external VC runtime files omitted" % (result["files"], result["dropped"], result["external"]))
    for digest, name in result["sums"]:
        print("%s  %s" % (digest, name))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
