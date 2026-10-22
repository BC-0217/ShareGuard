"""Build-tool safety and package-inventory tests (no build is performed)."""

from __future__ import annotations

import ast
import importlib.util
import os
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_tool(name):
    path = os.path.join(ROOT, "tools", name)
    spec = importlib.util.spec_from_file_location("shareguard_test_" + name.replace(".", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


packager = load_tool("package_release.py")
smoke = load_tool("packaged_smoke.py")


class PackageInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.path.join(ROOT, "artifacts"))
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name
        self.python = os.path.join(self.base, "python")
        self.build = os.path.join(self.base, "build")
        self.kits = os.path.join(self.base, "kits")
        self.dist = os.path.join(self.base, "dist")
        for path in (self.python, self.build, self.kits, self.dist):
            os.makedirs(path)

    def put(self, root, relative, data=b"x"):
        path = os.path.join(root, *relative.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    def make_gui(self):
        sources = {
            "ShareGuard.exe": self.put(self.build, "gui/work/ShareGuard.exe"),
            "base_library.zip": self.put(self.build, "gui/work/base_library.zip"),
            "python311.dll": self.put(self.python, "python311.dll"),
            "VCRUNTIME140.dll": self.put(self.python, "VCRUNTIME140.dll"),
            "_tkinter.pyd": self.put(self.python, "DLLs/_tkinter.pyd"),
            "_tk_data/tk.tcl": self.put(self.python, "tcl/tk8.6/tk.tcl"),
            "_tcl_data/tclIndex": self.put(self.python, "tcl/tcl8.6/tclIndex"),
            "api-ms-win-core-file-l1-1-0.dll": self.put(self.kits, "10/Redist/ucrt/DLLs/x64/api-ms-win-core-file-l1-1-0.dll"),
        }
        rows = []
        for destination, source in sources.items():
            if destination == "ShareGuard.exe":
                kind = "EXECUTABLE"
                actual = destination
            elif destination == "base_library.zip" or destination.startswith(("_tk_data/", "_tcl_data/")):
                kind = "DATA"
                actual = "_internal/" + destination
            elif destination.endswith(".pyd"):
                kind = "EXTENSION"
                actual = "_internal/" + destination
            else:
                kind = "BINARY"
                actual = "_internal/" + destination
            self.put(self.dist, actual)
            rows.append((destination.replace("/", "\\"), source, kind))
        toc = os.path.join(self.base, "COLLECT-00.toc")
        with open(toc, "w", encoding="utf-8") as handle:
            handle.write(repr((rows,)))
        return toc

    def audit(self, toc):
        return packager.audit_tree(
            self.dist,
            toc,
            top="ShareGuard",
            executable="ShareGuard.exe",
            gui=True,
            python_root=self.python,
            build_root=self.build,
            windows_kits_root=self.kits,
        )

    def test_fresh_collect_inventory_and_provenance_are_required(self):
        rows, dropped, external = self.audit(self.make_gui())
        self.assertEqual(dropped, [])
        self.assertEqual(external, ["VCRUNTIME140.dll"])
        self.assertEqual(len(rows), 7)
        self.assertEqual(
            {row["provenance"] for row in rows},
            {"pyinstaller-output", "cpython-runtime", "cpython-tcltk", "windows-ucrt"},
        )
        self.assertTrue(all("source" in row for row in rows))
        self.assertNotIn("VCRUNTIME140.dll", {row["path"] for row in rows})

    def test_uncollected_file_is_rejected_even_when_name_looks_allowed(self):
        toc = self.make_gui()
        self.put(self.dist, "_internal/select.pyd")
        with self.assertRaises(packager.PackageError):
            self.audit(toc)

    def test_external_runtime_source_is_rejected(self):
        toc = self.make_gui()
        with open(toc, encoding="utf-8") as handle:
            rows = ast.literal_eval(handle.read())[0]
        outside = self.put(self.base, "outside/select.pyd")
        self.put(self.dist, "_internal/select.pyd")
        rows.append(("select.pyd", outside, "EXTENSION"))
        with open(toc, "w", encoding="utf-8") as handle:
            handle.write(repr((rows,)))
        with self.assertRaises(packager.PackageError):
            self.audit(toc)


class BuildGuardTests(unittest.TestCase):
    def test_build_uses_unique_outputs_without_recursive_delete(self):
        with open(os.path.join(ROOT, "tools", "build_windows.ps1"), encoding="utf-8") as handle:
            script = handle.read()
        self.assertNotIn("Remove-Item", script)
        self.assertIn("Assert-SafeNewChild $Build $BuildBase", script)
        self.assertIn("Assert-SafeNewChild $DistRun $DistBase", script)
        self.assertIn("reparse point found on output path", script)
        self.assertIn("package-inventory.json", script)
        self.assertIn("struct.calcsize('P') == 8", script)
        self.assertIn("CPython-FULL-LICENSES.html", script)
        self.assertIn("PyInstaller-COPYING.txt", script)
        self.assertIn("Microsoft-Windows-SDK-License.rtf", script)
        self.assertIn("Microsoft-Windows-SDK-Third-Party-Notices.rtf", script)

    def test_public_release_requires_external_vc_runtime(self):
        with tempfile.TemporaryDirectory(dir=os.path.join(ROOT, "artifacts")) as folder:
            clean = smoke.Checks([])
            smoke.external_prerequisite_checks(clean, folder)
            self.assertTrue(clean.results["vc_runtime_is_external_prerequisite"]["ok"])
            with open(os.path.join(folder, "VCRUNTIME140.DLL"), "wb") as handle:
                handle.write(b"synthetic")
            bundled = smoke.Checks([])
            smoke.external_prerequisite_checks(bundled, folder)
            self.assertFalse(bundled.results["vc_runtime_is_external_prerequisite"]["ok"])

    def test_missing_code_reader_fails_mandatory_privacy_gate(self):
        checks = smoke.Checks([])
        with tempfile.TemporaryDirectory(dir=os.path.join(ROOT, "artifacts")) as folder, \
                mock.patch.object(smoke, "code_filename_scan", return_value=None):
            smoke.privacy_scan(checks, folder)
        self.assertFalse(checks.results["code_filenames_gui"]["ok"])
        self.assertFalse(checks.results["code_filenames_cli"]["ok"])


if __name__ == "__main__":
    unittest.main()
