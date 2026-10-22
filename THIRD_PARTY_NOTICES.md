# Third-party notices

## Source distribution

ShareGuard's source code uses only the Python standard library (Python 3.11
or newer, including `tkinter`). It has no runtime dependencies from PyPI and
contains no copied third-party source code.

## Windows portable binaries

The portable applications target Windows 10/11 x64 only. They are produced
with PyInstaller and contain an interpreter, selected standard-library extensions, GUI support files, and
Windows runtime files. Licenses for those components apply only to those
components.

| Component or prerequisite | Purpose | Release treatment |
|---|---|---|
| CPython runtime and selected standard-library files | Bundled interpreter and standard library | `licenses/CPython-LICENSE.txt` |
| Software incorporated in the installed CPython distribution, including the OpenSSL, libffi, zlib, bzip2, xz/liblzma and Expat components that may be collected by this build | Cryptography/hash, FFI, compression and XML support used by selected standard-library modules | `licenses/CPython-FULL-LICENSES.html` (the complete installed CPython license page, including incorporated-software notices and license texts) |
| Tcl/Tk | GUI toolkit and data for the GUI executable | `licenses/Tcl-Tk-license.terms` |
| PyInstaller bootloader | Starts each bundled application | `licenses/PyInstaller-COPYING.txt` (GPL 2.0 text and the PyInstaller bootloader exception) |
| Microsoft Windows SDK/UCRT API-set runtime files collected from the installed Windows Kits tree | Windows runtime compatibility | `licenses/Microsoft-Windows-SDK-License.rtf` and `licenses/Microsoft-Windows-SDK-Third-Party-Notices.rtf` |
| Microsoft Visual C++ 2015–2022 x64 Runtime (`VCRUNTIME140*.dll`) | External CPython runtime prerequisite | **Not included in the public release.** It must already be installed on Windows 10/11 x64 (or provided by a newer compatible Microsoft runtime). ShareGuard provides no downloader or installer. |

For every included component above, the release includes the corresponding
full installed text rather than relying on this notice as a substitute. The audited package inventory records every
released file's relative name, SHA-256 digest, type, and provenance class. It
is retained as private build evidence because PyInstaller's raw collection
metadata contains build-machine paths; it is not placed in the release ZIP.

The exact collected set is build-specific. `tools/package_release.py` rejects
a file unless it is present in that build's fresh PyInstaller `COLLECT-00.toc`,
has an explicitly allowed relative name and type, and comes from the expected
CPython, Tcl/Tk, Windows Kits, or fresh build root. Files not accounted for by
that inventory are refused. Collected `VCRUNTIME140*.dll` files are filtered
case-insensitively from public staging, and the sanitized private inventory
records their fixed release-relative names under the external Microsoft Visual
C++ runtime prerequisite without recording source paths.

Including a module in the portable runtime does not imply that ShareGuard uses
it at runtime. ShareGuard has no application networking, telemetry, update,
credential-validation, malware-detection, or online-check feature. This does
not make a claim about external communication performed by Windows,
filesystem, cloud, or security drivers.

The release ZIP also contains `README.md`, `SECURITY.md`, ShareGuard's `LICENSE`,
and this notice. ShareGuard's MIT license does not replace any third-party
license above.
