<#
.SYNOPSIS
  Build the ShareGuard Windows portable release with the locally installed
  Python and PyInstaller. Never downloads, installs, or deletes anything.

.DESCRIPTION
  Each run uses new UTC-stamped folders and fails if any already exists:
    build/pyi/<run>/{gui,cli,selftest}/
    dist/<run>/ShareGuard-<version>-windows-x64/
    dist/<run>/ShareGuard-<version>-windows-x64.zip
    dist/<run>/SHA256SUMS.txt
  The release contains the windowed GUI, console CLI, public documents, and
  complete installed license documents for CPython and bundled components,
  Tcl/Tk, the PyInstaller bootloader, and the Windows SDK/UCRT files collected
  by the build. tools/package_release.py checks the
  fresh COLLECT inventories, source provenance and explicit file allowlist,
  omits VCRUNTIME140*.dll from public staging as an installed system
  prerequisite, then writes a private hash inventory under the build run folder.
#>
[CmdletBinding()]
param(
    [string]$Python = "",
    [switch]$NoSelfTest,
    [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"
$Version = "0.1.0"
$ReleaseName = "ShareGuard-$Version-windows-x64"

function Fail([int]$Code, [string]$Message) {
    Write-Host "ERROR: $Message"
    exit $Code
}

function Full-Path([string]$Path) {
    return [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
}

$Root = Full-Path ((Resolve-Path -LiteralPath (Split-Path -Parent $PSScriptRoot)).ProviderPath)
$BuildBase = Full-Path (Join-Path $Root "build\pyi")
$DistBase = Full-Path (Join-Path $Root "dist")
$RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
$Build = Full-Path (Join-Path $BuildBase $RunId)
$DistRun = Full-Path (Join-Path $DistBase $RunId)
$Release = Full-Path (Join-Path $DistRun $ReleaseName)

# A target must be a strict child of its fixed base. Every existing component,
# including the repository and base, must be an ordinary directory, not a
# symlink/junction/reparse point. Outputs are new; no recursive cleanup exists.
function Assert-SafeNewChild([string]$Path, [string]$Base) {
    $full = Full-Path $Path
    $baseFull = Full-Path $Base
    if (-not $baseFull.StartsWith($Root + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail 3 "output base is outside the repository"
    }
    if (-not $full.StartsWith($baseFull + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail 3 "output is outside its approved build or dist base"
    }
    if (Test-Path -LiteralPath $full) {
        Fail 3 "new output path already exists for run $RunId"
    }
    $probe = Split-Path -Parent $full
    while ($probe -and $probe.Length -ge $Root.Length) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force
            if (-not $item.PSIsContainer) { Fail 3 "output ancestor is not a directory" }
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                Fail 3 "reparse point found on output path"
            }
            $resolved = Full-Path $item.FullName
            if (-not ($resolved -eq $Root -or $resolved.StartsWith($Root + "\", [System.StringComparison]::OrdinalIgnoreCase))) {
                Fail 3 "resolved output ancestor leaves the repository"
            }
        }
        if ($probe -eq $Root) { break }
        $probe = Split-Path -Parent $probe
    }
    if ($probe -ne $Root) { Fail 3 "output path is not rooted in the repository" }
}

function Assert-CreatedSafe([string]$Path, [string]$Base) {
    $full = Full-Path $Path
    $baseFull = Full-Path $Base
    if (-not $full.StartsWith($baseFull + "\", [System.StringComparison]::OrdinalIgnoreCase)) {
        Fail 3 "created output left its approved base"
    }
    $item = Get-Item -LiteralPath $full -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Fail 3 "created output is not an ordinary directory"
    }
    if ((Full-Path $item.FullName) -ne $full) { Fail 3 "created output identity mismatch" }
}

Assert-SafeNewChild $Build $BuildBase
Assert-SafeNewChild $DistRun $DistBase

if (-not $Python) {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if (-not $cmd) { Fail 2 "python was not found on PATH" }
    $Python = $cmd.Source
}
$Python = Full-Path $Python
& $Python -c "import struct, sys; raise SystemExit(0 if sys.version_info >= (3, 11) and struct.calcsize('P') == 8 else 1)"
if ($LASTEXITCODE -ne 0) { Fail 2 "64-bit Python 3.11 or newer is required for the x64 release" }
& $Python -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail 2 "PyInstaller is not installed for this Python. Install it yourself; this script never downloads."
}
$PyVersion = (& $Python -c "import platform; print(platform.python_version())").Trim()
$PyiVersion = (& $Python -c "import PyInstaller; print(PyInstaller.__version__)").Trim()
$PythonRoot = Full-Path ((& $Python -c "import sys; print(sys.base_prefix)").Trim())
$ProjectVersion = (& $Python -c "import sys; sys.path.insert(0, sys.argv[1]); import shareguard; print(shareguard.__version__)" (Join-Path $Root "src")).Trim()
if ($ProjectVersion -ne $Version) { Fail 1 "version mismatch between package and build script" }

$WindowsKitsRoot = Full-Path (Join-Path ${env:ProgramFiles(x86)} "Windows Kits")
$PyLicense = Join-Path $PythonRoot "LICENSE.txt"
$PyLicenseHtml = Join-Path $PythonRoot "Doc\html\license.html"
$TkLicense = (& $Python -c "import os, sys, glob; m = sorted(glob.glob(os.path.join(sys.base_prefix, 'tcl', 'tk8*', 'license.terms'))); print(m[0] if m else '')").Trim()
$PyiLicense = (& $Python -c "import importlib.metadata as m; d = m.distribution('pyinstaller'); f = [x for x in d.files if x.name == 'COPYING.txt']; print(d.locate_file(f[0]) if f else '')").Trim()
$SdkLicenseRoot = Join-Path $WindowsKitsRoot "10\Licenses"
$SdkLicenseDir = Get-ChildItem -LiteralPath $SdkLicenseRoot -Directory -ErrorAction SilentlyContinue |
    Where-Object { (Test-Path -LiteralPath (Join-Path $_.FullName "sdk_license.rtf")) -and (Test-Path -LiteralPath (Join-Path $_.FullName "sdk_third_party_notices.rtf")) } |
    Sort-Object Name -Descending | Select-Object -First 1
$SdkLicense = if ($SdkLicenseDir) { Join-Path $SdkLicenseDir.FullName "sdk_license.rtf" } else { "" }
$SdkThirdParty = if ($SdkLicenseDir) { Join-Path $SdkLicenseDir.FullName "sdk_third_party_notices.rtf" } else { "" }
foreach ($required in @($WindowsKitsRoot, $PyLicense, $PyLicenseHtml, $TkLicense, $PyiLicense, $SdkLicense, $SdkThirdParty, (Join-Path $Root "tools\package_release.py"))) {
    if (-not $required -or -not (Test-Path -LiteralPath $required)) { Fail 2 "required build or license input is missing" }
}

Write-Host "[build] run $RunId - Python $PyVersion, PyInstaller $PyiVersion, ShareGuard $Version"
Write-Host "[build] byte-identical rebuilds are not claimed."
Write-Host "[build] public ZIP omits VCRUNTIME140*.dll; Microsoft Visual C++ 2015-2022 x64 Runtime is an installed prerequisite."
if ($PreflightOnly) {
    Write-Host "[build] preflight passed; no output created"
    exit 0
}

New-Item -ItemType Directory -Path (Join-Path $Build "entry") | Out-Null
New-Item -ItemType Directory -Path $Release | Out-Null
Assert-CreatedSafe $Build $BuildBase
Assert-CreatedSafe $DistRun $DistBase
Assert-CreatedSafe $Release $DistBase

$CliEntry = Join-Path $Build "entry\shareguard_cli.py"
Set-Content -LiteralPath $CliEntry -Encoding ASCII -Value @'
import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from shareguard.cli import main
    sys.exit(main())
'@

$CommonExcludes = @("--exclude-module", "ssl", "--exclude-module", "_ssl")
function Invoke-PyInstaller([string]$Tag, [string]$Name, [string]$Script, [string]$Mode, [string[]]$Extra) {
    $pyiArgs = @(
        "-m", "PyInstaller", "--noconfirm", "--onedir", $Mode,
        "--name", $Name,
        "--paths", (Join-Path $Root "src"),
        "--workpath", (Join-Path $Build "$Tag\work"),
        "--specpath", (Join-Path $Build "$Tag\spec"),
        "--distpath", (Join-Path $Build "$Tag\dist"),
        "--log-level", "WARN"
    ) + $CommonExcludes + $Extra + @($Script)
    Write-Host "[build] $Name ($Mode)"
    & $Python @pyiArgs
    if ($LASTEXITCODE -ne 0) { Fail 1 "PyInstaller failed for $Name" }
}

# Dist/work/spec roots are separate because GUI ShareGuard and CLI shareguard
# collide on case-insensitive file systems.
Invoke-PyInstaller "gui" "ShareGuard" (Join-Path $Root "tools\launch_gui.pyw") "--windowed" @()
Invoke-PyInstaller "cli" "shareguard" $CliEntry "--console" @(
    "--exclude-module", "tkinter",
    "--exclude-module", "shareguard.gui",
    "--exclude-module", "shareguard.gui_session",
    "--exclude-module", "shareguard.gui_selftest"
)
if (-not $NoSelfTest) {
    Invoke-PyInstaller "selftest" "ShareGuardSelfTest" (Join-Path $Root "src\shareguard\gui_selftest.py") "--windowed" @()
    $SelfTestTarget = Join-Path $DistRun "ShareGuardSelfTest"
    if (Test-Path -LiteralPath $SelfTestTarget) { Fail 3 "self-test destination already exists" }
    Copy-Item -LiteralPath (Join-Path $Build "selftest\dist\ShareGuardSelfTest") -Destination $SelfTestTarget -Recurse
}

$PackagerArgs = @(
    "-I", (Join-Path $Root "tools\package_release.py"),
    "--gui-dist", (Join-Path $Build "gui\dist\ShareGuard"),
    "--cli-dist", (Join-Path $Build "cli\dist\shareguard"),
    "--gui-toc", (Join-Path $Build "gui\work\ShareGuard\COLLECT-00.toc"),
    "--cli-toc", (Join-Path $Build "cli\work\shareguard\COLLECT-00.toc"),
    "--python-root", $PythonRoot,
    "--build-root", $Build,
    "--windows-kits-root", $WindowsKitsRoot,
    "--release", $Release,
    "--zip-path", (Join-Path $DistRun "$ReleaseName.zip"),
    "--sums-path", (Join-Path $DistRun "SHA256SUMS.txt"),
    "--inventory", (Join-Path $Build "package-inventory.json")
)
foreach ($doc in @("README.md", "SECURITY.md", "LICENSE", "THIRD_PARTY_NOTICES.md")) {
    $PackagerArgs += @("--document", (Join-Path $Root $doc))
}
$PackagerArgs += @(
    "--license", "$PyLicense=CPython-LICENSE.txt",
    "--license", "$PyLicenseHtml=CPython-FULL-LICENSES.html",
    "--license", "$TkLicense=Tcl-Tk-license.terms",
    "--license", "$PyiLicense=PyInstaller-COPYING.txt",
    "--license", "$SdkLicense=Microsoft-Windows-SDK-License.rtf",
    "--license", "$SdkThirdParty=Microsoft-Windows-SDK-Third-Party-Notices.rtf"
)
& $Python @PackagerArgs
if ($LASTEXITCODE -ne 0) { Fail 1 "release packaging failed" }
Write-Host "[build] audited inventory: build\pyi\$RunId\package-inventory.json"
Write-Host "[build] done: dist\$RunId\$ReleaseName.zip"
exit 0
