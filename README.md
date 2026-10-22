# ShareGuard

공유하기 전에 파일·폴더·ZIP 안에 개인 키, 토큰, 비밀번호 같은 민감정보가 남아
있는지 **내 PC에서** 점검하는 도구입니다. 일반 사용자를 위한 한국어 기본 GUI와
개발자를 위한 CLI를 제공합니다. 버전 0.1.0. 공개 제품 지원 범위는 **Windows 10/11 x64**입니다(현재 검증 호스트: Windows 10 빌드 19045).

> ShareGuard는 악성코드 탐지, 키 유효성 확인, 안전 인증 도구가 **아닙니다**.
> "발견 없음"은 "안전함"이라는 뜻이 아닙니다.

[English below](#english)

## 사용법 (GUI)

1. `ShareGuard.exe`를 실행합니다. 소스로 실행할 때는 `tools/ShareGuard.vbs`를 더블클릭하거나 `pythonw tools/launch_gui.pyw`를 실행하세요(콘솔 창 없음).
2. **파일 추가** / **폴더 추가**로 점검 대상을 고릅니다. 선택한 경로는 이 단계에서만 확인용으로 표시됩니다.
3. **점검 시작**을 누릅니다. 언제든 **취소**할 수 있습니다.
4. 결과 표에는 불투명 대상 ID(예: `T3`), 분류, 규칙, 신뢰도, 심각도, 줄 번호, 횟수만 표시됩니다. 실제 값·내용·경로는 표시되지 않습니다.
5. **점검하지 못한 항목** 탭에서 불완전 사유(권한 없음, 크기 한도, 암호화된 ZIP 항목 등)를 확인하세요.
6. 수정할 위치가 필요하면 발견 항목 **하나**를 고르고 **선택 항목 위치 보기**를 누릅니다. 경고를 확인해야만 위치가 표시되며, 자동 복사·저장되지 않습니다.
7. 필요하면 **JSON 보고서 저장**으로 비식별 보고서를 새 파일로 저장합니다. 기존 파일은 덮어쓰지 않습니다. 점검 뒤 선택 루트가 없어지거나 이동·교체되어 신원을 다시 확인할 수 없으면 저장을 거부합니다.

메뉴에서 언어(한국어/English)와 밝게/어둡게 테마를 즉시 바꿀 수 있습니다.

## 사용법 (CLI)

```
shareguard scan PATH... [--json] [--report NEW_FILE.json]
                [--max-file-mib N] [--max-total-mib N] [--max-entries N]
                [--max-depth N] [--file-timeout SEC] [--scan-timeout SEC]
                [--max-line-chars N]
shareguard --version
```

Windows 소스에서는 `python -m shareguard scan PATH...` 로 실행합니다. 인자 없이 실행하면 GUI가 열립니다. 한도 옵션은 기본값보다 낮추는 것만 가능합니다. 비 Windows에서는 도움말·버전 확인만 지원하며 공개 GUI/CLI 점검은 고정된 unsupported-platform 오류로 시작 전에 거부합니다. POSIX 백엔드는 합성 코어 회귀 테스트를 위한 내부 개발용이며 Linux 제품 지원을 뜻하지 않습니다.

| 종료 코드 | 의미 |
|---|---|
| 0 | 점검 완료, 규칙에 해당하는 항목 없음 (안전 보증 아님) |
| 1 | 점검 완료, 민감정보 의심 항목 발견 |
| 2 | 불완전 – 일부를 점검하지 못함 (건너뜀·오류·한도) |
| 3 | 취소됨 |
| 4 | 오류 – 점검 불가 또는 잘못된 인자·보고서 저장 실패 |

GUI와 CLI는 같은 점검 엔진과 같은 판정 규칙을 사용합니다.

## 무엇을 찾나요

- PEM·OpenSSH·PGP·PuTTY·SSH2 **개인 키** 헤더 (인증서·공개 키는 제외)
- 형식이 뚜렷한 **토큰** (예: 클라우드·코드 저장소·메신저·결제·패키지 레지스트리·AI 서비스 키 형식)
- `password`, `api_key`, `client_secret`, `access_token`, `secret_key` 같은 이름에 **실제 값이 할당된 경우** (명백한 자리표시자와 환경 변수 참조는 제외)
- **URL 안의 사용자 이름·비밀번호**

텍스트(UTF-8, UTF-16 등)와 ZIP 안의 텍스트를 읽습니다. ZIP은 디스크에 풀지 않습니다.

## 지원하지 않는 것과 한계

- ZIP 항목 압축 방식은 저장(Stored)과 Deflate만 지원합니다. BZIP2·LZMA 등 그 밖의 방식, 중첩 압축, 암호화된 ZIP 항목, ZIP 외 압축 형식, 이미지·PDF·오피스 문서 내부 텍스트는 점검하지 않으며 "불완전"으로 표시합니다.
- 심볼릭 링크·정션·재분석 지점과 확인 가능한 UNC·매핑 드라이브·클라우드/원격 경로는 파일을 열기 전에 거부합니다. 지원 대상은 Windows의 로컬 파일입니다.
- 기본 한도: 파일 16MiB, 전체 읽기 256MiB, 항목 10,000개, 깊이 32, 파일당 약 5초, 전체 120초. 전체 읽기는 파일·ZIP 메타데이터/압축 데이터의 물리적 읽기와 ZIP 항목의 해제된 평문을 각각 계산하므로 ZIP 데이터가 두 종류의 예산에 모두 반영될 수 있습니다. 한도에 걸리면 "불완전"입니다.
- **오탐**: 예제·테스트용 값이 실제처럼 보이면 보고될 수 있습니다.
- **미탐**: 알 수 없는 형식, 인코딩·분할·난독화된 값, 규칙에 없는 비밀은 놓칠 수 있습니다. 엔트로피만으로 비밀을 찾는다고 약속하지 않습니다.
- 발견한 키가 유효한지, 이미 폐기됐는지 확인하지 않습니다. 의심 항목은 직접 확인하고, 노출된 비밀은 교체(rotate)하세요.

## 개인정보와 네트워크

- ShareGuard 애플리케이션에는 네트워크 연결, 텔레메트리, 업데이트 확인 기능이 없습니다. 알려진 원격/클라우드 경로도 스캔 전에 거부합니다. 다만 운영체제·파일시스템·보안 드라이버가 수행하는 모든 외부 통신까지 보증하는 것은 아닙니다.
- 결과·보고서에 원래 경로, ZIP 항목 이름, 내용, 비밀값 일부나 해시, 원시 오류 메시지를 넣지 않습니다.
- 기본적으로 로그나 위치 지도를 디스크에 저장하지 않습니다. 자세한 내용은 [SECURITY.md](SECURITY.md)를 보세요.

## 설치·빌드·테스트

- 공개 실행 환경: Windows 10/11 x64와 시스템에 설치된 **Microsoft Visual C++ 2015–2022 x64 Runtime**(또는 더 최신의 호환 런타임)이 필요합니다. 공개 ZIP에는 `VCRUNTIME140*.dll`을 포함하지 않습니다. 런타임이 없다는 Windows 오류가 나오면 Microsoft의 공식 런타임 설치 프로그램으로 사용자가 직접 설치해야 하며, ShareGuard는 이를 다운로드하거나 설치하지 않습니다. Windows 배포판은 Python 설치가 필요 없지만 운영체제 런타임까지 모두 포함한 완전 독립 패키지는 아닙니다. 소스 실행은 64비트 Python 3.11 이상이 필요합니다(표준 라이브러리와 tkinter만 사용, 외부 런타임 패키지 없음).
- 소스 체크아웃에서 설치나 다운로드 없이 실행하려면 저장소 루트의 PowerShell에서 `src`를 명시적으로 import 경로로 설정하세요:

  ```powershell
  $env:PYTHONPATH = (Resolve-Path -LiteralPath .\src).Path
  python -m shareguard --version
  python -m shareguard scan SYNTHETIC_PATH
  pythonw -m shareguard
  ```

  실제 개인 파일 대신 프로젝트 안의 합성 테스트 입력만 개발 검증에 사용하세요. `tools/ShareGuard.vbs`와 `tools/launch_gui.pyw`는 소스 GUI용 `src` 경로를 자체 설정합니다.
- 테스트(같은 명시적 `PYTHONPATH` 환경): `python -m unittest discover -s tests -t .`
- Windows 빌드(개발용, 설치된 PyInstaller 사용·다운로드 없음): `powershell -ExecutionPolicy Bypass -File tools/build_windows.ps1`
- 스크립트는 `build/pyi/<UTC 실행ID>`와 `dist/<UTC 실행ID>`에 새 산출물만 만들며 기존 경로는 삭제·덮어쓰지 않습니다. 현재 확인된 개발 도구는 Python 3.11.9 / PyInstaller 6.21.0이며 바이트 동일 재현은 주장하지 않습니다.
- 빌드 결과 점검: `python tools/packaged_smoke.py dist/<UTC 실행ID>/ShareGuard-0.1.0-windows-x64`
- 라이선스: MIT ([LICENSE](LICENSE)). 배포판에는 수집된 런타임에 해당하는 전체 설치 라이선스 문서가 함께 들어갑니다. 구성요소와 파일명: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

---

## English

ShareGuard checks selected files, folders and ZIP archives **on your own
computer** for leftover sensitive data - private keys, tokens, passwords -
before you share them. It has a Korean-default GUI (English available) and a
CLI. Version 0.1.0. The public product support target is **Windows 10/11 x64** (currently verified on Windows 10 build 19045).

> ShareGuard is **not** malware detection, key validation or a safety
> certification. "No findings" does not mean "safe".

### GUI

1. Run `ShareGuard.exe` (from source: double-click `tools/ShareGuard.vbs` or run `pythonw tools/launch_gui.pyw`; no console window).
2. Use **Add files** / **Add folder**. Selected paths are shown only at this step, for confirmation.
3. Press **Start scan**; **Cancel** works at any time.
4. The results table shows opaque target IDs (e.g. `T3`), category, rule, confidence, severity, line and count - never values, content or paths.
5. The **Not scanned** tab lists why the scan is incomplete (access denied, size limit, encrypted ZIP entry, ...).
6. To fix a finding, select **one** row and choose **Show selected location**. The location appears only after you confirm a warning and is never copied or saved automatically.
7. **Save JSON report** writes a sanitized report to a new file; existing files are never overwritten. Export is refused if a selected root disappeared, moved or was replaced after scanning and its identity cannot be reverified.

Language and light/dark theme can be switched from the menu at any time.

### CLI

```
shareguard scan PATH... [--json] [--report NEW_FILE.json] [limit options]
shareguard --version
```

On Windows, run from source with `python -m shareguard scan PATH...`.
Without arguments the GUI opens. Limit options can only lower the defaults.
On non-Windows systems only help and version queries are supported; public GUI
and CLI scans refuse before starting with a fixed unsupported-platform error.
The POSIX backend is internal development support for synthetic core regression
tests, not a supported Linux product.

| Exit code | Meaning |
|---|---|
| 0 | Complete, no rule matched (not a safety guarantee) |
| 1 | Complete, possible sensitive data found |
| 2 | Incomplete - something was skipped, failed or hit a limit |
| 3 | Cancelled |
| 4 | Error - scan could not run, invalid arguments or report not written |

The GUI and CLI use the same scan engine and the same outcome rules.

### What it detects

- PEM, OpenSSH, PGP, PuTTY and SSH2 **private key** headers (certificates and public keys are ignored)
- **Tokens** with recognizable formats (cloud, code hosting, chat, payment, package registry and AI service key formats)
- **Literal values assigned** to names such as `password`, `api_key`, `client_secret`, `access_token`, `secret_key` (obvious placeholders and environment references are excluded)
- **User names and passwords inside URLs**

Text files (UTF-8, UTF-16, ...) and text inside ZIP archives are read; ZIP
archives are never extracted to disk.

### Not supported / limitations

- ZIP entries using Stored or Deflate compression are supported. Other ZIP methods such as BZIP2 or LZMA, nested archives, encrypted ZIP entries, non-ZIP archive formats, and text inside images, PDFs or office documents are not scanned and are reported as incomplete.
- Symbolic links, junctions and reparse points, plus identifiable UNC, mapped-drive, cloud and remote paths, are rejected before file open. Supported inputs are local files on Windows.
- Default limits: 16 MiB per file, 256 MiB total reads, 10,000 entries, depth 32, about 5 s per file, 120 s per scan. Physical file/ZIP metadata/compressed reads and decoded ZIP-entry plaintext are each counted, so ZIP data can consume both budgets. Hitting a limit makes the result incomplete.
- **False positives**: sample or test values that look real may be reported.
- **False negatives**: unknown formats, encoded/split/obfuscated values and secrets outside the rules can be missed. There is no promise of entropy-only detection.
- Key validity or revocation is never checked. Review findings yourself and rotate any exposed secret.

### Privacy and network

- The ShareGuard application has no network, telemetry, update-check or upload feature, and known remote/cloud paths are refused before scanning. This does not guarantee that the operating system, filesystem, or security drivers make no external communication.
- Results and reports never contain original paths, ZIP member names, content, secret fragments or hashes, or raw error messages.
- No logs or location maps are written to disk by default. See [SECURITY.md](SECURITY.md).

### Requirements, build and tests

- Public runtime: Windows 10/11 x64 with the **Microsoft Visual C++ 2015–2022 x64 Runtime** (or a newer compatible runtime) already installed. Public ZIPs omit `VCRUNTIME140*.dll`. If Windows reports that the runtime DLL is missing, install the runtime manually using Microsoft's official installer; ShareGuard does not download or install it. The Windows build needs no Python installation, but it is not a wholly self-contained replacement for operating-system runtime prerequisites. Source use requires 64-bit Python 3.11+ with the standard library and tkinter; no third-party runtime packages.
- To run a source checkout without installing or downloading anything, explicitly set the `src` import path from PowerShell at the repository root:

  ```powershell
  $env:PYTHONPATH = (Resolve-Path -LiteralPath .\src).Path
  python -m shareguard --version
  python -m shareguard scan SYNTHETIC_PATH
  pythonw -m shareguard
  ```

  Use only project-local synthetic inputs for development checks, not personal files. `tools/ShareGuard.vbs` and `tools/launch_gui.pyw` set the source GUI's `src` path themselves.
- Tests in the same explicit `PYTHONPATH` environment: `python -m unittest discover -s tests -t .`
- Windows build (development only; uses an already installed PyInstaller, never downloads): `powershell -ExecutionPolicy Bypass -File tools/build_windows.ps1`
- The script creates only new `build/pyi/<UTC-run>` and `dist/<UTC-run>` trees; it never removes or overwrites an existing output. The currently checked development tools are Python 3.11.9 and PyInstaller 6.21.0. Byte-identical builds are not claimed.
- Check a build: `python tools/packaged_smoke.py dist/<UTC-run>/ShareGuard-0.1.0-windows-x64`
- License: MIT ([LICENSE](LICENSE)). The portable release includes the full installed license documents corresponding to its collected runtime components. Components and filenames: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
