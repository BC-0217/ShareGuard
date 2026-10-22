# Security policy / 보안 정책

## 범위와 한계 (한국어)

ShareGuard는 파일을 공유하기 **전에** 선택한 파일·폴더·ZIP 안의 민감정보 의심
항목(개인 키, 알려진 형식의 토큰, 비밀번호·키 할당, URL 내 자격증명)을 찾는
로컬 점검 도구입니다. v0.1.0 공개 제품은 Windows 10/11 x64의 로컬 파일만 지원합니다. POSIX 백엔드는 합성 코어 회귀 테스트용 내부 개발 구현이며 Linux 제품 지원이 아닙니다.

- 악성코드 탐지기가 **아닙니다**.
- 발견한 키·토큰이 실제로 유효한지 확인하지 **않습니다** (어떤 서비스에도 접속하지 않습니다).
- 보안 인증이나 "안전함" 판정을 **제공하지 않습니다**. "발견 없음"은 규칙에 해당하는 항목을 찾지 못했다는 뜻일 뿐입니다.
- 오탐(false positive)과 미탐(false negative)이 모두 가능합니다. 특히 알 수 없는 형식의 비밀값, 인코딩·난독화된 값, 이미지·문서 내부 텍스트, 지원하지 않는 압축 형식은 놓칠 수 있습니다.

## 설계상 보호 장치

- **애플리케이션 네트워크 기능 없음**: ShareGuard 자체에는 네트워크 연결·텔레메트리·업데이트 확인·자동 업로드 기능이 없습니다. 확인 가능한 UNC·매핑 드라이브·클라우드/원격 경로는 입력을 열기 전에 거부합니다. 운영체제·파일시스템·보안 드라이버가 수행하는 모든 외부 통신까지 보증하지는 않습니다.
- **읽기 전용**: 입력 파일을 수정·삭제하지 않으며 ZIP을 디스크에 풀지 않습니다(임시 평문 파일 없음).
- **범위 제한**: 심볼릭 링크·정션·재분석 지점을 따라가지 않고, 선택한 범위 밖으로 나가지 않습니다. 확인할 수 없는 경우는 건너뛰고 "불완전"으로 표시합니다.
- **자원 제한**: 파일 크기, 전체 읽기량, 항목 수, 깊이, 시간에 한도가 있습니다. 전체 읽기량은 물리적 파일/ZIP 읽기와 해제된 ZIP 항목 평문을 각각 계산합니다. 한도에 걸리면 결과는 "불완전"입니다.
- **결과 비식별화**: 기본 결과(GUI·CLI·JSON 보고서)에는 원래 경로, ZIP 항목 이름, 파일 내용, 비밀값 일부·해시, 원시 예외 메시지가 포함되지 않습니다. 불투명 대상 ID·규칙 ID·분류·신뢰도·줄 번호·건수만 포함합니다.
- **위치 보기**: GUI에서 사용자가 발견 항목 하나를 선택하고 경고를 확인한 경우에만 그 위치를 화면에 표시합니다. 자동 복사·저장하지 않으며, 위치 정보는 GUI 프로세스 메모리에만 있고 새 선택·새 점검·종료 시 지워집니다.
- **보고서 저장**: 사용자가 명시적으로 요청할 때만 저장하며, 기존 파일을 덮어쓰지 않고 점검 대상 안에는 쓰지 않습니다. 스캔 시점의 숫자 파일 신원은 별도 비공개 프로세스 채널로만 전달되며, 저장 직전에 모든 선택 루트를 다시 열어 신원을 비교합니다. 누락·이동·교체·검증 불가는 저장을 거부합니다.
- **외부 시스템 런타임 전제조건**: 공개 ZIP은 권리가 확인되지 않은 `VCRUNTIME140*.dll`을 포함하지 않습니다. Windows 10/11 x64에 Microsoft Visual C++ 2015–2022 x64 Runtime(또는 더 최신의 호환 런타임)이 설치되어 있어야 합니다. ShareGuard는 이를 다운로드·설치하거나 이 전제조건을 우회하지 않습니다.
- **로그 없음**: 기본적으로 점검 로그나 위치 지도를 디스크에 남기지 않습니다.

## 취약점 신고

보안 문제를 발견하면 공개 이슈에 비밀값이나 실제 경로를 올리지 말고, 저장소의
비공개 보안 신고(GitHub Security Advisories)를 이용해 주세요. 재현에는 합성
(가짜) 데이터만 사용해 주세요.

---

## Scope and limitations (English)

ShareGuard is a local tool that looks for likely sensitive data (private
keys, recognizable token formats, password/key assignments, credentials in
URLs) in selected files, folders and ZIP archives **before** you share them.
The v0.1.0 public product supports local files on Windows 10/11 x64 only. The
POSIX backend is internal development support for synthetic core regression,
not a supported Linux product.

- It is **not** malware detection.
- It does **not** check whether a key or token is valid; it never contacts any service.
- It does **not** certify anything as safe. "No findings" only means no rule matched.
- False positives and false negatives are both possible. Unknown secret formats, encoded or obfuscated values, text inside images or office documents, and unsupported archive formats can be missed.

## Built-in safeguards

- **No application network feature**: ShareGuard itself has no networking, telemetry, update-check or upload feature. Identifiable UNC, mapped-drive, cloud and remote inputs are refused before file open. This is not a guarantee that the operating system, filesystem, or security drivers perform no external communication.
- **Read-only**: inputs are never modified or deleted; ZIP archives are read in memory and never extracted (no temporary plaintext files).
- **Scoped**: symbolic links, junctions and reparse points are not followed and the scan never leaves the selected scope. Anything that cannot be verified is skipped and reported as incomplete.
- **Bounded**: file size, total bytes read, entry count, depth and time are limited. Physical file/ZIP reads and decoded ZIP-entry plaintext are counted independently. Hitting a limit makes the result incomplete.
- **Sanitized results**: default output (GUI, CLI, JSON report) contains no original paths, ZIP member names, file content, secret fragments or hashes, or raw exception text - only opaque target IDs, rule IDs, category, confidence, line numbers and counts.
- **Reveal location**: the GUI shows the location of one finding only after you select it and confirm a warning. It is never copied or saved automatically; locations live only in the GUI process memory and are cleared on a new selection, a new scan and exit.
- **Report export**: written only when you ask, never overwriting an existing file and never inside a scanned folder. Numeric scan-time file identities travel only over a separate private process channel; every selected root is reopened and compared immediately before export. Missing, moved, replaced or unverifiable roots make export fail closed.
- **External system runtime prerequisite**: the public ZIP omits `VCRUNTIME140*.dll`, whose redistribution rights were not established for this release. Windows 10/11 x64 must already have the Microsoft Visual C++ 2015–2022 x64 Runtime (or a newer compatible runtime) installed. ShareGuard neither downloads/installs nor bypasses this prerequisite.
- **No logs**: no scan logs or location maps are written to disk by default.

## Reporting a vulnerability

Please do not post secrets or real paths in public issues. Use the
repository's private security reporting (GitHub Security Advisories) and use
synthetic data in reproductions.
