"""User-interface strings for the ShareGuard GUI.

Korean is the default language. Adding a language means adding one more
mapping with the same keys; ``missing_keys`` is used by the tests to keep
every catalog complete.
"""

from __future__ import annotations

DEFAULT_LANGUAGE = "ko"

_KO = {
    "app.title": "ShareGuard - 공유 전 민감정보 점검",
    "menu.language": "언어",
    "menu.theme": "테마",
    "theme.light": "밝게",
    "theme.dark": "어둡게",
    "btn.add_files": "파일 추가...",
    "btn.add_folder": "폴더 추가...",
    "btn.clear": "선택 비우기",
    "btn.scan": "점검 시작",
    "btn.cancel": "취소",
    "btn.reveal": "선택 항목 위치 보기...",
    "btn.save": "JSON 보고서 저장...",
    "label.selection": "점검 대상: {count}개 선택됨",
    "label.selection_hint": "선택한 경로는 이 화면에서만 확인용으로 표시되며 결과·보고서에는 포함되지 않습니다.",
    "label.summary": "발견 {findings}건 · 파일 {files}개 · ZIP 항목 {entries}개 · 점검 못한 항목 {issues}건",
    "label.disclaimer": "이 결과는 안전 판정이 아닙니다. 탐지 규칙이 놓치는 정보가 있을 수 있습니다.",
    "col.target": "대상 ID",
    "col.category": "분류",
    "col.rule": "규칙",
    "col.confidence": "신뢰도",
    "col.severity": "심각도",
    "col.line": "줄",
    "col.count": "횟수",
    "col.issue_code": "문제 코드",
    "col.issue_text": "설명",
    "col.issue_count": "건수",
    "category.service_token": "서비스 토큰",
    "category.credential_assignment": "비밀번호·키 값",
    "category.private_key": "개인 키",
    "category.url_credential": "URL 로그인 정보",
    "level.high": "높음",
    "level.medium": "보통",
    "level.low": "낮음",
    "enum.unknown": "알 수 없음",
    "tab.findings": "발견 항목",
    "tab.issues": "점검하지 못한 항목",
    "status.idle": "대기 중",
    "status.starting": "점검 준비 중...",
    "status.scanning": "점검 중... 대상 {targets}개",
    "status.cancelling": "취소 중...",
    "status.done": "점검 완료",
    "outcome.complete_none": "완료 - 규칙에 해당하는 항목 없음 (안전 보증 아님)",
    "outcome.complete_findings": "완료 - 민감정보 의심 항목 발견",
    "outcome.incomplete": "불완전 - 일부를 점검하지 못했습니다",
    "outcome.cancelled": "취소됨 - 결과가 불완전합니다",
    "outcome.error": "오류 - 점검을 완료하지 못했습니다 ({code})",
    "dlg.no_selection": "먼저 점검할 파일이나 폴더를 추가하세요.",
    "dlg.no_finding_selected": "위치를 확인할 발견 항목을 하나 선택하세요.",
    "dlg.reveal_title": "위치 정보 표시 경고",
    "dlg.reveal_warning": "선택한 발견 항목 1건의 실제 파일 위치를 화면에 표시합니다.\n\n화면 공유·녹화 중이라면 먼저 중지하세요. 위치는 자동으로 복사되거나 저장되지 않습니다.\n\n계속할까요?",
    "dlg.reveal_unavailable": "이 항목의 위치 정보가 없습니다. (새 점검을 시작하면 이전 위치 정보는 지워집니다)",
    "dlg.location_title": "발견 항목 위치",
    "dlg.location_path": "파일 경로",
    "dlg.location_member": "ZIP 내부 항목",
    "dlg.close": "닫기",
    "dlg.save_title": "JSON 보고서 저장",
    "dlg.saved": "보고서를 저장했습니다. (경로·내용·비밀값은 포함되지 않습니다)",
    "dlg.save_failed": "보고서를 저장하지 못했습니다. (코드: {code})",
    "dlg.no_result": "저장할 점검 결과가 없습니다.",
    "dlg.busy": "점검이 진행 중입니다.",
    "dlg.quit_busy": "점검이 진행 중입니다. 취소하고 종료할까요?",
    "dlg.error_title": "ShareGuard",
}

_EN = {
    "app.title": "ShareGuard - pre-sharing sensitive data check",
    "menu.language": "Language",
    "menu.theme": "Theme",
    "theme.light": "Light",
    "theme.dark": "Dark",
    "btn.add_files": "Add files...",
    "btn.add_folder": "Add folder...",
    "btn.clear": "Clear selection",
    "btn.scan": "Start scan",
    "btn.cancel": "Cancel",
    "btn.reveal": "Show selected location...",
    "btn.save": "Save JSON report...",
    "label.selection": "Targets: {count} selected",
    "label.selection_hint": "Selected paths are shown here only for confirmation and are not included in results or reports.",
    "label.summary": "Findings: {findings} · Files: {files} · ZIP entries: {entries} · Not scanned: {issues}",
    "label.disclaimer": "This is not a safety verdict. The rules can miss sensitive data.",
    "col.target": "Target ID",
    "col.category": "Category",
    "col.rule": "Rule",
    "col.confidence": "Confidence",
    "col.severity": "Severity",
    "col.line": "Line",
    "col.count": "Count",
    "col.issue_code": "Issue code",
    "col.issue_text": "Description",
    "col.issue_count": "Count",
    "category.service_token": "Service Token",
    "category.credential_assignment": "Password or Key Value",
    "category.private_key": "Private Key",
    "category.url_credential": "URL Login Information",
    "level.high": "High",
    "level.medium": "Medium",
    "level.low": "Low",
    "enum.unknown": "Unknown",
    "tab.findings": "Findings",
    "tab.issues": "Not scanned",
    "status.idle": "Idle",
    "status.starting": "Preparing scan...",
    "status.scanning": "Scanning... Targets: {targets}",
    "status.cancelling": "Cancelling...",
    "status.done": "Scan finished",
    "outcome.complete_none": "Complete - no rule matches (not a safety guarantee)",
    "outcome.complete_findings": "Complete - possible sensitive data found",
    "outcome.incomplete": "Incomplete - some content was not scanned",
    "outcome.cancelled": "Cancelled - results are incomplete",
    "outcome.error": "Error - the scan did not finish ({code})",
    "dlg.no_selection": "Add files or folders to scan first.",
    "dlg.no_finding_selected": "Select one finding to show its location.",
    "dlg.reveal_title": "Location display warning",
    "dlg.reveal_warning": "The real file location of the one selected finding will be shown on screen.\n\nStop any screen sharing or recording first. The location is never copied or saved automatically.\n\nContinue?",
    "dlg.reveal_unavailable": "No location is available for this item. (Starting a new scan clears earlier locations.)",
    "dlg.location_title": "Finding location",
    "dlg.location_path": "File path",
    "dlg.location_member": "ZIP member",
    "dlg.close": "Close",
    "dlg.save_title": "Save JSON report",
    "dlg.saved": "Report saved. (It contains no paths, content or secret values.)",
    "dlg.save_failed": "The report could not be saved. (code: {code})",
    "dlg.no_result": "There is no scan result to save.",
    "dlg.busy": "A scan is in progress.",
    "dlg.quit_busy": "A scan is in progress. Cancel it and quit?",
    "dlg.error_title": "ShareGuard",
}

# Descriptions for the core's fixed issue codes: code -> (Korean, English).
ISSUE_DESCRIPTIONS = {
    "UNSUPPORTED_PLATFORM": ("지원하지 않는 실행 환경", "Unsupported platform"),
    "PATH_NOT_FOUND": ("경로를 찾을 수 없음", "Path not found"),
    "PATH_UNSUPPORTED": ("지원하지 않는 경로 형식", "Unsupported path type"),
    "LINK_REJECTED": ("링크·정션·재분석 지점은 점검하지 않음", "Link, junction or reparse point not followed"),
    "SPECIAL_FILE": ("일반 파일이 아님", "Not a regular file"),
    "ACCESS_DENIED": ("접근 권한 없음", "Access denied"),
    "OPEN_FAILED": ("파일을 열 수 없음", "Could not open file"),
    "READ_ERROR": ("읽기 오류", "Read error"),
    "DIRECTORY_READ_ERROR": ("폴더 목록을 읽을 수 없음", "Could not list folder"),
    "IDENTITY_UNVERIFIED": ("파일 신원을 확인할 수 없어 건너뜀", "File identity could not be verified"),
    "MUTATION_DETECTED": ("점검 중 파일이 변경됨", "File changed during the scan"),
    "FILE_TOO_LARGE": ("파일 크기 한도 초과", "File size limit exceeded"),
    "TOTAL_BYTES_LIMIT": ("전체 읽기량 한도 초과", "Total read limit exceeded"),
    "ENTRY_COUNT_LIMIT": ("항목 수 한도 초과", "Entry count limit exceeded"),
    "DIRECTORY_COUNT_LIMIT": ("폴더 수 한도 초과", "Folder count limit exceeded"),
    "DEPTH_LIMIT": ("폴더 깊이 한도 초과", "Folder depth limit exceeded"),
    "FILE_TIME_LIMIT": ("파일별 시간 한도 초과", "Per-file time limit exceeded"),
    "SCAN_TIME_LIMIT": ("전체 시간 한도 초과", "Scan time limit exceeded"),
    "FINDINGS_LIMIT": ("발견 항목 수 한도 초과", "Findings limit reached"),
    "ISSUES_LIMIT": ("문제 항목 수 한도 초과", "Issues limit reached"),
    "BINARY_CONTENT": ("텍스트가 아닌 파일", "Binary content not scanned"),
    "UNSUPPORTED_ENCODING": ("지원하지 않는 문자 인코딩", "Unsupported text encoding"),
    "LINE_TOO_LONG": ("줄 길이 한도 초과", "Line length limit exceeded"),
    "UNSUPPORTED_ARCHIVE": ("지원하지 않는 압축 형식", "Unsupported archive format"),
    "ZIP_CORRUPT": ("손상된 ZIP", "Corrupt ZIP archive"),
    "ZIP_CENTRAL_DIRECTORY_LIMIT": ("ZIP 목록 한도 초과", "ZIP directory limit exceeded"),
    "ZIP_UNSUPPORTED_FEATURE": ("지원하지 않는 ZIP 기능", "Unsupported ZIP feature"),
    "ZIP_ENCRYPTED_ENTRY": ("암호화된 ZIP 항목", "Encrypted ZIP entry"),
    "ZIP_UNSUPPORTED_COMPRESSION": ("지원하지 않는 ZIP 압축 방식", "Unsupported ZIP compression"),
    "ZIP_NESTED_ARCHIVE": ("ZIP 안의 압축 파일은 점검하지 않음", "Nested archive not scanned"),
    "ZIP_CRC_MISMATCH": ("ZIP 무결성(CRC) 불일치", "ZIP CRC mismatch"),
    "ZIP_UNSAFE_NAME": ("안전하지 않은 ZIP 항목 이름", "Unsafe ZIP entry name"),
    "ZIP_DUPLICATE_NAME": ("중복된 ZIP 항목 이름", "Duplicate ZIP entry name"),
    "ZIP_LINK_ENTRY": ("ZIP 링크 항목", "ZIP link entry"),
    "ZIP_SPECIAL_ENTRY": ("ZIP 특수 항목", "ZIP special entry"),
    "ZIP_ENTRY_TOO_LARGE": ("ZIP 항목 크기 한도 초과", "ZIP entry size limit exceeded"),
    "ZIP_COMMENT_NOT_SCANNED": ("ZIP 주석은 점검하지 않음", "ZIP comment not scanned"),
    "NO_INPUT": ("점검 대상 없음", "No input"),
    "POLICY_INVALID": ("잘못된 점검 설정", "Invalid scan policy"),
    "INTERNAL_ERROR": ("내부 오류", "Internal error"),
}

for _code, (_ko_text, _en_text) in ISSUE_DESCRIPTIONS.items():
    _KO["issue." + _code] = _ko_text
    _EN["issue." + _code] = _en_text

CATALOGS = {"ko": _KO, "en": _EN}
LANGUAGE_NAMES = {"ko": "한국어", "en": "English"}

# Fixed render-only mappings. Unknown values always collapse to a localized
# label and are never echoed into the UI.
FINDING_CATEGORY_KEYS = {
    "service_token": "category.service_token",
    "credential_assignment": "category.credential_assignment",
    "private_key": "category.private_key",
    "url_credential": "category.url_credential",
}
FINDING_LEVEL_KEYS = {
    "high": "level.high",
    "medium": "level.medium",
    "low": "level.low",
}


def available_languages():
    return list(CATALOGS)


def text(language, key, **values):
    """Return the string for ``key``; unknown languages fall back to Korean."""
    catalog = CATALOGS.get(language, CATALOGS[DEFAULT_LANGUAGE])
    template = catalog.get(key)
    if template is None:
        template = CATALOGS[DEFAULT_LANGUAGE].get(key, key)
    if values:
        try:
            return template.format(**values)
        except (KeyError, IndexError, ValueError):
            return template
    return template


def finding_category(language, value):
    """Localize one allowlisted finding category without echoing unknown input."""
    key = FINDING_CATEGORY_KEYS.get(value) if isinstance(value, str) else None
    return text(language, key or "enum.unknown")


def finding_level(language, value):
    """Localize one allowlisted confidence/severity without echoing unknown input."""
    key = FINDING_LEVEL_KEYS.get(value) if isinstance(value, str) else None
    return text(language, key or "enum.unknown")


def missing_keys(language):
    reference = set(CATALOGS[DEFAULT_LANGUAGE])
    return sorted(reference - set(CATALOGS.get(language, {})))
