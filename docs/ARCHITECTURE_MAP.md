# ShareGuard architecture map

Purpose: know which layer, component and invariant a change touches before
making it. Stable IDs (`L*`, `C*`, `INV-*`) survive file renames. The map is
checked against source; when a listed file changes without this map being
reviewed, treat the map as stale.

## Layers

| ID | Layer | Files | Owns |
|---|---|---|---|
| L1 | Core scan engine and public boundary | `src/shareguard/{platform_support,policy,model,rules,textscan,zipscan,context,scanner,_winfs,_posixfs}.py` | Windows 10/11 x64 public gate, bounded traversal, safe opens, detection, sanitized result model |
| L2 | Report output | `src/shareguard/safeio.py` | fixed-schema JSON report, exclusive create, destination checks |
| L3 | CLI | `src/shareguard/{cli,__main__}.py` | argument parsing without echo, exit codes, GUI launch with no args |
| L4 | GUI worker/IPC | `src/shareguard/gui_session.py` | spawned worker, pipes, drain/reaper threads, validation, location store |
| L5 | GUI (Tk) | `src/shareguard/{gui,locales}.py` | window, selection, results, reveal-one-location, export |
| L6 | Verification/packaging | `src/shareguard/gui_selftest.py`, `tools/*`, `tests/*`, `.github/workflows/*` | live self-test, build, packaged smoke, CI |

External boundaries: Windows 10/11 x64 local filesystem (read-only inputs;
one new report file), Win32 file APIs, OS process creation (spawn), Tcl/Tk.
ShareGuard has no network feature. The POSIX backend is internal synthetic
core-test support only and is not a public product boundary.

## Data and control flow

```
selected paths (GUI selection / CLI args)
   │
   ├─ CLI (L3): owned spawn worker + Ctrl+C cancel ─┐
   │                                                 ▼
   └─ GUI (L5) ─ ScanSession (L4) ─ spawn ─> worker_main ─> scanner.scan_paths (L1)
          ▲            │  result pipe: JSON {progress|result|error}     │
          │            │  private location pipe: [gen,target,path,member] ◄─ location_callback
          │            │  private scope pipe: numeric scan/root identities only
          │   drain threads: parse + ScanResult.from_dict/to_dict round trip + exit_code
          │   (bounded slots: merged progress, one terminal)
          └── poll() on Tk thread via after(100 ms); render in batches
                         │
        validated result + imported private root scopes
                         └──> safeio.write_report (L2) on explicit save
```

## Components and key symbols

| ID | Component | Key symbols | Notes |
|---|---|---|---|
| C0 | Public platform | `platform_support.is_public_platform_supported`, `unsupported_platform_result` | one Windows 10/11 x64 predicate shared by public API, CLI and GUI; no bypass flag/environment variable |
| C1 | Policy | `Policy`, `CEILINGS`, `Policy.from_dict` | limits can only be lowered |
| C2 | Result model | `ScanResult.to_dict/from_dict`, `IssueCode`, `ISSUE_CODES`, `Finding`, `Target` | opaque target IDs `T<n>`; strict schema |
| C3 | Scanner | `scan_paths(paths, policy, cancel_event, callback, location_callback)` | `callback` gets counters + `current_target`; `location_callback(target_id, path, member)` |
| C4 | Exit rule | `cli.exit_code` | complete-none 0, complete-findings 1, incomplete 2, cancelled 3, error 4 |
| C5 | Report | `safeio.write_report`, `export_result_scopes/import_result_scopes/clear_result_scopes`, `ReportError.code`, `REPORT_ERROR_CODES` | fixed uppercase codes only; report export requires privately imported numeric root identities |
| C6 | Worker | `gui_session.worker_main` | never imports Tk; public JSON has no paths/identities; sends locations and numeric report scopes over two distinct private one-way pipes |
| C7 | Session | `ScanSession.start/poll/cancel/close`, `_drain_results`, `_drain_locations`, `_drain_scope`, `_reap` | validates all IPC off the Tk thread; `poll` and `close` never block |
| C8 | Location store | `LocationStore.reset/put/get/clear` | memory only; generation-gated; ≤20,000 entries, ≤8 MiB chars |
| C9 | App | `ShareGuardApp.start_scan/_poll/_handle_final/reveal_location/save_report/shutdown` | every Tk call on the UI thread (`_require_ui_thread`) |
| C10 | Self-test | `gui_selftest.run`, `audited_worker` | sanitized summary only; network audit hooks |

## Invariants (high risk first)

| ID | Invariant | Enforced in | Tests |
|---|---|---|---|
| INV-PLATFORM-1 | Public API, CLI and GUI call the same `is_public_platform_supported()` boundary before scanner/worker creation or input access; unsupported platforms get a fixed sanitized result/error | C0, C9, CLI/public API | core/CLI platform tests; `test_gui.py::test_shared_platform_guard_refuses_without_worker_or_input_touch` |
| INV-LEAK-1 | No source paths, ZIP member names, content, secret fragments/hashes or raw exception text in results, CLI output, GUI widgets (except the reveal dialog), progress messages or reports | C2, C3, C5, C6 (`sanitize_progress`), C9 | `test_gui.py` (canary in labels), `test_gui_live.py` (summary + report canary), core tests, `packaged_smoke.py` |
| INV-LEAK-2 | Paths travel only on the private location pipe, live only in `LocationStore` memory, and are shown for one selected finding after a warning; never copied/saved; cleared on new selection, new scan and exit. Numeric report-scope identities use a separate private pipe and never enter result/progress/location/display/report data | C5, C6, C8, C9 | `test_gui.py::test_result_render_reveal_and_cleanup`, `test_gui_session.py::test_scope_protocol_is_numeric_only_and_generation_gated`, live test |
| INV-IPC-1 | Result pipe messages have exact key sets, allowlisted types/codes/counters, matching generation, ≤16 MiB; violations end the scan as `protocol_violation` | C7 `parse_message`, `validate_core_result` | `test_gui_session.py::ProtocolTests`, `test_protocol_violations`, `test_oversized_message_is_protocol_violation` |
| INV-IPC-2 | A result is rendered only after strict core validation (`from_dict` → `to_dict` equals payload) on a helper thread; export stays disabled until the bounded numeric scope envelope is validated and imported | C5, C7, C9 | `test_strict_validation_*`, `test_scope_protocol_is_numeric_only_and_generation_gated`, live report tests |
| INV-THREAD-1 | Helper threads never touch Tk; Tk methods refuse other threads | C7, C9 | `test_tk_access_off_ui_thread_is_refused` |
| INV-CANCEL-1 | An accepted cancel can never end as a complete result: a non-`cancelled` result that arrives after acceptance is discarded; cancel after the final outcome is rejected | C7 `poll` | `test_accepted_cancel_discards_complete_result_in_flight`, `test_cancel_after_final_is_rejected` |
| INV-CANCEL-2 | Cooperative cancel first; only the app-owned worker is terminated after a short grace, then killed | C7 | `test_forced_cancel_terminates_owned_worker`, live cancel |
| INV-TIME-1 | GUI wall timeout = policy scan timeout + 5 s startup grace, measured from before spawn | C7, C9 | `test_wall_timeout_covers_startup_and_hang`, `test_selection_shown_only_while_selecting` |
| INV-CLEAN-1 | `close()` returns immediately; the reaper sets `reaped` only after the worker is confirmed dead and all helper threads ended (else `reap_failed`); no thread accumulation | C7 | `test_close_is_nonblocking_and_releases_hung_writer`, `test_repeated_cancel_does_not_accumulate_threads`, `test_partial_message_then_death_does_not_hang` |
| INV-DONE-1 | Outcome and completeness are separate; GUI and CLI use the same exit rule; no "safe" verdict text | C4, C9, locales | `test_error_and_cancelled_outcomes`, live test exit codes |
| INV-UI-1 | UI stays responsive: polling via `after`, batched rendering (400 rows), heartbeat gaps < 0.5 s while rendering 10,000 findings and during cooperative and forced cancellation | C9, C10 | `test_large_result_renders_in_batches`, live `large_result_max_ui_gap_seconds`, `max_ui_gap_seconds_during_cancel`, `forced_cancel_max_ui_gap_seconds` |
| INV-NET-1 | ShareGuard has no application networking/telemetry/update feature; known remote/cloud/reparse inputs are rejected before open. This does not promise that OS/filesystem/security drivers never communicate externally | whole app | core Windows path tests; live and packaged self-test audit hooks (Python-level events only) |
| INV-PKG-1 | Release ZIP contains only the two audited app trees, four public documents, and enumerated full installed license texts; each binary/data file matches the fresh COLLECT inventory, explicit allowlist, and approved provenance. `VCRUNTIME140*.dll` is omitted case-insensitively and recorded as an external installed prerequisite in the private sanitized inventory. GUI has the windows subsystem, CLI the console subsystem; entry and every nested PYZ code object's `co_filename` are checked with a mandatory PyInstaller reader gate; frozen spawn works | `tools/build_windows.ps1`, `tools/package_release.py`, `tools/packaged_smoke.py` | `test_gui_build.py`, packaged smoke |

Core-only invariants (bounded reads, ZIP handling, link/reparse rejection,
input immutability, report destination rules) are owned and tested by the
core test suite (`tests/test_core*.py`, `tests/test_cli*.py`).

## Known limits of the verification

- Network observation uses per-worker Python audit hooks; native code and OS/filesystem/security drivers that bypass them are not observed. A deliberately non-cooperative worker that is forcibly terminated cannot emit its final audit receipt, so that phase proves UI/process cleanup rather than complete network observation.
- Public scans are Windows 10/11 x64 only and require the Microsoft Visual C++ 2015–2022 x64 Runtime (or newer compatible runtime) already installed; the public ZIP deliberately omits `VCRUNTIME140*.dll`. Windows 11 and a runtime-absent clean VM have not been executed.  Ubuntu CI exercises internal synthetic/core development regressions and is not evidence of Linux product support or an all-filesystem offline guarantee.
- The live GUI test checks Tk widget state and the real worker pipeline; it does not compare screenshots. The packaged smoke adds a native Win32 visible-window check for the release GUI.
- The release GUI has no scripted mode; scripted packaged GUI checks run on a separately built self-test executable of the same code.
