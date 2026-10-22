"""Tkinter desktop GUI for ShareGuard.

Threading rule: every Tk call happens on the thread that created the root
window.  Scans run in a spawned worker process managed by
:class:`shareguard.gui_session.ScanSession`; the UI polls it with ``after``.
Drain threads in the session never call Tk.
"""

from __future__ import annotations

import multiprocessing
import threading

from shareguard import locales
from shareguard.gui_session import STARTUP_GRACE_SECONDS, LocationStore, ScanSession

POLL_MS = 100
RENDER_BATCH = 400
SHUTDOWN_REAP_SECONDS = 6.0


def supported_public_platform():
    """Use the shared public Windows 10/11 x64 product boundary."""
    from shareguard.platform_support import is_public_platform_supported

    return is_public_platform_supported()


THEMES = {
    "light": {
        "bg": "#f3f4f6",
        "fg": "#1b1d21",
        "field": "#ffffff",
        "muted": "#5b6170",
        "select_bg": "#2f6fb0",
        "select_fg": "#ffffff",
        "warn": "#9a4a00",
    },
    "dark": {
        "bg": "#1e2024",
        "fg": "#e6e8eb",
        "field": "#2a2d33",
        "muted": "#a2a8b3",
        "select_bg": "#3d6ea8",
        "select_fg": "#ffffff",
        "warn": "#f0a050",
    },
}

OUTCOME_KEYS = {
    0: "outcome.complete_none",
    1: "outcome.complete_findings",
    2: "outcome.incomplete",
    3: "outcome.cancelled",
    4: "outcome.error",
}


# Session-level error codes (fixed set from gui_session.ERROR_CODES).
def session_error_code(value):
    from shareguard.gui_session import ERROR_CODES

    return value if value in ERROR_CODES else "worker_failed"


def report_error_code(exc):
    """Map a report failure to the core's fixed codes; never echo exception text."""
    try:
        from shareguard.safeio import REPORT_ERROR_CODES, REPORT_WRITE_FAILED
    except Exception:
        return "REPORT_WRITE_FAILED"
    code = getattr(exc, "code", None)
    return code if isinstance(code, str) and code in REPORT_ERROR_CODES else REPORT_WRITE_FAILED


# ---------------------------------------------------------------------------
# View-model helpers (pure functions; no Tk) over a result dict that has
# already passed ``validate_result``.


def finding_rows(result, language=locales.DEFAULT_LANGUAGE):
    """Return localized tree rows without changing opaque target/rule IDs."""
    return [
        (
            f["target_id"],
            locales.finding_category(language, f["category"]),
            f["rule_id"],
            locales.finding_level(language, f["confidence"]),
            locales.finding_level(language, f["severity"]),
            f["line"],
            f["count"],
        )
        for f in result["findings"]
    ]


def issue_rows(result, language):
    """Return (code, description, count) rows using the core's exact codes."""
    from shareguard.model import ISSUE_CODES

    counts = {}
    for issue in result["issues"]:
        code = issue["code"]
        if code not in ISSUE_CODES:
            raise ValueError("unknown issue code")
        counts[code] = counts.get(code, 0) + 1
    return [(code, locales.text(language, "issue." + code), n) for code, n in sorted(counts.items())]


def summary_counts(result):
    counts = result["counts"]
    return {
        "findings": len(result["findings"]),
        "files": counts["files_scanned"],
        "entries": counts["archive_entries_scanned"],
        "issues": len(result["issues"]),
    }


# ---------------------------------------------------------------------------


class ShareGuardApp:
    """Main window.  ``session_factory`` exists so tests can inject workers."""

    def __init__(self, root=None, *, language=None, theme="light", session_factory=ScanSession):
        import tkinter as tk
        from tkinter import ttk

        self._tk = tk
        self._ttk = ttk
        self.root = root if root is not None else tk.Tk()
        self._ui_thread = threading.current_thread()
        self.language = language if language in locales.CATALOGS else locales.DEFAULT_LANGUAGE
        self.theme = theme if theme in THEMES else "light"
        self._session_factory = session_factory
        self.paths = []
        self.locations = LocationStore()
        self.session = None
        self.generation = 0
        self.result = None
        self.scan_result = None
        self.final = None
        self._export_ready = False
        self._poll_job = None
        self._render_job = None
        self._progress_targets = 0
        self._dialog = None
        self._language_var = tk.StringVar(master=self.root, value=self.language)
        self._theme_var = tk.StringVar(master=self.root, value=self.theme)
        self._build()
        self.apply_theme(self.theme)
        self.refresh_texts()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # -- construction --------------------------------------------------------

    def _build(self):
        tk, ttk = self._tk, self._ttk
        root = self.root
        root.geometry("900x620")
        root.minsize(720, 480)
        self.style = ttk.Style(root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.menubar = tk.Menu(root, tearoff=False)
        self.language_menu = tk.Menu(self.menubar, tearoff=False)
        for code in locales.available_languages():
            self.language_menu.add_radiobutton(
                label=locales.LANGUAGE_NAMES.get(code, code),
                value=code,
                variable=self._language_var,
                command=lambda c=code: self.set_language(c),
            )
        self.theme_menu = tk.Menu(self.menubar, tearoff=False)
        for name in THEMES:
            self.theme_menu.add_radiobutton(
                value=name, variable=self._theme_var, command=lambda n=name: self.apply_theme(n)
            )
        self.menubar.add_cascade(menu=self.language_menu)
        self.menubar.add_cascade(menu=self.theme_menu)
        root.configure(menu=self.menubar)

        outer = ttk.Frame(root, padding=10)
        outer.pack(fill="both", expand=True)

        select_row = ttk.Frame(outer)
        select_row.pack(fill="x")
        self.btn_add_files = ttk.Button(select_row, command=self.on_add_files)
        self.btn_add_folder = ttk.Button(select_row, command=self.on_add_folder)
        self.btn_clear = ttk.Button(select_row, command=self.on_clear)
        for widget in (self.btn_add_files, self.btn_add_folder, self.btn_clear):
            widget.pack(side="left", padx=(0, 6))
        self.lbl_selection = ttk.Label(select_row)
        self.lbl_selection.pack(side="left", padx=10)

        self.selection_list = tk.Listbox(outer, height=4, activestyle="none", exportselection=False)
        self.selection_list.pack(fill="x", pady=(6, 0))
        self.lbl_hint = ttk.Label(outer, style="Muted.TLabel", wraplength=860)
        self.lbl_hint.pack(fill="x", pady=(2, 8))

        action_row = ttk.Frame(outer)
        action_row.pack(fill="x")
        self.btn_scan = ttk.Button(action_row, command=self.on_scan)
        self.btn_cancel = ttk.Button(action_row, command=self.on_cancel, state="disabled")
        self.btn_scan.pack(side="left", padx=(0, 6))
        self.btn_cancel.pack(side="left")
        self.progress = ttk.Progressbar(action_row, mode="indeterminate", length=180)
        self.progress.pack(side="left", padx=10)
        self.lbl_status = ttk.Label(action_row)
        self.lbl_status.pack(side="left")

        self.lbl_outcome = ttk.Label(outer, style="Outcome.TLabel")
        self.lbl_outcome.pack(fill="x", pady=(8, 0))
        self.lbl_summary = ttk.Label(outer)
        self.lbl_summary.pack(fill="x")
        self.lbl_disclaimer = ttk.Label(outer, style="Warn.TLabel", wraplength=860)
        self.lbl_disclaimer.pack(fill="x", pady=(0, 6))

        # Pack the footer first from the bottom so the expandable results area
        # cannot consume it at the supported 720x480 minimum client size.
        bottom = ttk.Frame(outer)
        bottom.pack(side="bottom", fill="x", pady=(8, 0))
        self.btn_reveal = ttk.Button(bottom, command=self.on_reveal, state="disabled")
        self.btn_save = ttk.Button(bottom, command=self.on_save, state="disabled")
        self.btn_reveal.pack(side="left", padx=(0, 6))
        self.btn_save.pack(side="left")

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        findings_frame = ttk.Frame(self.notebook)
        issues_frame = ttk.Frame(self.notebook)
        self.notebook.add(findings_frame)
        self.notebook.add(issues_frame)

        self.finding_columns = ("target", "category", "rule", "confidence", "severity", "line", "count")
        self.tree = ttk.Treeview(
            findings_frame, columns=self.finding_columns, show="headings", selectmode="browse"
        )
        widths = (90, 150, 200, 80, 80, 60, 60)
        for column, width in zip(self.finding_columns, widths):
            self.tree.column(column, width=width, anchor="w", stretch=True)
        scroll = ttk.Scrollbar(findings_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.issue_tree = ttk.Treeview(
            issues_frame, columns=("code", "text", "count"), show="headings", selectmode="none"
        )
        self.issue_tree.column("code", width=230, anchor="w")
        self.issue_tree.column("text", width=330, anchor="w")
        self.issue_tree.column("count", width=70, anchor="e")
        self.issue_tree.pack(fill="both", expand=True)


    # -- language / theme ----------------------------------------------------

    def t(self, key, **values):
        return locales.text(self.language, key, **values)

    def set_language(self, code):
        self._require_ui_thread()
        if code in locales.CATALOGS:
            self.language = code
            self._language_var.set(code)
            self.refresh_texts()

    def refresh_texts(self):
        t = self.t
        self.root.title(t("app.title"))
        self.menubar.entryconfigure(0, label=t("menu.language"))
        self.menubar.entryconfigure(1, label=t("menu.theme"))
        for index, name in enumerate(THEMES):
            self.theme_menu.entryconfigure(index, label=t("theme." + name))
        self.btn_add_files.configure(text=t("btn.add_files"))
        self.btn_add_folder.configure(text=t("btn.add_folder"))
        self.btn_clear.configure(text=t("btn.clear"))
        self.btn_scan.configure(text=t("btn.scan"))
        self.btn_cancel.configure(text=t("btn.cancel"))
        self.btn_reveal.configure(text=t("btn.reveal"))
        self.btn_save.configure(text=t("btn.save"))
        self.lbl_hint.configure(text=t("label.selection_hint"))
        self.lbl_disclaimer.configure(text=t("label.disclaimer"))
        self.notebook.tab(0, text=t("tab.findings"))
        self.notebook.tab(1, text=t("tab.issues"))
        headings = ("col.target", "col.category", "col.rule", "col.confidence", "col.severity", "col.line", "col.count")
        for column, key in zip(self.finding_columns, headings):
            self.tree.heading(column, text=t(key))
        self.issue_tree.heading("code", text=t("col.issue_code"))
        self.issue_tree.heading("text", text=t("col.issue_text"))
        self.issue_tree.heading("count", text=t("col.issue_count"))
        if self.result is not None:
            self._render_result()
        self._refresh_selection_label()
        self._refresh_status()
        self._refresh_outcome()

    def apply_theme(self, name):
        self._require_ui_thread()
        if name not in THEMES:
            return
        self.theme = name
        self._theme_var.set(name)
        c = THEMES[name]
        style = self.style
        style.configure(".", background=c["bg"], foreground=c["fg"], fieldbackground=c["field"])
        style.configure("TFrame", background=c["bg"])
        style.configure("TLabel", background=c["bg"], foreground=c["fg"])
        style.configure("Muted.TLabel", background=c["bg"], foreground=c["muted"])
        style.configure("Warn.TLabel", background=c["bg"], foreground=c["warn"])
        style.configure("Outcome.TLabel", background=c["bg"], foreground=c["fg"], font=("TkDefaultFont", 11, "bold"))
        style.configure("TButton", background=c["field"], foreground=c["fg"])
        style.map("TButton", background=[("active", c["select_bg"])], foreground=[("active", c["select_fg"]), ("disabled", c["muted"])])
        style.configure("TNotebook", background=c["bg"])
        style.configure("TNotebook.Tab", background=c["field"], foreground=c["fg"])
        style.map("TNotebook.Tab", background=[("selected", c["bg"])])
        style.configure("Treeview", background=c["field"], fieldbackground=c["field"], foreground=c["fg"])
        style.map("Treeview", background=[("selected", c["select_bg"])], foreground=[("selected", c["select_fg"])])
        style.configure("Treeview.Heading", background=c["bg"], foreground=c["fg"])
        style.configure("TProgressbar", background=c["select_bg"], troughcolor=c["field"])
        self.root.configure(background=c["bg"])
        self.selection_list.configure(
            background=c["field"], foreground=c["fg"], selectbackground=c["select_bg"], selectforeground=c["select_fg"]
        )
        for menu in (self.menubar, self.language_menu, self.theme_menu):
            try:
                menu.configure(background=c["field"], foreground=c["fg"])
            except self._tk.TclError:
                pass

    # -- selection -----------------------------------------------------------

    def on_add_files(self):
        from tkinter import filedialog

        if self._busy():
            return
        chosen = filedialog.askopenfilenames(parent=self.root)
        self.add_paths(list(chosen or ()))

    def on_add_folder(self):
        from tkinter import filedialog

        if self._busy():
            return
        chosen = filedialog.askdirectory(parent=self.root, mustexist=True)
        if chosen:
            self.add_paths([chosen])

    def add_paths(self, new_paths):
        """Add consciously selected paths; a new selection discards old results."""
        self._require_ui_thread()
        if self._busy():
            return
        new_paths = [p for p in new_paths if isinstance(p, str) and p]
        if not new_paths:
            return
        if self.final is not None:
            self.paths = []
        self._reset_results()
        for path in new_paths:
            if path not in self.paths:
                self.paths.append(path)
        self._show_selection(True)

    def on_clear(self):
        self._require_ui_thread()
        if self._busy():
            return
        self.paths = []
        self._reset_results()
        self._show_selection(True)

    def _show_selection(self, visible):
        self.selection_list.delete(0, "end")
        if visible:
            for path in self.paths:
                self.selection_list.insert("end", path)
        self._refresh_selection_label()

    def _refresh_selection_label(self):
        self.lbl_selection.configure(text=self.t("label.selection", count=len(self.paths)))

    # -- scanning ------------------------------------------------------------

    def _busy(self):
        return self.session is not None and not self.session.finished

    def on_scan(self):
        self._require_ui_thread()
        from tkinter import messagebox

        if self._busy():
            return
        if not self.paths:
            messagebox.showinfo(self.t("dlg.error_title"), self.t("dlg.no_selection"), parent=self.root)
            return
        self.start_scan()

    def start_scan(self, policy=None):
        """Start a background scan of the current selection."""
        self._require_ui_thread()
        if self._busy() or not self.paths:
            return False
        if not supported_public_platform():
            self._reset_results()
            self.final = {"outcome": "error", "result": None, "code": "unsupported_platform"}
            self._exit_code = 4
            self._status_key = "status.done"
            self._refresh_status()
            self._refresh_outcome()
            return False
        from shareguard.policy import Policy

        policy = policy if policy is not None else Policy()
        self._reset_results()
        self.generation += 1
        self._show_selection(False)
        self.session = self._session_factory(
            self.generation,
            list(self.paths),
            policy.to_dict(),
            location_store=self.locations,
            wall_timeout=float(policy.scan_timeout_seconds) + STARTUP_GRACE_SECONDS,
        )
        self._set_running(True)
        self._status_key = "status.starting"
        self._refresh_status()
        if not self.session.start():
            self._handle_final()
            return False
        self._schedule_poll()
        return True

    def on_cancel(self):
        self._require_ui_thread()
        if self._busy():
            self.session.cancel()
            self._status_key = "status.cancelling"
            self._refresh_status()

    def _schedule_poll(self):
        self._poll_job = self.root.after(POLL_MS, self._poll)

    def _poll(self):
        self._require_ui_thread()
        self._poll_job = None
        session = self.session
        if session is None:
            return
        counts = session.poll()
        if counts:
            self._progress_targets = counts.get("targets", self._progress_targets)
            if self._status_key != "status.cancelling":
                self._status_key = "status.scanning"
            self._refresh_status()
        if session.finished:
            self._handle_final()
        else:
            self._schedule_poll()

    def _handle_final(self):
        final = self.session.final or {"outcome": "error", "result": None, "code": "worker_failed"}
        # Release the worker right away; already-sent locations keep draining.
        self.session.close(graceful=True)
        self.final = final
        self.result = None
        self.scan_result = None
        self._export_ready = False
        if final["outcome"] == "result":
            # Already strictly validated by the session's drain thread.
            self.scan_result, self.result, self._exit_code = final["result"]
            self._export_ready = bool(getattr(self.session, "export_ready", False))
        else:
            self._exit_code = 3 if final["outcome"] == "cancelled" else 4
        self._set_running(False)
        self._status_key = "status.done"
        self._refresh_status()
        self._refresh_outcome()
        self._render_result()

    def _set_running(self, running):
        state_when_running = "disabled" if running else "normal"
        for widget in (self.btn_add_files, self.btn_add_folder, self.btn_clear, self.btn_scan):
            widget.configure(state=state_when_running)
        self.btn_cancel.configure(state="normal" if running else "disabled")
        if running:
            self.btn_reveal.configure(state="disabled")
            self.btn_save.configure(state="disabled")
            self.progress.start(12)
        else:
            self.progress.stop()

    _status_key = "status.idle"
    _exit_code = None

    def _refresh_status(self):
        self.lbl_status.configure(text=self.t(self._status_key, targets=self._progress_targets))

    def _refresh_outcome(self):
        if self.final is None:
            self.lbl_outcome.configure(text="")
            self.lbl_summary.configure(text="")
            return
        key = OUTCOME_KEYS.get(self._exit_code, "outcome.error")
        code = self.final.get("code")
        if code is not None:
            code = session_error_code(code)
        elif self.result is not None:
            code = self.result["completeness"]
        else:
            code = "worker_failed"
        self.lbl_outcome.configure(text=self.t(key, code=code))
        if self.result is not None:
            self.lbl_summary.configure(text=self.t("label.summary", **summary_counts(self.result)))
        else:
            self.lbl_summary.configure(text="")

    def _render_result(self):
        self._cancel_render()
        self.tree.delete(*self.tree.get_children())
        self.issue_tree.delete(*self.issue_tree.get_children())
        if self.result is None:
            return
        self._render_issues()
        self.btn_save.configure(state="normal" if self._export_ready else "disabled")
        self._pending_rows = finding_rows(self.result, self.language)
        self._render_next_batch()

    def _render_issues(self):
        self.issue_tree.delete(*self.issue_tree.get_children())
        for row in issue_rows(self.result, self.language):
            self.issue_tree.insert("", "end", values=row)

    def _render_next_batch(self):
        """Insert findings in small batches so large results keep the UI live."""
        self._render_job = None
        rows = self._pending_rows
        batch, self._pending_rows = rows[:RENDER_BATCH], rows[RENDER_BATCH:]
        for row in batch:
            self.tree.insert("", "end", values=row)
        if self._pending_rows:
            self._render_job = self.root.after(1, self._render_next_batch)
        else:
            self.btn_reveal.configure(state="normal" if self.tree.get_children() else "disabled")

    def _cancel_render(self):
        self._pending_rows = []
        if self._render_job is not None:
            try:
                self.root.after_cancel(self._render_job)
            except self._tk.TclError:
                pass
            self._render_job = None

    _pending_rows = ()

    @property
    def rendering(self):
        return self._render_job is not None

    def _clear_result_scope(self):
        scan_id = getattr(self.scan_result, "scan_id", None)
        if isinstance(scan_id, str):
            try:
                from shareguard.safeio import clear_result_scopes

                clear_result_scopes(scan_id)
            except Exception:
                pass

    def _reset_results(self):
        """Drop results, the session and every remembered location."""
        if self.session is not None:
            self.session.close()
            self.session = None
        self.locations.clear()
        self._clear_result_scope()
        self.result = None
        self.scan_result = None
        self._export_ready = False
        self.final = None
        self._exit_code = None
        self._progress_targets = 0
        self._status_key = "status.idle"
        self._close_dialog()
        self._cancel_render()
        self.tree.delete(*self.tree.get_children())
        self.issue_tree.delete(*self.issue_tree.get_children())
        self.btn_reveal.configure(state="disabled")
        self.btn_save.configure(state="disabled")
        self._refresh_status()
        self._refresh_outcome()

    # -- reveal one location -------------------------------------------------

    def selected_target_id(self):
        selection = self.tree.selection()
        if len(selection) != 1:
            return None
        values = self.tree.item(selection[0], "values")
        return values[0] if values else None

    def on_reveal(self):
        self._require_ui_thread()
        from tkinter import messagebox

        target_id = self.selected_target_id()
        if not target_id:
            messagebox.showinfo(self.t("dlg.error_title"), self.t("dlg.no_finding_selected"), parent=self.root)
            return
        if not messagebox.askokcancel(
            self.t("dlg.reveal_title"), self.t("dlg.reveal_warning"), icon="warning", parent=self.root
        ):
            return
        self.reveal_location(target_id)

    def reveal_location(self, target_id):
        """Show one target's location in a read-only dialog (no clipboard use)."""
        self._require_ui_thread()
        from tkinter import messagebox

        location = self.locations.get(self.generation, target_id)
        if location is None:
            messagebox.showinfo(self.t("dlg.error_title"), self.t("dlg.reveal_unavailable"), parent=self.root)
            return None
        self._close_dialog()
        tk, ttk = self._tk, self._ttk
        path, member = location
        dialog = tk.Toplevel(self.root)
        dialog.title(self.t("dlg.location_title"))
        dialog.transient(self.root)
        dialog.configure(background=THEMES[self.theme]["bg"])
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill="both", expand=True)
        fields = [("dlg.location_path", path)]
        if member is not None:
            fields.append(("dlg.location_member", member))
        for key, value in fields:
            ttk.Label(frame, text=self.t(key)).pack(anchor="w")
            entry = ttk.Entry(frame, width=80)
            entry.insert(0, value)
            entry.configure(state="readonly")
            entry.pack(fill="x", pady=(0, 8))
        ttk.Button(frame, text=self.t("dlg.close"), command=self._close_dialog).pack(anchor="e")
        dialog.protocol("WM_DELETE_WINDOW", self._close_dialog)
        self._dialog = dialog
        return dialog

    def _close_dialog(self):
        if self._dialog is not None:
            try:
                self._dialog.destroy()
            except self._tk.TclError:
                pass
            self._dialog = None

    # -- export --------------------------------------------------------------

    def on_save(self):
        self._require_ui_thread()
        from tkinter import filedialog, messagebox

        if self.result is None:
            messagebox.showinfo(self.t("dlg.error_title"), self.t("dlg.no_result"), parent=self.root)
            return
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title=self.t("dlg.save_title"),
            defaultextension=".json",
            initialfile="shareguard-report.json",
            filetypes=[("JSON", "*.json")],
        )
        if not destination:
            return
        code = self.save_report(destination)
        if code is None:
            messagebox.showinfo(self.t("dlg.error_title"), self.t("dlg.saved"), parent=self.root)
        else:
            messagebox.showerror(self.t("dlg.error_title"), self.t("dlg.save_failed", code=code), parent=self.root)

    def save_report(self, destination):
        """Write the sanitized report; return ``None`` or a fixed error code."""
        self._require_ui_thread()
        if self.scan_result is None:
            return "NO_RESULT"
        if not self._export_ready:
            return "REPORT_IDENTITY_UNVERIFIED"
        try:
            from shareguard.safeio import write_report

            write_report(self.scan_result, destination, list(self.paths))
        except Exception as exc:
            return report_error_code(exc)
        return None

    # -- shutdown ------------------------------------------------------------

    def on_close(self):
        self._require_ui_thread()
        from tkinter import messagebox

        if self._busy() and not messagebox.askyesno(
            self.t("dlg.error_title"), self.t("dlg.quit_busy"), parent=self.root
        ):
            return
        self.shutdown()

    def shutdown(self):
        """Stop the worker, forget locations and paths, destroy the window."""
        if self._poll_job is not None:
            try:
                self.root.after_cancel(self._poll_job)
            except self._tk.TclError:
                pass
            self._poll_job = None
        self._cancel_render()
        session = self.session
        if session is not None:
            if self._busy():
                session.cancel()
            session.close()
            self.session = None
        self._closing_session = session
        self.locations.clear()
        self._clear_result_scope()
        self._export_ready = False
        self.paths = []
        self._close_dialog()
        try:
            self.root.destroy()
        except self._tk.TclError:
            pass

    def _require_ui_thread(self):
        if threading.current_thread() is not self._ui_thread:
            raise RuntimeError("Tk access off the UI thread")

    _closing_session = None

    def run(self):
        self.root.mainloop()
        # The window is gone; give the reaper a bounded moment to release the
        # app-owned worker before the interpreter exits.
        if self._closing_session is not None:
            self._closing_session.reaped.wait(SHUTDOWN_REAP_SECONDS)


def main(argv=None):
    """GUI entry point (safe for spawn and frozen executables)."""
    multiprocessing.freeze_support()
    app = ShareGuardApp()
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
