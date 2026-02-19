"""
Ransomware Defense System - GUI Controller
Tkinter-based control panel to run system commands with live terminal output
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import os
import signal
import sys
import queue


# ─────────────────────────────────────────────
#  Colour & Style constants
# ─────────────────────────────────────────────
BG_DARK        = "#0d1117"
BG_PANEL       = "#161b22"
BG_TERMINAL    = "#0a0e14"
ACCENT_GREEN   = "#39d353"
ACCENT_RED     = "#f85149"
ACCENT_ORANGE  = "#e3b341"
ACCENT_BLUE    = "#58a6ff"
ACCENT_PURPLE  = "#bc8cff"
TEXT_PRIMARY   = "#c9d1d9"
TEXT_DIM       = "#6e7681"
BORDER_COLOR   = "#30363d"

BTN_MAIN_BG    = "#238636"
BTN_MAIN_FG    = "#ffffff"
BTN_MAIN_ACT   = "#2ea043"

BTN_SIM_BG     = "#9e6a03"
BTN_SIM_FG     = "#ffffff"
BTN_SIM_ACT    = "#b88205"

BTN_CLEAR_BG   = "#b62324"
BTN_CLEAR_FG   = "#ffffff"
BTN_CLEAR_ACT  = "#d1393a"

BTN_STOP_BG    = "#6e40c9"
BTN_STOP_FG    = "#ffffff"
BTN_STOP_ACT   = "#8957e5"

BTN_CHECK_BG   = "#1f6feb"
BTN_CHECK_FG   = "#ffffff"
BTN_CHECK_ACT  = "#388bfd"

FONT_MONO      = ("Courier New", 15)
FONT_MONO_SM   = ("Courier New", 13)
FONT_UI        = ("Segoe UI", 10)
FONT_UI_BOLD   = ("Segoe UI", 10, "bold")
FONT_TITLE     = ("Segoe UI", 15, "bold")
FONT_STATUS    = ("Segoe UI", 9)


# ─────────────────────────────────────────────
#  Helper: coloured tag definitions
# ─────────────────────────────────────────────
def _configure_tags(text_widget):
    text_widget.tag_configure("green",   foreground=ACCENT_GREEN)
    text_widget.tag_configure("red",     foreground=ACCENT_RED)
    text_widget.tag_configure("orange",  foreground=ACCENT_ORANGE)
    text_widget.tag_configure("blue",    foreground=ACCENT_BLUE)
    text_widget.tag_configure("purple",  foreground=ACCENT_PURPLE)
    text_widget.tag_configure("dim",     foreground=TEXT_DIM)
    text_widget.tag_configure("normal",  foreground=TEXT_PRIMARY)
    text_widget.tag_configure("bold",    foreground=TEXT_PRIMARY, font=("Courier New", 10, "bold"))


def _tag_for_line(line: str) -> str:
    """Pick a colour tag based on line content."""
    lo = line.lower()
    if any(k in lo for k in ("🚨", "critical", "attack detected", "ransomware")):
        return "red"
    if any(k in lo for k in ("✅", "success", "backed up", "unlocked", "created")):
        return "green"
    if any(k in lo for k in ("⚠️", "warning", "killing", "locked", "terminated")):
        return "orange"
    if any(k in lo for k in ("info", "starting", "monitoring", "🛡️")):
        return "blue"
    if any(k in lo for k in ("encrypted", "encrypt", "🎯", "💀", "🧪")):
        return "purple"
    if any(k in lo for k in ("error", "failed", "✗")):
        return "red"
    return "normal"


# ─────────────────────────────────────────────
#  ProcessRunner – runs a subprocess and
#  streams stdout/stderr to a queue
# ─────────────────────────────────────────────
class ProcessRunner:
    def __init__(self, cmd: list[str], log_queue: queue.Queue, cwd: str | None = None):
        self.cmd       = cmd
        self.log_queue = log_queue
        self.cwd       = cwd or os.getcwd()
        self.process   = None
        self._thread   = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self.process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=self.cwd,
            )
            for line in self.process.stdout:
                self.log_queue.put(("line", line.rstrip()))
            self.process.wait()
            rc = self.process.returncode
            self.log_queue.put(("done", rc))
        except FileNotFoundError as e:
            self.log_queue.put(("line", f"[ERROR] Command not found: {e}"))
            self.log_queue.put(("done", 1))
        except Exception as e:
            self.log_queue.put(("line", f"[ERROR] {e}"))
            self.log_queue.put(("done", 1))

    def stop(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
                self.process.wait(timeout=3)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None


# ─────────────────────────────────────────────
#  Main GUI Application
# ─────────────────────────────────────────────
class RansomwareGUI:
    def __init__(self, root: tk.Tk):
        self.root      = root
        self.root.title("🛡️  Ransomware Defense System — Control Panel")
        self.root.configure(bg=BG_DARK)
        self.root.minsize(900, 680)
        self.root.geometry("1050x750")

        # Running process handles
        self._main_runner    = None   # main.py process
        self._sim_runner     = None   # simulate_ransomware.py process

        # Separate log queues so each terminal stays independent
        self._main_queue     = queue.Queue()
        self._sim_queue      = queue.Queue()

        self._build_ui()
        self._poll_queues()   # start polling loop

    # ──────────────────────────────────────────
    #  UI construction
    # ──────────────────────────────────────────
    def _build_ui(self):
        # ── Title bar ──
        title_frame = tk.Frame(self.root, bg=BG_DARK)
        title_frame.pack(fill="x", padx=18, pady=(16, 0))

        tk.Label(
            title_frame,
            text="🛡️  Ransomware Defense System",
            bg=BG_DARK, fg=ACCENT_BLUE,
            font=FONT_TITLE,
        ).pack(side="left")

        self._global_status = tk.Label(
            title_frame,
            text="● IDLE",
            bg=BG_DARK, fg=TEXT_DIM,
            font=FONT_UI_BOLD,
        )
        self._global_status.pack(side="right", padx=6)

        ttk.Separator(self.root, orient="horizontal").pack(fill="x", padx=18, pady=10)

        # ── Button row ──
        btn_frame = tk.Frame(self.root, bg=BG_DARK)
        btn_frame.pack(fill="x", padx=18, pady=(0, 10))

        self._btn_main = self._make_button(
            btn_frame,
            "▶  Start Defense System\npython3 main.py",
            BTN_MAIN_BG, BTN_MAIN_FG, BTN_MAIN_ACT,
            self._start_main,
        )
        self._btn_main.pack(side="left", padx=(0, 8))

        self._btn_stop_main = self._make_button(
            btn_frame,
            "⏹  Stop Defense System",
            BTN_STOP_BG, BTN_STOP_FG, BTN_STOP_ACT,
            self._stop_main,
        )
        self._btn_stop_main.pack(side="left", padx=(0, 20))
        self._btn_stop_main.config(state="disabled")

        self._btn_sim = self._make_button(
            btn_frame,
            "🧪  Run Ransomware Simulation\npython3 simulate_ransomware.py --create-test-files",
            BTN_SIM_BG, BTN_SIM_FG, BTN_SIM_ACT,
            self._start_sim,
        )
        self._btn_sim.pack(side="left", padx=(0, 8))

        self._btn_stop_sim = self._make_button(
            btn_frame,
            "⏹  Stop Simulation",
            BTN_STOP_BG, BTN_STOP_FG, BTN_STOP_ACT,
            self._stop_sim,
        )
        self._btn_stop_sim.pack(side="left", padx=(0, 20))
        self._btn_stop_sim.config(state="disabled")

        self._btn_clear_dir = self._make_button(
            btn_frame,
            "🗑  Reset & Clear Directories\nchmod+rm+mkdir",
            BTN_CLEAR_BG, BTN_CLEAR_FG, BTN_CLEAR_ACT,
            self._clear_directories,
        )
        self._btn_clear_dir.pack(side="left", padx=(0, 8))

        self._btn_check_lock = self._make_button(
            btn_frame,
            "🔍  Check Folder Lock\nprotected_data status",
            BTN_CHECK_BG, BTN_CHECK_FG, BTN_CHECK_ACT,
            self._check_folder_lock,
        )
        self._btn_check_lock.pack(side="left")

        # ── Lock-status banner (hidden until first check) ──
        self._lock_banner_frame = tk.Frame(self.root, bg=BG_DARK)
        self._lock_banner_frame.pack(fill="x", padx=18, pady=(2, 4))
        self._lock_banner_inner = None   # built lazily on first check

        # ── Dual-terminal area ──
        pane = tk.PanedWindow(self.root, orient="horizontal", bg=BG_DARK, sashwidth=6, sashrelief="flat")
        pane.pack(fill="both", expand=True, padx=18, pady=(0, 14))

        self._main_term  = self._make_terminal(pane, "🛡️  Defense System Log  (main.py)", ACCENT_BLUE)
        self._sim_term   = self._make_terminal(pane, "🧪  Simulation Log  (simulate_ransomware.py)", ACCENT_ORANGE)

        pane.add(self._main_term["frame"], minsize=300)
        pane.add(self._sim_term["frame"],  minsize=300)

        # ── Status bar ──
        status_bar = tk.Frame(self.root, bg=BG_PANEL, height=26)
        status_bar.pack(fill="x", side="bottom")

        self._status_label = tk.Label(
            status_bar,
            text="  Ready — use the buttons above to control the system.",
            bg=BG_PANEL, fg=TEXT_DIM,
            font=FONT_STATUS, anchor="w",
        )
        self._status_label.pack(side="left", fill="x", padx=6)

        tk.Label(
            status_bar,
            text="Ransomware Defense System GUI  |  © 2025",
            bg=BG_PANEL, fg=TEXT_DIM,
            font=FONT_STATUS,
        ).pack(side="right", padx=6)

    # ──────────────────────────────────────────
    #  Widget helpers
    # ──────────────────────────────────────────
    def _make_button(self, parent, text, bg, fg, active_bg, command):
        btn = tk.Button(
            parent,
            text=text,
            bg=bg, fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=14, pady=8,
            font=FONT_UI_BOLD,
            cursor="hand2",
            command=command,
            justify="center",
            wraplength=200,
        )
        btn.bind("<Enter>", lambda e: btn.config(bg=active_bg))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg) if btn["state"] != "disabled" else None)
        return btn

    def _make_terminal(self, parent, title: str, accent: str) -> dict:
        frame = tk.Frame(parent, bg=BG_PANEL, bd=1, relief="flat",
                         highlightthickness=1, highlightbackground=BORDER_COLOR)

        # Header
        hdr = tk.Frame(frame, bg=BG_PANEL, pady=6)
        hdr.pack(fill="x", padx=8)

        tk.Label(hdr, text="●", bg=BG_PANEL, fg=accent, font=("Segoe UI", 12)).pack(side="left")
        tk.Label(hdr, text=f"  {title}", bg=BG_PANEL, fg=accent, font=FONT_UI_BOLD).pack(side="left")

        clear_btn = tk.Button(
            hdr, text="Clear", bg=BG_PANEL, fg=TEXT_DIM,
            relief="flat", bd=0, font=FONT_STATUS, cursor="hand2",
            activebackground=BORDER_COLOR, activeforeground=TEXT_PRIMARY,
        )
        clear_btn.pack(side="right", padx=4)

        ttk.Separator(frame, orient="horizontal").pack(fill="x")

        # Text widget
        txt = scrolledtext.ScrolledText(
            frame,
            bg=BG_TERMINAL, fg=TEXT_PRIMARY,
            insertbackground=TEXT_PRIMARY,
            font=FONT_MONO,
            relief="flat", bd=0,
            wrap="word",
            state="disabled",
        )
        txt.pack(fill="both", expand=True, padx=4, pady=4)
        _configure_tags(txt)

        clear_btn.config(command=lambda t=txt: self._clear_terminal(t))

        # Status strip
        strip = tk.Frame(frame, bg=BG_PANEL, height=22)
        strip.pack(fill="x")
        status_lbl = tk.Label(strip, text="Idle", bg=BG_PANEL, fg=TEXT_DIM, font=FONT_STATUS, anchor="w")
        status_lbl.pack(side="left", padx=8)

        return {"frame": frame, "text": txt, "status": status_lbl}

    # ──────────────────────────────────────────
    #  Terminal write helpers
    # ──────────────────────────────────────────
    def _clear_terminal(self, txt_widget):
        txt_widget.config(state="normal")
        txt_widget.delete("1.0", "end")
        txt_widget.config(state="disabled")

    def _append(self, terminal: dict, line: str, tag: str | None = None):
        txt = terminal["text"]
        txt.config(state="normal")
        tag = tag or _tag_for_line(line)
        txt.insert("end", line + "\n", tag)
        txt.see("end")
        txt.config(state="disabled")

    def _set_term_status(self, terminal: dict, msg: str, color: str = TEXT_DIM):
        terminal["status"].config(text=msg, fg=color)

    def _set_status(self, msg: str):
        self._status_label.config(text=f"  {msg}")

    # ──────────────────────────────────────────
    #  Queue polling (runs every 80 ms)
    # ──────────────────────────────────────────
    def _poll_queues(self):
        # main.py queue
        try:
            while True:
                kind, payload = self._main_queue.get_nowait()
                if kind == "line":
                    self._append(self._main_term, payload)
                elif kind == "done":
                    rc = payload
                    if rc == 0 or rc == -15:   # -15 = SIGTERM (normal stop)
                        self._append(self._main_term, f"\n[Process exited with code {rc}]", "dim")
                        self._set_term_status(self._main_term, "Stopped", TEXT_DIM)
                    else:
                        self._append(self._main_term, f"\n[Process exited with code {rc}]", "red")
                        self._set_term_status(self._main_term, f"Error (code {rc})", ACCENT_RED)
                    self._on_main_stopped()
        except queue.Empty:
            pass

        # simulator queue
        try:
            while True:
                kind, payload = self._sim_queue.get_nowait()
                if kind == "line":
                    self._append(self._sim_term, payload)
                elif kind == "lock_result":
                    self._render_lock_banner(payload)
                elif kind == "done":
                    rc = payload
                    if rc == 0 or rc == -15:
                        self._append(self._sim_term, f"\n[Process exited with code {rc}]", "dim")
                        self._set_term_status(self._sim_term, "Finished", ACCENT_GREEN)
                    else:
                        self._append(self._sim_term, f"\n[Process exited with code {rc}]", "red")
                        self._set_term_status(self._sim_term, f"Error (code {rc})", ACCENT_RED)
                    self._on_sim_stopped()
        except queue.Empty:
            pass

        self.root.after(80, self._poll_queues)

    # ──────────────────────────────────────────
    #  Button callbacks
    # ──────────────────────────────────────────
    def _start_main(self):
        if self._main_runner and self._main_runner.is_running():
            messagebox.showwarning("Already running", "Defense system is already running.")
            return

        self._clear_terminal(self._main_term["text"])
        self._append(self._main_term, "═" * 60, "dim")
        self._append(self._main_term, "  ▶  Starting: python3 main.py", "blue")
        self._append(self._main_term, "═" * 60, "dim")

        self._main_runner = ProcessRunner(
            ["python3", "main.py"],
            self._main_queue,
        )
        self._main_runner.start()

        self._btn_main.config(state="disabled", bg=TEXT_DIM)
        self._btn_stop_main.config(state="normal")
        self._set_term_status(self._main_term, "● Running", ACCENT_GREEN)
        self._global_status.config(text="● DEFENSE ACTIVE", fg=ACCENT_GREEN)
        self._set_status("Defense system started — monitoring file events...")

    def _stop_main(self):
        if self._main_runner:
            self._append(self._main_term, "\n[Sending stop signal…]", "orange")
            self._main_runner.stop()

    def _on_main_stopped(self):
        self._btn_main.config(state="normal", bg=BTN_MAIN_BG)
        self._btn_stop_main.config(state="disabled")
        self._global_status.config(text="● IDLE", fg=TEXT_DIM)
        self._set_status("Defense system stopped.")

    # ──────────────────────────────────
    def _start_sim(self):
        if self._sim_runner and self._sim_runner.is_running():
            messagebox.showwarning("Already running", "Simulation is already running.")
            return

        self._clear_terminal(self._sim_term["text"])
        self._append(self._sim_term, "═" * 60, "dim")
        self._append(self._sim_term, "  🧪  Starting: python3 simulate_ransomware.py --create-test-files", "orange")
        self._append(self._sim_term, "═" * 60, "dim")

        # Patch: provide auto-confirmed input so the script doesn't hang
        self._sim_runner = ProcessRunner(
            ["python3", "-c",
             "import subprocess, sys; "
             "p = subprocess.Popen("
             "['python3', 'simulate_ransomware.py', '--create-test-files'], "
             "stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True); "
             "p.stdin.write('\\n'); p.stdin.close(); "
             "[print(l, end='') for l in p.stdout]; p.wait(); sys.exit(p.returncode)"
            ],
            self._sim_queue,
        )
        self._sim_runner.start()

        self._btn_sim.config(state="disabled", bg=TEXT_DIM)
        self._btn_stop_sim.config(state="normal")
        self._set_term_status(self._sim_term, "● Running", ACCENT_ORANGE)
        self._set_status("Simulation running — watch the Defense System log for detections!")

    def _stop_sim(self):
        if self._sim_runner:
            self._append(self._sim_term, "\n[Sending stop signal…]", "orange")
            self._sim_runner.stop()

    def _on_sim_stopped(self):
        self._btn_sim.config(state="normal", bg=BTN_SIM_BG)
        self._btn_stop_sim.config(state="disabled")
        self._set_status("Simulation finished.")

    # ──────────────────────────────────
    def _clear_directories(self):
        confirm = messagebox.askyesno(
            "Confirm Reset",
            "This will:\n\n"
            "1. chmod -R u+w protected_data\n"
            "2. rm -rf protected_data backup logs\n"
            "3. mkdir protected_data\n\n"
            "Are you sure you want to reset all directories?",
        )
        if not confirm:
            return

        # Show output in sim terminal (neutral use)
        self._clear_terminal(self._sim_term["text"])
        self._append(self._sim_term, "═" * 60, "dim")
        self._append(self._sim_term, "  🗑  Resetting directories…", "red")
        self._append(self._sim_term, "═" * 60, "dim")

        def _run():
            cmds = [
                ["chmod", "-R", "u+w", "protected_data"],
                ["rm", "-rf", "protected_data", "backup", "logs"],
                ["mkdir", "protected_data"],
            ]
            for cmd in cmds:
                self._sim_queue.put(("line", f"$ {' '.join(cmd)}"))
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, cwd=os.getcwd()
                    )
                    if result.stdout.strip():
                        self._sim_queue.put(("line", result.stdout.strip()))
                    if result.returncode != 0 and result.stderr.strip():
                        self._sim_queue.put(("line", f"[stderr] {result.stderr.strip()}"))
                except FileNotFoundError:
                    self._sim_queue.put(("line", f"[ERROR] Command not found: {cmd[0]}"))

            self._sim_queue.put(("line", ""))
            self._sim_queue.put(("line", "✅ Directories reset successfully."))
            self._sim_queue.put(("done", 0))

        threading.Thread(target=_run, daemon=True).start()
        self._set_status("Resetting directories…")

    # ──────────────────────────────────────────
    #  Folder lock check
    # ──────────────────────────────────────────
    def _check_folder_lock(self):
        """
        Inspect the protected_data directory and every file inside it.
        Reports whether the folder itself and each file are locked (read-only)
        or writable, then renders a visual banner + detailed list in the sim terminal.
        """
        protected_dir = os.path.join(os.getcwd(), "protected_data")

        # ── Gather status data in a thread so UI stays responsive ──
        def _gather():
            results = {
                "dir_exists":   False,
                "dir_writable": None,
                "files":        [],          # list of (filename, is_writable)
                "locked_count": 0,
                "writable_count": 0,
            }

            if not os.path.isdir(protected_dir):
                self._sim_queue.put(("lock_result", results))
                return

            results["dir_exists"] = True
            results["dir_writable"] = os.access(protected_dir, os.W_OK)

            for root, dirs, files in os.walk(protected_dir):
                for fname in sorted(files):
                    fpath = os.path.join(root, fname)
                    try:
                        writable = os.access(fpath, os.W_OK)
                    except Exception:
                        writable = None
                    results["files"].append((fname, writable))
                    if writable is True:
                        results["writable_count"] += 1
                    else:
                        results["locked_count"] += 1

            self._sim_queue.put(("lock_result", results))

        threading.Thread(target=_gather, daemon=True).start()
        self._set_status("Checking folder lock status…")

    def _render_lock_banner(self, results: dict):
        """Draw / redraw the lock-status banner and log details to the sim terminal."""

        # ── Clear old banner contents ──
        for widget in self._lock_banner_frame.winfo_children():
            widget.destroy()

        protected_dir = os.path.join(os.getcwd(), "protected_data")

        if not results["dir_exists"]:
            # Folder missing
            banner = tk.Frame(self._lock_banner_frame, bg="#3d1a1a",
                              highlightthickness=1, highlightbackground=ACCENT_RED, pady=6)
            banner.pack(fill="x")
            tk.Label(banner, text="  ❌  protected_data  →  FOLDER DOES NOT EXIST",
                     bg="#3d1a1a", fg=ACCENT_RED, font=FONT_UI_BOLD).pack(side="left", padx=10)
            self._set_status("protected_data folder not found.")
            self._append(self._sim_term, "❌  protected_data directory does not exist.", "red")
            return

        dir_locked   = not results["dir_writable"]
        total        = len(results["files"])
        locked_count = results["locked_count"]
        write_count  = results["writable_count"]

        if dir_locked and locked_count == total and total > 0:
            # Fully locked
            bg_col    = "#1a1a0d"
            bd_col    = ACCENT_ORANGE
            icon      = "🔒"
            headline  = f"LOCKED — directory & all {total} file(s) are read-only"
            lbl_color = ACCENT_ORANGE
            status_msg = f"🔒 Folder is LOCKED — {locked_count}/{total} files read-only."
        elif not dir_locked and write_count == total:
            # Fully writable
            bg_col    = "#0d1f0d"
            bd_col    = ACCENT_GREEN
            icon      = "🔓"
            headline  = f"UNLOCKED — directory & all {total} file(s) are writable"
            lbl_color = ACCENT_GREEN
            status_msg = f"🔓 Folder is UNLOCKED — all {total} files writable."
        else:
            # Mixed
            bg_col    = "#1a1200"
            bd_col    = ACCENT_ORANGE
            icon      = "⚠️"
            headline  = (f"PARTIAL — dir {'read-only' if dir_locked else 'writable'}  |  "
                         f"{locked_count} locked / {write_count} writable  ({total} total)")
            lbl_color = ACCENT_ORANGE
            status_msg = f"⚠️  Mixed state — {locked_count} locked, {write_count} writable."

        # Banner row
        banner = tk.Frame(self._lock_banner_frame, bg=bg_col,
                          highlightthickness=1, highlightbackground=bd_col, pady=5)
        banner.pack(fill="x")

        tk.Label(banner, text=f"  {icon}  protected_data  →  {headline}",
                 bg=bg_col, fg=lbl_color, font=FONT_UI_BOLD).pack(side="left", padx=10)
        tk.Label(banner, text=f"📁 {protected_dir}",
                 bg=bg_col, fg=TEXT_DIM, font=FONT_STATUS).pack(side="right", padx=10)

        # File breakdown sub-row
        detail_frame = tk.Frame(self._lock_banner_frame, bg=BG_PANEL)
        detail_frame.pack(fill="x", pady=(1, 0))

        if results["files"]:
            cols = 4
            for i, (fname, writable) in enumerate(results["files"]):
                state_icon  = "🔒" if not writable else "🔓"
                state_color = ACCENT_ORANGE if not writable else ACCENT_GREEN
                cell = tk.Frame(detail_frame, bg=BG_PANEL)
                cell.grid(row=i // cols, column=i % cols, sticky="w", padx=6, pady=1)
                tk.Label(cell, text=state_icon, bg=BG_PANEL, fg=state_color,
                         font=FONT_STATUS).pack(side="left")
                tk.Label(cell, text=f" {fname}", bg=BG_PANEL, fg=TEXT_PRIMARY,
                         font=FONT_MONO_SM).pack(side="left")
        else:
            tk.Label(detail_frame, text="  (no files found in directory)",
                     bg=BG_PANEL, fg=TEXT_DIM, font=FONT_STATUS).pack(side="left", padx=8, pady=2)

        # ── Also log to sim terminal ──
        self._append(self._sim_term, "═" * 60, "dim")
        self._append(self._sim_term, f"  🔍  Folder Lock Check  —  {protected_dir}", "blue")
        self._append(self._sim_term, "═" * 60, "dim")
        self._append(self._sim_term,
                     f"  Directory  : {'READ-ONLY 🔒' if dir_locked else 'WRITABLE 🔓'}",
                     "orange" if dir_locked else "green")
        self._append(self._sim_term, f"  Total files : {total}", "normal")
        self._append(self._sim_term,
                     f"  Locked      : {locked_count}",
                     "orange" if locked_count else "dim")
        self._append(self._sim_term,
                     f"  Writable    : {write_count}",
                     "green" if write_count else "dim")
        self._append(self._sim_term, "", "dim")
        for fname, writable in results["files"]:
            icon2  = "🔒" if not writable else "🔓"
            color2 = "orange" if not writable else "green"
            self._append(self._sim_term, f"  {icon2}  {fname}", color2)
        self._append(self._sim_term, "═" * 60, "dim")

        self._set_status(status_msg)

    # ──────────────────────────────────────────
    #  Cleanup on window close
    # ──────────────────────────────────────────
    def on_close(self):
        if self._main_runner:
            self._main_runner.stop()
        if self._sim_runner:
            self._sim_runner.stop()
        self.root.destroy()


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    root = tk.Tk()
    app  = RansomwareGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
