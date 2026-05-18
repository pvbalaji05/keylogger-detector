# ================================================================
#   SIMPLE KEYLOGGER DETECTOR
#   Educational Cybersecurity Tool — Detection & Awareness Only
#   Author  : Balaji PV
#   Purpose : Detect suspicious processes that may indicate
#             keylogging activity on the system.
#
#   DISCLAIMER: This project is developed ONLY for educational
#   and defensive cybersecurity purposes. It does NOT create,
#   install, or use any keylogger. It only reads the list of
#   running processes — the same way Task Manager does.
# ================================================================

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import psutil          # For reading running processes
import os              # For file paths and logging
import threading       # For running the scan in the background
import datetime        # For timestamps in logs
import logging         # For saving scan results to a file


# ================================================================
# SECTION 1 — CONFIGURATION
# Known suspicious process names commonly linked to keyloggers.
# This list is for EDUCATIONAL awareness only.
# ================================================================

SUSPICIOUS_PROCESSES = [
    # Generic keylogger / spy tools
    "keylogger", "klogger", "spyware", "spy", "hook",
    "winspy", "spyrix", "refog", "revealer", "ardamax",
    "actual keylogger", "kidlogger", "pykeylogger",
    "logkeys", "xlogger", "elite keylogger",
    # Remote access tools that can include keylogging
    "remcos", "njrat", "darkcomet", "blackshades",
    "netwire", "orcus", "imminent monitor",
    # Screen / activity recorders sometimes misused
    "screenlogger", "inputmapper",
    # Common test / demo keylogger names
    "test_keylogger", "keylog", "key_log",
]

# Processes that are always safe — never flag these
WHITELIST = [
    "explorer.exe", "svchost.exe", "system", "registry",
    "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "taskmgr.exe", "python.exe",
    "python3.exe", "code.exe", "notepad.exe", "chrome.exe",
    "firefox.exe", "msedge.exe",
]

# ================================================================
# SECTION 2 — LOGGING SETUP
# Saves scan results to a log file in the same folder as the script
# ================================================================

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_log.txt")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


# ================================================================
# SECTION 3 — DETECTION LOGIC
# Scans all running processes and flags suspicious ones.
# ================================================================

def scan_processes():
    """
    Reads all running processes using psutil.
    Returns two lists:
      - suspicious : processes that match known keylogger names
      - all_procs  : every running process with its details
    """
    suspicious = []
    all_procs  = []

    for proc in psutil.process_iter(['pid', 'name', 'status']):
        try:
            pid    = proc.info['pid']
            name   = proc.info['name'] or "Unknown"
            status = proc.info['status'] or "unknown"

            # Check if process name matches any suspicious keyword
            name_lower = name.lower()
            is_suspicious = any(
                bad in name_lower for bad in SUSPICIOUS_PROCESSES
            ) and name_lower not in [w.lower() for w in WHITELIST]

            proc_data = {
                "pid":    pid,
                "name":   name,
                "status": status,
                "flag":   "⚠ SUSPICIOUS" if is_suspicious else "✓ Safe",
            }

            all_procs.append(proc_data)
            if is_suspicious:
                suspicious.append(proc_data)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process ended or we don't have permission — skip it
            continue

    return suspicious, all_procs


# ================================================================
# SECTION 4 — MAIN GUI APPLICATION
# ================================================================

class KeyloggerDetectorApp:
    """
    The main application window built with Tkinter.
    Cybersecurity-themed dark UI with neon green accents.
    """

    # ── Color palette ──────────────────────────────────────────
    BG          = "#0a0e17"   # Deep navy black — main background
    BG2         = "#0f1623"   # Slightly lighter — card background
    BG3         = "#1a2233"   # Panel background
    ACCENT      = "#00ff88"   # Neon green — primary accent
    ACCENT2     = "#00cfff"   # Cyan — secondary accent
    DANGER      = "#ff4444"   # Red — suspicious alert
    TEXT        = "#e0e6f0"   # Light grey — body text
    TEXT_DIM    = "#5a6a80"   # Dimmed text
    FONT_MONO   = ("Courier New", 10)
    FONT_HEAD   = ("Courier New", 18, "bold")
    FONT_SUB    = ("Courier New", 11)
    FONT_BTN    = ("Courier New", 10, "bold")
    FONT_SMALL  = ("Courier New", 9)

    def __init__(self, root):
        self.root = root
        self._build_window()
        self._build_header()
        self._build_status_bar()
        self._build_controls()
        self._build_table()
        self._build_log_panel()
        self._build_footer()
        self.log_message("System ready. Click 'SCAN SYSTEM' to begin.", "info")

    # ── Window setup ───────────────────────────────────────────
    def _build_window(self):
        self.root.title("Keylogger Detector  |  Balaji PV")
        self.root.geometry("980x720")
        self.root.minsize(800, 600)
        self.root.configure(bg=self.BG)
        self.root.resizable(True, True)

    # ── Header ─────────────────────────────────────────────────
    def _build_header(self):
        header = tk.Frame(self.root, bg=self.BG, pady=12)
        header.pack(fill="x", padx=20)

        # Blinking dot indicator
        self.dot_color = tk.StringVar(value=self.ACCENT)
        self.dot = tk.Label(header, text="●", font=("Courier New", 22),
                            bg=self.BG, fg=self.ACCENT)
        self.dot.pack(side="left", padx=(0, 10))
        self._blink_dot()

        # Title
        tk.Label(header, text="KEYLOGGER DETECTOR",
                 font=self.FONT_HEAD, bg=self.BG, fg=self.ACCENT).pack(side="left")

        # Sub-label on the right
        tk.Label(header, text="[ DEFENSIVE SECURITY TOOL ]",
                 font=self.FONT_SMALL, bg=self.BG, fg=self.TEXT_DIM).pack(side="right")

        # Divider line
        tk.Frame(self.root, bg=self.ACCENT, height=1).pack(fill="x", padx=20)

    def _blink_dot(self):
        """Makes the green dot blink to simulate a live indicator."""
        current = self.dot.cget("fg")
        self.dot.config(fg=self.ACCENT if current == self.BG else self.BG)
        self.root.after(800, self._blink_dot)

    # ── Status bar (Safe / Warning) ────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=self.BG3, pady=8, padx=20)
        bar.pack(fill="x", padx=20, pady=(10, 0))

        tk.Label(bar, text="STATUS:", font=self.FONT_SMALL,
                 bg=self.BG3, fg=self.TEXT_DIM).pack(side="left")

        self.status_label = tk.Label(bar, text="  ●  IDLE — NOT SCANNED YET",
                                     font=("Courier New", 11, "bold"),
                                     bg=self.BG3, fg=self.ACCENT2)
        self.status_label.pack(side="left", padx=8)

        # Scan counter on the right
        self.scan_count = 0
        self.scan_label = tk.Label(bar, text="Scans: 0",
                                   font=self.FONT_SMALL, bg=self.BG3, fg=self.TEXT_DIM)
        self.scan_label.pack(side="right")

    # ── Control buttons ────────────────────────────────────────
    def _build_controls(self):
        ctrl = tk.Frame(self.root, bg=self.BG, pady=10)
        ctrl.pack(fill="x", padx=20)

        btn_cfg = dict(font=self.FONT_BTN, relief="flat",
                       cursor="hand2", padx=20, pady=8)

        # SCAN button
        self.scan_btn = tk.Button(
            ctrl, text="⬡  SCAN SYSTEM",
            bg=self.ACCENT, fg=self.BG,
            activebackground="#00cc66", activeforeground=self.BG,
            command=self._start_scan, **btn_cfg
        )
        self.scan_btn.pack(side="left", padx=(0, 10))

        # REFRESH button
        tk.Button(
            ctrl, text="↺  REFRESH",
            bg=self.BG3, fg=self.ACCENT2,
            activebackground=self.BG2, activeforeground=self.ACCENT2,
            command=self._start_scan, **btn_cfg
        ).pack(side="left", padx=(0, 10))

        # CLEAR LOG button
        tk.Button(
            ctrl, text="✕  CLEAR LOG",
            bg=self.BG3, fg=self.TEXT_DIM,
            activebackground=self.BG2, activeforeground=self.TEXT,
            command=self._clear_log, **btn_cfg
        ).pack(side="left")

        # Filter toggle
        self.show_all = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ctrl, text=" Show all processes",
            variable=self.show_all,
            bg=self.BG, fg=self.TEXT_DIM,
            selectcolor=self.BG3,
            activebackground=self.BG,
            font=self.FONT_SMALL,
            command=self._refresh_table
        ).pack(side="right")

        tk.Label(ctrl, text="Filter:", font=self.FONT_SMALL,
                 bg=self.BG, fg=self.TEXT_DIM).pack(side="right", padx=(0, 4))

    # ── Results table ──────────────────────────────────────────
    def _build_table(self):
        frame = tk.Frame(self.root, bg=self.BG, padx=20)
        frame.pack(fill="both", expand=True, pady=(0, 5))

        tk.Label(frame, text="RUNNING PROCESSES",
                 font=self.FONT_SMALL, bg=self.BG, fg=self.TEXT_DIM,
                 anchor="w").pack(fill="x", pady=(0, 4))

        # Style the Treeview (table widget)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Cyber.Treeview",
                         background=self.BG2,
                         foreground=self.TEXT,
                         fieldbackground=self.BG2,
                         rowheight=26,
                         font=self.FONT_MONO,
                         borderwidth=0)
        style.configure("Cyber.Treeview.Heading",
                         background=self.BG3,
                         foreground=self.ACCENT,
                         font=("Courier New", 10, "bold"),
                         relief="flat")
        style.map("Cyber.Treeview",
                  background=[("selected", "#1a3a2a")])

        # Table columns
        cols = ("PID", "Process Name", "Status", "Security")
        self.tree = ttk.Treeview(frame, columns=cols, show="headings",
                                  style="Cyber.Treeview")

        self.tree.heading("PID",          text="PID")
        self.tree.heading("Process Name", text="PROCESS NAME")
        self.tree.heading("Status",       text="STATUS")
        self.tree.heading("Security",     text="SECURITY CHECK")

        self.tree.column("PID",          width=70,  anchor="center")
        self.tree.column("Process Name", width=320, anchor="w")
        self.tree.column("Status",       width=120, anchor="center")
        self.tree.column("Security",     width=180, anchor="center")

        # Scrollbar
        sb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Row colour tags
        self.tree.tag_configure("suspicious", foreground=self.DANGER)
        self.tree.tag_configure("safe",       foreground=self.TEXT)

        # Store last scan results for filter toggle
        self._last_suspicious = []
        self._last_all         = []

    # ── Log panel ──────────────────────────────────────────────
    def _build_log_panel(self):
        frame = tk.Frame(self.root, bg=self.BG, padx=20)
        frame.pack(fill="x", pady=(0, 5))

        tk.Label(frame, text="SCAN LOG",
                 font=self.FONT_SMALL, bg=self.BG, fg=self.TEXT_DIM,
                 anchor="w").pack(fill="x")

        self.log_box = scrolledtext.ScrolledText(
            frame, height=6, bg=self.BG2, fg=self.ACCENT,
            font=self.FONT_SMALL, relief="flat",
            insertbackground=self.ACCENT, state="disabled",
            wrap="word"
        )
        self.log_box.pack(fill="x")

        # Tag colours for different log levels
        self.log_box.tag_config("info",    foreground=self.ACCENT2)
        self.log_box.tag_config("warn",    foreground="#ffaa00")
        self.log_box.tag_config("danger",  foreground=self.DANGER)
        self.log_box.tag_config("success", foreground=self.ACCENT)
        self.log_box.tag_config("dim",     foreground=self.TEXT_DIM)

    # ── Footer ─────────────────────────────────────────────────
    def _build_footer(self):
        tk.Frame(self.root, bg=self.ACCENT, height=1).pack(fill="x", padx=20)
        footer = tk.Frame(self.root, bg=self.BG, pady=6)
        footer.pack(fill="x", padx=20)
        tk.Label(footer,
                 text="⚠  For educational & defensive cybersecurity purposes only  |  Balaji PV  |  2025",
                 font=self.FONT_SMALL, bg=self.BG, fg=self.TEXT_DIM).pack()

    # ================================================================
    # SECTION 5 — SCAN LOGIC (runs in a background thread)
    # ================================================================

    def _start_scan(self):
        """Launches the scan in a separate thread so the UI stays responsive."""
        self.scan_btn.config(state="disabled", text="⬡  SCANNING...")
        self._set_status("SCANNING...", self.ACCENT2)
        self.log_message("Starting system scan...", "info")
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self):
        """The actual scan — runs off the main thread."""
        try:
            suspicious, all_procs = scan_processes()

            # Update counts and store results
            self._last_suspicious = suspicious
            self._last_all        = all_procs
            self.scan_count      += 1

            # Schedule UI updates on the main thread
            self.root.after(0, self._update_ui, suspicious, all_procs)

        except Exception as e:
            self.root.after(0, self.log_message,
                            f"Scan error: {str(e)}", "danger")
            self.root.after(0, self.scan_btn.config,
                            {"state": "normal", "text": "⬡  SCAN SYSTEM"})

    def _update_ui(self, suspicious, all_procs):
        """Updates the table and status after a scan completes."""
        self._refresh_table()

        total     = len(all_procs)
        sus_count = len(suspicious)

        self.scan_label.config(text=f"Scans: {self.scan_count}")

        if sus_count == 0:
            self._set_status("●  SYSTEM CLEAN — No threats detected", self.ACCENT)
            self.log_message(
                f"Scan complete. {total} processes checked. No suspicious activity found.",
                "success"
            )
            logging.info(f"Scan #{self.scan_count}: {total} processes — CLEAN")
        else:
            self._set_status(
                f"⚠  WARNING — {sus_count} suspicious process(es) found!", self.DANGER
            )
            self.log_message(
                f"Scan complete. {total} processes checked. "
                f"⚠ {sus_count} SUSPICIOUS process(es) detected!", "danger"
            )
            for p in suspicious:
                self.log_message(
                    f"  → PID {p['pid']} | {p['name']} | {p['status']}", "warn"
                )
                logging.warning(
                    f"Scan #{self.scan_count}: SUSPICIOUS | PID {p['pid']} | {p['name']}"
                )
            # Show alert popup
            messagebox.showwarning(
                "⚠ Suspicious Activity Detected",
                f"{sus_count} suspicious process(es) found!\n\n"
                + "\n".join(f"• {p['name']}  (PID {p['pid']})" for p in suspicious)
                + "\n\nRecommendation: Investigate these processes immediately."
            )

        self.scan_btn.config(state="normal", text="⬡  SCAN SYSTEM")

    def _refresh_table(self):
        """Clears and repopulates the table based on the current filter."""
        for row in self.tree.get_children():
            self.tree.delete(row)

        procs = self._last_all if self.show_all.get() else self._last_suspicious

        for p in procs:
            tag = "suspicious" if "SUSPICIOUS" in p["flag"] else "safe"
            self.tree.insert("", "end",
                             values=(p["pid"], p["name"], p["status"], p["flag"]),
                             tags=(tag,))

    # ================================================================
    # SECTION 6 — HELPER METHODS
    # ================================================================

    def _set_status(self, text, color):
        self.status_label.config(text=f"  {text}", fg=color)

    def log_message(self, msg, level="info"):
        """Appends a timestamped message to the on-screen log panel."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_box.config(state="normal")
        self.log_box.insert("end", f"[{ts}] ", "dim")
        self.log_box.insert("end", f"{msg}\n", level)
        self.log_box.see("end")
        self.log_box.config(state="disabled")

    def _clear_log(self):
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")
        self.log_message("Log cleared.", "dim")


# ================================================================
# SECTION 7 — ENTRY POINT
# ================================================================

if __name__ == "__main__":
    root = tk.Tk()
    app  = KeyloggerDetectorApp(root)
    root.mainloop()
