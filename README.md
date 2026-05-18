Simple Keylogger Detector

> **Educational & Defensive Cybersecurity Tool**
> This project is developed ONLY for educational and defensive cybersecurity purposes.
> It does NOT create, install, or use any keylogger.

---

What Is This?

A lightweight Python desktop application that scans your running processes and flags any that match known keylogger-related names. Think of it as a simplified, educational version of what antivirus software does — built from scratch in Python.

---

Features

| Feature | Description |
|---|---|
| Scan System | Reads all running processes using `psutil` |
| Refresh | Re-runs the scan with one click |
| Indicator | Marks each process as Safe or Suspicious |
| Process Table | Shows PID, Name, Status, and Security tag |
| Scan Log | Real-time timestamped log panel inside the app |
| Log File | Saves every scan result to `scan_log.txt` |
| Alert Popup | Warning dialog if suspicious processes are found |
| Filter Toggle | Switch between showing all vs suspicious-only |
| Dark UI | Cybersecurity-themed dark interface with neon accents |

---

## Screenshots

```
╔══════════════════════════════════════════╗
║  ● KEYLOGGER DETECTOR  [ DEFENSIVE ]     ║
╠══════════════════════════════════════════╣
║  STATUS: ● SYSTEM CLEAN                 ║
║  [⬡ SCAN SYSTEM]  [↺ REFRESH]           ║
╠══════════════════════════════════════════╣
║  PID  │ PROCESS NAME │ STATUS │ SECURITY ║
║  1234 │ explorer.exe │ running│ ✓ Safe   ║
║  5678 │ chrome.exe   │ running│ ✓ Safe   ║
╚══════════════════════════════════════════╝
```

---

## Installation & Setup

### Step 1 — Make sure Python is installed
Download from [python.org](https://python.org) if needed.
```bash
python --version
```

### Step 2 — Install the only external library
```bash
pip install psutil
```
> `tkinter` comes built-in with Python — no extra install needed.

### Step 3 — Run the application
```bash
python keylogger_detector.py
```

---

## Project Structure

```
keylogger-detector/
│
├── keylogger_detector.py   ← Main application (all code here)
├── scan_log.txt            ← Auto-created after first scan
└── README.md               ← This file
```

---

## How It Works

```
User clicks "SCAN SYSTEM"
        ↓
Background thread starts (UI stays responsive)
        ↓
psutil.process_iter() reads all running processes
        ↓
Each process name is checked against SUSPICIOUS_PROCESSES list
        ↓
Whitelisted safe processes are excluded
        ↓
Results are displayed in the table
        ↓
If suspicious found → Alert popup + Warning log entry
If all clear → "System Clean" status shown
        ↓
Results saved to scan_log.txt
```

---

## Detection Logic Explained

The tool checks each process name against a hardcoded list of strings commonly found in keylogger tool names:

```python
SUSPICIOUS_PROCESSES = [
    "keylogger", "klogger", "spyware", "ardamax",
    "refog", "revealer", "remcos", "njrat", ...
]
```

It uses simple **substring matching** — if a process name *contains* any of those keywords, it's flagged. Known safe system processes are whitelisted and always skipped.

> **Limitation:** This is educational logic only. Real keyloggers use obfuscated names, rootkits, or DLL injection and would NOT be caught this way. For real protection, use a proper antivirus/EDR solution.

---

## Python Libraries Used

| Library | Purpose | Built-in? |
|---|---|---|
| `psutil` | Read system processes |  Install needed |
| `tkinter` | GUI / UI window | Built-in |
| `threading` | Background scan (non-blocking) | Built-in |
| `logging` | Save results to log file |  Built-in |
| `os` | File paths | Built-in |
| `datetime` | Timestamps in logs |  Built-in |

---

## What You Learn From This Project

- Reading system processes programmatically with `psutil`
- Building a desktop GUI with `tkinter`
- Using threads to keep the UI responsive during heavy tasks
- Writing logs with Python's `logging` module
- Basic pattern matching for threat detection
- Cybersecurity awareness about keylogger indicators

---

##  Disclaimer

This tool is built **strictly for learning and defensive awareness**.
It does not:
- Record keystrokes
- Install any monitoring software
- Access any private data

It only reads the public list of running processes — exactly like Windows Task Manager.

---

##  Author

**Balaji PV**
- GitHub: [@pvbalaji05](https://github.com/pvbalaji05)
- LinkedIn: [balaji-pv](https://www.linkedin.com/in/balaji-pv-844274362)

---

© 2025 Balaji PV — Educational Cybersecurity Project
