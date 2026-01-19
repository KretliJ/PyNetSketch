# 🛠️ PyNetSketch Troubleshooting Guide

This document lists the most common errors encountered during the development and execution of PyNetSketch across different operating systems.

## 🖥️ Graphical User Interface (Tkinter / GUI)

### 1. Window does not open on Linux (Display/X11 Error)

Symptom: `_tkinter.TclError: no display name and no $DISPLAY environment variable.`

Cause: Usually occurs when running the app with sudo directly within a Wayland or X11 session.
Solution:

Avoid running the entire GUI as root. Instead, grant specific capabilities to the Python binary:

```
sudo setcap cap_net_raw,cap_net_admin=eip ./.venv/bin/python3
./.venv/bin/python3 gui_app.py
```

## 📡 Packet Capture and Networking (Rust / Scapy)

### 2. Traffic Monitor showing 0 pps (Windows)

Symptom: The traffic graph does not move or displays an interface error.

Cause: Npcap driver not installed or "WinPcap Compatible Mode" is disabled.

Solution:

Inicialization should handle lack of drivers but if that did not happen, ensure Npcap is installed (nmap.org/npcap).

In the code, verify that the Friendly Name to GUID translation is correctly implemented in net_utils.py.

### 3. Socket Permission Error (Raw Sockets)

Symptom: `PermissionError: [Errno 1] Operation not permitted.`

Cause: Network operations such as ARP Scanning and Sniffing require elevated privileges.
Solution:

Linux: Use sudo setcap (recommended) or run the script with sudo.

Windows: Run your terminal (PowerShell/CMD) or IDE as Administrator.

## Core Compilation (Rust / Maturin)

### 4. error: linking with 'link.exe' failed (Windows)

Symptom: Failure while compiling the Rust core.

Cause: The compiler cannot find the Npcap SDK libraries.
Solution:

Ensure the Npcap SDK is extracted to C:\NpcapSDK or edit the chosen path to reflect the current location of the SDK.

In PowerShell, before running maturin, execute:

```
$env:LIB = "C:\NpcapSDK\Lib\x64;" + $env:LIB
```
or

```
$env:LIB = "C:\<location in the C drive>;" + $env:LIB
```
### 5. fatal error: `pcap.h: No such file or directory (Linux)`

Symptom: Rust fails to compile the pnet or libpcap dependency.

Cause: Missing libpcap development headers.
Solution:

Debian/Ubuntu: `sudo apt install libpcap-dev`

Fedora: `sudo dnf install libpcap-devel`

Arch Linux: `sudo pacman -S libpcap`

## 📦 Dependencies and Environment

### 6. Tkinter not found (Arch Linux / Fedora)

Symptom: `ModuleNotFoundError: No module named 'tkinter'.`

Cause: Some Linux distributions do not include the Tkinter module by default with the Python package.

Solution:

Arch: sudo pacman -S tk

Fedora: sudo dnf install python3-tkinter

Debian: sudo apt-get install python3-tkinter

### 7. Maturin fails in VENV

Symptom: `command 'maturin' not found.`

Cause: The package was not installed in the virtual environment or the venv is not active.

Solution:

Ensure the venv is active (`source .venv/bin/activate`).

Run `pip install maturin` inside the venv.

## 📝 Pro Tip: Debug Logs

If errors happens during execution, check the gen_log.txt file generated in the LOGS folder.
