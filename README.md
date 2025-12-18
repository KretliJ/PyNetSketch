<img alt="LogoPNS" src="https://github.com/KretliJ/PyNetSketch/blob/main/assets/app_icon.png">

# PyNetSketch 📡

**PyNetSketch** is a robust, Python-based network management and reconnaissance tool designed as a **Software Engineering Thesis** and Proof of Concept (PoC).

It demonstrates advanced architectural patterns by featuring a Hybrid Engine that combines a flexible Python frontend (Tkinter) with a high-performance Rust core for critical I/O operations. The project is designed to bridge the gap between abstract network theory and visual understanding.

> **Note:** This project serves as an academic case study in Systems Integration, FFI (Foreign Function Interface), and Concurrency Patterns.

## 🌟 Key Features

* **Hybrid Engine (Python + Rust):** Critical tasks (Port Scanning, Traffic Sniffing, TCP Connect) are offloaded to a compiled Rust core via PyO3, ensuring near-native performance while maintaining Python's ease of development.
* **Modular Architecture (Refactored v1.5):** The codebase follows strict Separation of Concerns (SoC), decoupling Network Logic (`net_utils`), User Interface (`interface/`), and Server Control (`host_functions`).
* **Differential Traffic Monitor:**
    * Real-time visualization of network throughput using Rust (pnet) for packet capture.
    * Visualizing "Total Traffic" vs. "Filtered Traffic" (isolate a specific IP's bandwidth usage against the network noise).
    * Implements threaded callbacks with GIL release strategies to prevent UI starvation during high-load sniffing.
* **Multi-Mode Scanning:**
    * **Ping Host:** Smart availability check (ICMP -> TCP Fallback).
    * **Trace Route:** TCP-SYN based traceroute with "Hidden Node" detection.
    * **ARP Table Scan:** Fast local subnet discovery with MAC Vendor resolution.
* **Visual Topology Mapper:** Generates a dynamic "hub-and-spoke" diagram of subnets and devices.
* **Distributed Mode:** Acts as a Probe Server for the PyNetSketch Mobile Companion app.

## 🛠️ Modes

* 🖥️ **Standalone (GUI):** The classic desktop experience. Runs the modular Tkinter GUI locally.
    * **Best for:** Deep diagnostics, traffic analysis, and visualization.

* 📡 **Server (Remote Probe):** Turns the machine into a headless network probe.
    * **Auto-Discovery:** Broadcasts presence via UDP.
    * **Remote Control:** Accepts JSON commands via TCP sockets from mobile clients.
    * **Hardware Abstraction:** Allows mobile devices to execute raw socket operations (like ARP scans) by proxying through the PC.

## 📂 Project Structure (v1.6)

The project adheres to a modular design pattern:

* `gui_app.py`: **Main Controller**. Initializes the app and orchestrates modules.
* `rust_src/`: **Rust Core**. Contains the `pynetsketch_core` source code for high-performance sniffing and scanning.
* `interface/`: **View Layer**.
    * `scanner_tab.py`: Treeview logic for ARP results.
    * `traffic_tab.py`: Graph rendering and IP filtering logic.
    * `topology_tab.py`: Canvas drawing logic for network maps.
    * `server_mode.py`: UI for the Probe Server mode.
    * `startup_screen.py`: View Layer. Handles the threaded loading sequence and visual startup feedback.
* `net_utils.py`: **Model / Middleware**. Handles logic adaptation, Scapy fallback, and FFI calls to Rust.
* `host_functions.py`: Server logic for the mobile companion.
* `utils.py`: Thread management (`run_in_background`) and logging.

## 🛠️ Prerequisites

* **Python 3.11+**
* **Rust Toolchain** (for compiling the core): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

## 📦 Installation & Compilation for Development

### 🐧 Linux (Debian/Ubuntu/Kali)

* libpcap headers: Required for compiling the Rust core packet capture features.
```
sudo apt-get install libpcap-dev
```

### 🪟 Windows
* **Npcap Driver:** Download from [nmap.org/npcap](https://nmap.org/npcap/). Though this chack is handled during the startup cycle
* **Npcap SDK:** To compile the Rust core, download the **Npcap SDK** and set the `LIB` environment variable to point to `Packet.lib`. Extract in a known folder (C:\NpcapSDK)

### 1: Configure venv 

**Linux**
```
python3 -m venv .venv
source .venv/bin/activate
```
**Windows**
```
python -m venv .venv
.\.venv\Scripts\activate
```
### 2: Install dependencies
```
pip install scapy requests pillow maturin
```
### 3: Compile Rust core
**Linux**
```
cd rust_src
maturin develop --release
cd ..
```
**Windows**
```
$env:LIB = "C:\NpcapSDK\Lib\x64;" + $env:LIB # Ignore if already in PATH
cd rust_src
maturin develop --release
cd ..
```
### 4: Execute
**Linux**
```
# Point to the venv python executable to ensure dependencies are found
sudo ./.venv/bin/python gui_app.py
```
**Windows**
```
python gui_app.py
```

## 🛠️ Version History

<details>
<summary><strong>v.1.X - Early Engineering</strong></summary>
   
* **v1.0 - v1.2:** Basic Monolithic Prototyping.
* **v1.3** Rust Integration (Hybrid Engine).
* **v1.4** Distributed Server Mode & Mobile Protocol.
* **v1.5** Pre-release executable, fixes and error documentation.
* **v1.6 (Thesis Milestone 1 - Modularization and Interfacing):**
    * **Refactoring:** Full GUI modularization.
    * **Performance:** Implemented threaded Rust Sniffer with GIL release (fixed freezing).
    * **Feature:** Differential Traffic Filtering.
    * **Fix:** Solved Windows Interface Name mismatch (Adapter Pattern).
* **v1.7 (Thesis Milestone 2 - Stability):**
    * **Concurrency:** Implemented Bidirectional Control Channel for Rust Sniffer (Non-blocking I/O cancellation <1s).
    * **Optimization:** Added "Subnet Chunking" strategy for large network scans (eliminating Atomic Scapy freezes).
    * **Performance:** Threaded Rust Sniffer with GIL release and Differential Traffic Filtering.
* **v1.8 (Thesis Milestone 3 - Loading and Build fixes):**
    * **UX Polish:** Implemented custom Tkinter Splash Screen with transparency and procedural throbber.
    * **Architecture:** "Lazy Loading" pattern implementation for visual feedback on app launch.
    * **Critical Fix:** Resolved blocking I/O on Rust Core (Stop latency < 0.1s) and fixed PyInstaller binary shadowing.
* **v1.9 (Current - Traffic Monitor Refactor):**
    * **Refactored TrafficTab:** Implemented persistent packet tracking by hosts IP and improved adherence to SRP.
    * **IP list:** Added right-click context menu with 'Filter by this Host' option. 
</details>

## ⚠️ Known Limitations & Engineering Challenges

<details>
<summary><strong>Click to expand</strong></summary>

### ~~1. Large Subnet Scans (The "Atomic Scapy" Issue)~~ (SOLVED)
**Status:** **FIXED in v1.7**.
Scanning a `/16` network still relies on Scapy's atomic calls in Python mode, which can delay UI updates. The Rust implementation mitigates this but requires further optimization for massive ranges.
**Solution:** Implemented the Subnet Chunking logic in net_utils.py. Any target network larger than a /24 is now split into smaller /24 blocks. The scanner processes these blocks sequentially, checking for thread cancellation signals (stop_event) and updating the UI progress bar between each chunk, preventing the interface from freezing during massive scans.

### ~~2. Logs in PyInstaller Mode~~ (SOLVED)
**Status:** **FIXED in v1.6**.
Logs currently write to the temporary execution directory when frozen with PyInstaller. Needs logic to detect `sys.frozen`.
**Solution:** Refactored utils.py to implement Context-Aware Path Detection.

### ~~3. Rust Thread Cancellation~~ (SOLVED)
**Status:** **FIXED in v1.7**.
While the Python UI now remains responsive (due to `py.allow_threads`), stopping a Rust operation instantly requires the Rust loop to check a shared atomic flag. Currently, it stops after the current batch/timeout (approx. 1s latency).
**Solution:** Established a Bidirectional Control Channel via FFI. Configured the Rust `pnet` channel with a 100ms read timeout to prevent blocking on idle networks. The Python callback now returns a boolean status.

### 4. ~~Traffic Monitor "0 pps" / Interface Error~~ (SOLVED)
**Status:** **FIXED in v1.6**.
Previously, the app failed to identify the correct interface GUID on Windows.
**Solution:** Implemented an automatic translation layer in `net_utils.py` that maps Scapy's detected device (Friendly Name) to the Npcap GUID required by the Rust `pnet` library.

</details>

## 📱 Mobile App
To control this tool from your phone, check the [PyNetSketch Mobile App](https://github.com/KretliJ/PyNetSketch_Mobile).

NOTE: 
Development environment setup is necessary to run the mobile app.

## 📜 License
This project is licensed under the MIT License.

## ⚠️ Disclaimer
**Educational Use Only.** This tool involves raw socket manipulation and packet interception. Use only on networks you own or have permission to audit.

---

<details><summary><b>Architecture Diagrams (UML)</b></summary>
<img alt="ClassDiagram 2025-2" src="https://github.com/KretliJ/PyNetSketch/blob/main/projectDiagrams/ClassDiagram.png">
   
<img alt="UserFlow 2025-2" src="https://github.com/KretliJ/PyNetSketch/blob/main/projectDiagrams/SequenceDiagram.png">

<img alt="UserFlow 2025-2" src="https://github.com/KretliJ/PyNetSketch/blob/main/projectDiagrams/UserFlow.png">
</details>
