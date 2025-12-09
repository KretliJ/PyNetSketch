import os
import sys
# --- FIX: Tkinter em Ambiente Virtual (Windows) ---
# Isso resolve o erro "_tkinter.TclError: Can't find a usable init.tcl"
# forçando o Python a buscar as libs gráficas na instalação base, não no venv quebrado.
if sys.platform == "win32":
    import glob
    
    # 1. Encontra onde o Python REAL está instalado (fora do venv)
    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    
    # 2. Procura pelas pastas tcl8.6 e tk8.6 dentro da instalação base
    # (Geralmente em C:\Python3xx\tcl\...)
    tcl_dir = os.path.join(base_prefix, "tcl")
    
    if os.path.exists(tcl_dir):
        # Tenta encontrar a pasta exata (pode ser tcl8.6, tcl8.6.13, etc)
        tcl_libs = glob.glob(os.path.join(tcl_dir, "tcl8*"))
        tk_libs = glob.glob(os.path.join(tcl_dir, "tk8*"))
        
        if tcl_libs and tk_libs:
            # Define as variáveis de ambiente em tempo de execução
            os.environ["TCL_LIBRARY"] = tcl_libs[0]
            os.environ["TK_LIBRARY"] = tk_libs[0]
            
            # print(f"DEBUG: Tcl fix applied. Using {tcl_libs[0]}")
# --------------------------------------------------
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
import time

import platform 
import webbrowser

# Core Logic imports
import net_utils
import utils
import report_utils

# Interface Modules
from interface.ui_helpers import set_app_icon
from interface.server_mode import NetworkServerMode
from interface.scanner_tab import ScannerTab
from interface.topology_tab import TopologyTab
from interface.traffic_tab import TrafficTab

# --- CONFIGURAÇÃO GLOBAL E UTILITÁRIOS ---

def check_npcap():
    """Verifica se o Npcap está instalado no Windows."""
    if platform.system() != "Windows":
        return
    npcap_path = os.path.join(os.environ["WINDIR"], "System32", "Npcap", "wpcap.dll")
    if not os.path.exists(npcap_path):
        temp_root = tk.Tk()
        temp_root.withdraw() 
        msg = "Npcap is required. Download from nmap.org/npcap?"
        if messagebox.askyesno("Missing Dependency", msg):
            webbrowser.open("https://nmap.org/npcap/")
            sys.exit(0)
        else:
            temp_root.destroy()

# --- CLASSE DO MODO STANDALONE (GUI COMPLETA) ---
class NetworkApp:
    def __init__(self, root):
        self.root = root
        set_app_icon(self.root) 
        self.root.title("PyNetSketch (Standalone)")
        self.root.geometry("1200x800") 
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # --- Styles ---
        self.style.configure("Green.TButton", background="#4caf50", foreground="white")
        self.style.map("Green.TButton", background=[("active", "#45a049"), ("disabled", "#d3d3d3")])
        self.style.configure("Red.TButton", background="#f44336", foreground="white")
        self.style.map("Red.TButton", background=[("active", "#d32f2f"), ("disabled", "#d3d3d3")])
        
        # --- State ---
        self.latest_scan_results = []
        self.local_ip = net_utils.get_local_ip()
        self.current_stop_event = None
        
        # Spinner State
        self.spinner_running = False
        self.spinner_chars = ['|', '/', '-', '\\']
        self.spinner_idx = 0
        self.task_start_time = None

        # --- Layout ---
        self.create_top_bar() 
        self.create_tabs()
        self.create_bottom_bar() 

        self.fill_local_ip()
        self.log_to_console(f"App started. Local IP: {self.local_ip}")

    def create_top_bar(self):
        control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)

        # Target Inputs
        ttk.Label(control_frame, text="Target:").pack(side="left", padx=(5, 2))
        self.target_entry = ttk.Entry(control_frame, width=25)
        self.target_entry.pack(side="left", padx=5)
        ttk.Button(control_frame, text="My Subnet", width=10, command=self.fill_local_ip).pack(side="left", padx=2)

        ttk.Separator(control_frame, orient="vertical").pack(side="left", fill="y", padx=15)

        # Mode Selection
        ttk.Label(control_frame, text="Mode:").pack(side="left", padx=(5, 2))
        self.mode_var = tk.StringVar(value="Ping Host")
        self.mode_combo = ttk.Combobox(control_frame, textvariable=self.mode_var, state="readonly", width=18)
        self.mode_combo['values'] = ("Ping Host", "Trace Route", "Tracert no DNS", "ARP Scan", "Port Scan", "Traffic Monitor")
        self.mode_combo.pack(side="left", padx=5)
        self.mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)

        # Start/Stop
        self.start_btn = ttk.Button(control_frame, text="START", command=self.start_selected_task, style="Green.TButton")
        self.start_btn.pack(side="left", padx=(15, 5))
        self.stop_btn = ttk.Button(control_frame, text="STOP", command=self.stop_current_task, state="disabled", style="Red.TButton")
        self.stop_btn.pack(side="left", padx=5)

        # Utilities
        ttk.Button(control_frame, text="Export Results", command=self.export_data).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side="right", padx=5)

    def create_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # 1. Console (Kept inline as it's simple and tightly coupled to controller logging)
        self.tab_console = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_console, text="Console & Logs")
        self.console_text = scrolledtext.ScrolledText(self.tab_console, state='disabled', font=("Consolas", 10))
        self.console_text.pack(fill="both", expand=True, padx=5, pady=5)

        # 2. Scanner (Modularized)
        self.tab_scanner = ScannerTab(self.notebook, self)
        self.notebook.add(self.tab_scanner, text="Network Scanner")

        # 3. Topology (Modularized)
        self.tab_visual = TopologyTab(self.notebook)
        self.notebook.add(self.tab_visual, text="Network Topology")
        
        # 4. Traffic Monitor (Modularized)
        self.tab_traffic = TrafficTab(self.notebook)
        self.notebook.add(self.tab_traffic, text="Traffic Monitor")

        # 5. Persistent Logs
        self.tab_logs = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_logs, text="Persistent Logs")
        self._setup_persistent_logs_tab()

    def _setup_persistent_logs_tab(self):
        logs_toolbar = ttk.Frame(self.tab_logs)
        logs_toolbar.pack(fill="x", padx=5, pady=5)
        ttk.Button(logs_toolbar, text="🔄 Atualizar Logs", command=self.load_persistent_logs).pack(side="left")
        self.log_display = scrolledtext.ScrolledText(self.tab_logs, state='disabled', font=("Consolas", 9))
        self.log_display.pack(fill="both", expand=True, padx=5, pady=5)
        self.load_persistent_logs()

    def load_persistent_logs(self):
        self.log_display.config(state='normal')
        self.log_display.delete(1.0, tk.END)
        log_path = utils.LOG_FILE
        if os.path.exists(log_path):
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    self.log_display.insert(tk.END, f.read())
                    self.log_display.see(tk.END)
            except Exception as e:
                 self.log_display.insert(tk.END, f"Erro ao ler arquivo: {e}")
        else:
             self.log_display.insert(tk.END, "Arquivo de log não encontrado ainda.")
        self.log_display.config(state='disabled')

    def create_bottom_bar(self):
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side="bottom", fill="x", padx=10, pady=5)
        ttk.Label(bottom_frame, text="").pack(side="left", expand=True)
        ttk.Button(bottom_frame, text="About", width=8, command=self.show_about_dialog).pack(side="right")

    def show_about_dialog(self):
        messagebox.showinfo("About PyNetSketch", "PyNetSketch v1.5 Modular")

    # --- UI Logic ---
    def fill_local_ip(self):
        current_ip = net_utils.get_local_ip()
        subnet = ".".join(current_ip.split('.')[:3]) + ".0/24"
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, subnet)
        self.log_to_console(f"Reset target to local subnet: {subnet}")

    def on_mode_change(self, event):
        mode = self.mode_var.get()
        if mode == "Traffic Monitor":
            self.notebook.select(self.tab_traffic)
        elif mode == "ARP Scan":
            self.notebook.select(self.tab_scanner)
        elif mode == "Persistent Log":
             self.notebook.select(self.tab_logs)
             self.load_persistent_logs()
        else:
            self.notebook.select(self.tab_console)

    def set_task_running(self, running, stop_event=None):
        if running:
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.mode_combo.config(state="disabled")
            self.current_stop_event = stop_event
            self.spinner_running = True
            self.task_start_time = time.time()
            self.console_text.config(state='normal')
            self.console_text.insert(tk.END, f"{self.spinner_chars[0]}\n0.0s", "spinner")
            self.console_text.config(state='disabled')
            self._run_spinner()
        else:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.mode_combo.config(state="readonly")
            self.current_stop_event = None
            self.spinner_running = False
            self.console_text.config(state='normal')
            try:
                self.console_text.delete("spinner.first", "spinner.last")
            except Exception: pass
            self.console_text.config(state='disabled')

    def _run_spinner(self):
        if not self.spinner_running: return
        try:
            elapsed = time.time() - self.task_start_time
            self.console_text.config(state='normal')
            try: self.console_text.delete("spinner.first", "spinner.last")
            except Exception: pass
            self.spinner_idx = (self.spinner_idx + 1) % len(self.spinner_chars)
            text = f"{self.spinner_chars[self.spinner_idx]}\n{elapsed:.1f}s"
            self.console_text.insert(tk.END, text, "spinner")
            self.console_text.see(tk.END)
            self.console_text.config(state='disabled')
            self.root.after(100, self._run_spinner)
        except Exception as e: print(f"Spinner error: {e}")

    def stop_current_task(self):
        if self.current_stop_event:
            self.current_stop_event.set()
            self.log_to_console("Signal sent to stop task...")
            self.stop_btn.config(state="disabled")

    def log_to_console(self, message):
        utils._log_operation(message, "GUI")
        self.root.after(0, self._update_console_widget, message)

    def _update_console_widget(self, message):
        self.console_text.config(state='normal')
        if self.spinner_running:
            try: self.console_text.delete("spinner.first", "spinner.last")
            except Exception: pass
        self.console_text.insert(tk.END, f">> {message}\n")
        if self.spinner_running:
            elapsed = time.time() - self.task_start_time
            text = f"{self.spinner_chars[self.spinner_idx]}\n{elapsed:.1f}s"
            self.console_text.insert(tk.END, text, "spinner")
        self.console_text.see(tk.END)
        self.console_text.config(state='disabled')

    def clear_logs(self):
        self.console_text.config(state='normal')
        self.console_text.delete(1.0, tk.END)
        self.console_text.config(state='disabled')

    # --- Core Functions ---
    def start_selected_task(self):
        mode = self.mode_var.get()
        target = self.target_entry.get()
        
        if mode == "Ping Host":
            target = target.split("/")[0] # Clean CIDR
            self.log_to_console(f"Pinging {target}...")
            
            def ping_formatter(result):
                success, rtt = result
                status = "ONLINE" if success else "OFFLINE"
                msg = f"Ping Result: {target} is {status}"
                if success: msg += f" (RTT: {rtt}ms)"
                self.handle_generic_finish(msg)

            evt = utils.run_in_background(net_utils.ping_host, ping_formatter, 
                                          progress_callback=self.log_to_console, target_ip=target)
            self.set_task_running(True, evt)
            
        elif mode in ["Trace Route", "Tracert no DNS"]:
            target = target.split("/")[0]
            resolve_dns = (mode == "Trace Route")
            self.log_to_console(f"Tracing {target}...")
            evt = utils.run_in_background(net_utils.perform_traceroute, self.handle_generic_finish, 
                                          progress_callback=self.log_to_console,
                                          target_ip=target, resolve_dns=resolve_dns)
            self.set_task_running(True, evt)
            
        elif mode == "ARP Scan":
            self.log_to_console(f"Scanning {target}...")
            evt = utils.run_in_background(net_utils.arp_scan, self.handle_scan_result, 
                                          progress_callback=self.log_to_console, network_cidr=target)
            self.set_task_running(True, evt)
            
        elif mode == "Port Scan":
            target = target.split("/")[0]
            self.log_to_console(f"Port scanning {target}...")
            evt = utils.run_in_background(net_utils.scan_ports, self.handle_generic_finish, 
                                          progress_callback=self.log_to_console, target_ip=target)
            self.set_task_running(True, evt)
            
        elif mode == "Traffic Monitor":
            self.log_to_console("Starting Traffic Monitor...")
            self.notebook.select(self.tab_traffic)
            self.tab_traffic.reset_data()
            
            # >>>> NOVO CÓDIGO AQUI <<<<
            # Pega o filtro da UI
            filter_ip = self.tab_traffic.get_filter_ip()
            if filter_ip:
                self.log_to_console(f"Applying filter: Host {filter_ip}")
            
            # Passa o filtro para a função do net_utils
            evt = utils.run_in_background(
                net_utils.monitor_traffic, 
                self.handle_generic_finish, 
                progress_callback=self.handle_traffic_update,
                filter_ip=filter_ip  # Argumento novo
            )
            self.set_task_running(True, evt)

    # --- Result Handlers ---
    def handle_generic_finish(self, result_msg):
        self.root.after(0, self._finalize_task_ui, result_msg)

    def _finalize_task_ui(self, result_msg):
        elapsed_str = ""
        if self.task_start_time:
            duration = time.time() - self.task_start_time
            elapsed_str = f" in {duration:.1f}s"
        self.set_task_running(False)
        if result_msg and isinstance(result_msg, str):
            self.log_to_console(result_msg)
        self.log_to_console(f"Task Completed{elapsed_str}.")

    def handle_scan_result(self, devices):
        self.root.after(0, self._process_scan_data, devices)

    def _process_scan_data(self, devices):
        elapsed_str = ""
        if self.task_start_time:
            duration = time.time() - self.task_start_time
            elapsed_str = f" in {duration:.1f}s"
        self.set_task_running(False)
        self.log_to_console(f"Scan Finished{elapsed_str}.")
        
        self.latest_scan_results = devices
        
        # Delegate display to modules
        if devices:
            self.tab_scanner.populate(devices)
            self.tab_visual.update_map(devices)

    def handle_traffic_update(self, data):
        try:
            if isinstance(data, str):
                self.log_to_console(data)
            # Aceita tuple, list, int ou float
            elif isinstance(data, (int, float, tuple, list)):
                self.root.after(0, self.tab_traffic.add_data_point, data)
        except Exception as e:
            print(f"Graph update error: {e}")

    def export_data(self):
        top = tk.Toplevel(self.root)
        top.title("Export Options")
        top.geometry("300x150")
        
        ttk.Label(top, text="Select Format:").pack(pady=10)
        def do_export(fmt):
            top.destroy()
            report_utils.export_results(self.latest_scan_results, fmt)
        ttk.Button(top, text="CSV (Excel)", command=lambda: do_export("csv")).pack(pady=5)
        ttk.Button(top, text="HTML (Web/PDF)", command=lambda: do_export("html")).pack(pady=5)

# --- INICIALIZAÇÃO E LAUNCHER ---
def main_launcher():
    check_npcap()    
    if platform.system() == "Windows":
        try:
            import ctypes
            myappid = 'student.project.network.scanner.poc' 
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception: pass

    # Janela de Seleção (Launcher)
    selection_window = tk.Tk()
    set_app_icon(selection_window)
    selection_window.title("PyNetSketch - Launcher")
    selection_window.geometry("350x250")
    
    style = ttk.Style()
    style.configure("Big.TButton", font=("Arial", 12))
    
    ttk.Label(selection_window, text="Selecione o Modo de Operação:", font=("Arial", 11)).pack(pady=20)
    
    selection_state = {"mode": None, "session_name": "My PyNetSketch Probe"}

    def select_standalone():
        selection_state["mode"] = "standalone"
        selection_window.destroy()

    def select_server():
        name = simpledialog.askstring("Session Name", "Nome desta sonda/servidor:", initialvalue="Lab Probe 01")
        if name:
            selection_state["mode"] = "server"
            selection_state["session_name"] = name
            selection_window.destroy()

    ttk.Button(selection_window, text="🖥️ Standalone (GUI)", command=select_standalone, width=25, style="Big.TButton").pack(pady=10)
    ttk.Button(selection_window, text="📡 Server (Remote Probe)", command=select_server, width=25, style="Big.TButton").pack(pady=10)
    
    selection_window.mainloop()

    if selection_state["mode"] == "standalone":
        root = tk.Tk()
        app = NetworkApp(root)
        root.mainloop()
    elif selection_state["mode"] == "server":
        root = tk.Tk()
        app = NetworkServerMode(root, session_name=selection_state["session_name"])
        root.mainloop()

if __name__ == "__main__":
    main_launcher()