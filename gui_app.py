import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog
from tkinterweb import HtmlFrame
import platform
import webbrowser
import ctypes
import re

def resource_path(relative_path):
    """ Retorna o caminho absoluto do recurso, funcionando para dev e para PyInstaller """
    try:
        # PyInstaller cria uma pasta temp e armazena o caminho em _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def setup_window_icon(window):
    """ Define o ícone da janela de forma cross-platform """
    try:
        # 1. Tenta formato Windows (.ico) via iconbitmap
        # Isso é preferível no Windows pois define o ícone da barra de tarefas e cabeçalho corretamente
        if sys.platform.startswith("win"):
            ico_path = resource_path(os.path.join("assets", "app_icon.ico"))
            if os.path.exists(ico_path):
                window.iconbitmap(default=ico_path)
                return
        
        # 2. Fallback para Linux/Mac ou se o .ico falhar (.png)
        # O Linux prefere iconphoto com PNG
        png_path = resource_path(os.path.join("assets", "app_icon.png"))
        if os.path.exists(png_path):
            img = tk.PhotoImage(file=png_path)
            window.iconphoto(True, img)
            
    except Exception as e:
        print(f"Icon load warning: {e}")

# --- FIX: Tkinter in venv (Windows) ---
if sys.platform == "win32":
    import glob
    base_prefix = getattr(sys, "base_prefix", sys.prefix)
    tcl_dir = os.path.join(base_prefix, "tcl")
    if os.path.exists(tcl_dir):
        tcl_libs = glob.glob(os.path.join(tcl_dir, "tcl8*"))
        tk_libs = glob.glob(os.path.join(tcl_dir, "tk8*"))
        if tcl_libs and tk_libs:
            os.environ["TCL_LIBRARY"] = tcl_libs[0]
            os.environ["TK_LIBRARY"] = tk_libs[0]
# --------------------------------------------------

# --- GLOBAL MODULE PLACEHOLDERS ---
net_utils = None
utils = None
report_utils = None
set_app_icon = None
NetworkServerMode = None
ScannerTab = None
TopologyTab = None
TrafficTab = None

# --- CONFIGURAÇÃO DE DEPENDÊNCIA (NPCAP) ---
def check_npcap_silent():
    if platform.system() != "Windows":
        return True
    npcap_path = os.path.join(os.environ["WINDIR"], "System32", "Npcap", "wpcap.dll")
    return os.path.exists(npcap_path)

def prompt_npcap_install():
    root = tk.Tk()
    root.withdraw()
    if messagebox.askyesno("Missing Dependency", "Npcap is required (Packet Capture Driver).\nDownload from nmap.org/npcap?"):
        webbrowser.open("https://nmap.org/npcap/")
    root.destroy()
    sys.exit(0)

def is_valid_target(target):
    # Regex para IP Simples ou CIDR (ex: 192.168.0.1 ou 192.168.0.1/24)
    # Note o (\/\d{1,2})? no final para o opcional /24
    ip_cidr_pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(/\d{1,2})?$"
    
    # Regex para Domínios (ex: google.com, sub.dominio.com.br)
    domain_pattern = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"

    if re.match(ip_cidr_pattern, target) or re.match(domain_pattern, target, re.IGNORECASE):
        return True
    return False

# --- CLASSE DA APLICAÇÃO PRINCIPAL ---
class NetworkApp:
    def __init__(self, root, initial_dark_mode=False):
        self.root = root
        self.task_running = False
        
        # Set internal state to False initially so toggle_theme works correctly
        self.is_dark_mode = False 
        
        setup_window_icon(self.root)

        self.root.title("PyNetSketch (Standalone)")
        self.root.geometry("1200x800") 
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Default Styles (Color Buttons)
        self.style.configure("Green.TButton", background="#4caf50", foreground="white")
        self.style.map("Green.TButton", background=[("active", "#45a049"), ("disabled", "#d3d3d3")])
        self.style.configure("Red.TButton", background="#f44336", foreground="white")
        self.style.map("Red.TButton", background=[("active", "#d32f2f"), ("disabled", "#d3d3d3")])
        
        # State
        self.latest_scan_results = []
        self.local_ip = net_utils.get_local_ip()
        self.current_stop_event = None
        
        # Spinner State
        self.spinner_running = False
        self.spinner_chars = ['|', '/', '-', '\\']
        self.spinner_idx = 0
        self.task_start_time = None

        # Layout
        self.create_top_bar() 
        self.create_tabs()
        self.create_bottom_bar() 

        self.fill_local_ip()
        self.log_to_console(f"App started. Local IP: {self.local_ip}")
        
        # --- APPLY INHERITED THEME ---
        if initial_dark_mode:
            self.toggle_theme()

    def create_top_bar(self):
        control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(control_frame, text="Target:").pack(side="left", padx=(5, 2))
        self.target_entry = ttk.Entry(control_frame, width=25)
        self.target_entry.pack(side="left", padx=5)
        ttk.Button(control_frame, text="My Subnet", width=10, command=self.fill_local_ip).pack(side="left", padx=2)

        ttk.Separator(control_frame, orient="vertical").pack(side="left", fill="y", padx=15)

        ttk.Label(control_frame, text="Mode:").pack(side="left", padx=(5, 2))
        self.mode_var = tk.StringVar(value="Ping Host")
        self.mode_combo = ttk.Combobox(control_frame, textvariable=self.mode_var, state="readonly", width=18)
        self.mode_combo['values'] = ("Ping Host", "Trace Route", "Tracert no DNS", "ARP Scan", "Port Scan", "Traffic Monitor")
        self.mode_combo.pack(side="left", padx=5)
        self.mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)

        self.start_btn = ttk.Button(control_frame, text="START", command=self.start_selected_task, style="Green.TButton")
        self.start_btn.pack(side="left", padx=(15, 5))
        self.stop_btn = ttk.Button(control_frame, text="STOP", command=self.stop_current_task, state="disabled", style="Red.TButton")
        self.stop_btn.pack(side="left", padx=5)

        ttk.Button(control_frame, text="Export Results", command=self.export_data).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side="right", padx=5)

    def create_tabs(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_console = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_console, text="Console & Logs")
        self.console_text = scrolledtext.ScrolledText(self.tab_console, state='disabled', font=("Consolas", 10))
        self.console_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.tab_scanner = ScannerTab(self.notebook, self)
        self.notebook.add(self.tab_scanner, text="Network Scanner")

        self.tab_visual = TopologyTab(self.notebook)
        self.notebook.add(self.tab_visual, text="Network Topology")
        
        self.tab_traffic = TrafficTab(self.notebook, app=self)
        self.notebook.add(self.tab_traffic, text="Traffic Monitor")

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
        
        # Espaçador (Empurra tudo para a direita)
        ttk.Label(bottom_frame, text="").pack(side="left", expand=True)
        
        # Botão About (Fica no extremo direito)
        ttk.Button(bottom_frame, text="About", width=8, command=self.show_about_dialog).pack(side="right", padx=5)

        # Botão de Tema (Fica ao lado do About)
        self.btn_theme = ttk.Button(bottom_frame, text="🌙 Dark Mode", width=12, command=self.toggle_theme)
        self.btn_theme.pack(side="right", padx=5)

    def show_about_dialog(self):
        messagebox.showinfo("About PyNetSketch", f"PyNetSketch v2.0\nA student's project by KretliJ")

    # --- UI Logic ---

    def toggle_theme(self):
        style = self.style
        
        # --- DEFINIÇÃO DE CORES ---
        # Dark Mode Colors
        dark_main_bg = "#121b29"      # Fundo Principal
        dark_panel_bg = "#1c2636"     # Paineis
        # AQUI: Inputs agora usam a mesma cor "Deep" do botão desativado/fundo
        dark_input_bg = "#161e2b"     
        dark_text_fg = "#e1e6ef"      
        dark_accent = "#3b8ed0"       
        dark_border = "#2a3b55"       
        
        # Light Mode Colors
        light_bg = "#f0f0f0"
        light_fg = "black"
        # AQUI: Borda mais forte para o Light Mode (Cinza Médio em vez de Claro)
        light_border = "#888888"      

        if not self.is_dark_mode:
            # ========================================================
            # ATIVAR DARK MODE (DEEP BLUE)
            # ========================================================
            style.theme_use('clam')
            
            # 1. Configuração Global e Janela
            style.configure(".", background=dark_main_bg, foreground=dark_text_fg, bordercolor=dark_border)
            self._set_window_titlebar_color(True)
            self.root.configure(bg=dark_main_bg)

            # 2. Barra de Rolagem (Scrollbar) - Totalmente Escura
            style.configure("Vertical.TScrollbar", 
                            background=dark_panel_bg,    # Cor da "alça"
                            troughcolor=dark_main_bg,    # Cor do "trilho" no fundo
                            bordercolor=dark_main_bg,    # Remove borda 3D
                            arrowcolor=dark_text_fg,     # Setas brancas
                            relief="flat")
            style.map("Vertical.TScrollbar", 
                      background=[("active", dark_accent), ("pressed", dark_accent)])

            # 3. Inputs e Combobox (CORRIGIDO)
            style.configure("TEntry", fieldbackground=dark_input_bg, foreground="white", bordercolor=dark_border)
            
            style.configure("TCombobox", 
                            fieldbackground=dark_input_bg,
                            background=dark_input_bg,     
                            foreground="white", 
                            arrowcolor=dark_accent,       
                            bordercolor=dark_border)
            
            style.map("TCombobox", 
                      fieldbackground=[("readonly", dark_input_bg), ("disabled", dark_input_bg)],
                      background=[("readonly", dark_input_bg), ("disabled", dark_input_bg)],
                      
                      foreground=[("readonly", "white"), ("disabled", "#555")],
                      selectforeground=[("readonly", "white")],    # Texto branco quando selecionado
                      selectbackground=[("readonly", dark_input_bg)]) # Mantém fundo escuro ao clicar
            
            # Dropdown List
            self.root.option_add('*TCombobox*Listbox.background', dark_input_bg)
            self.root.option_add('*TCombobox*Listbox.foreground', 'white')
            self.root.option_add('*TCombobox*Listbox.selectBackground', dark_accent)
            self.root.option_add('*TCombobox*Listbox.selectForeground', 'white')

            # 4. Botões (Padronizados)
            style.configure("TButton", background=dark_panel_bg, foreground=dark_text_fg, 
                            bordercolor=dark_border, borderwidth=1, font=("Segoe UI", 9))
            style.map("TButton", 
                      background=[("active", dark_accent), ("disabled", dark_input_bg)], 
                      foreground=[("active", "white"), ("disabled", "#555555")])

            # Botões Coloridos (Verde/Vermelho)
            style.configure("Green.TButton", background="#2e7d32", foreground="white")
            style.map("Green.TButton", background=[("active", "#388e3c"), ("disabled", dark_input_bg)])
            
            style.configure("Red.TButton", background="#c62828", foreground="white")
            style.map("Red.TButton", background=[("active", "#d32f2f"), ("disabled", dark_input_bg)])

            # 5. Abas e Paineis
            style.configure("TNotebook", background=dark_main_bg, borderwidth=0)
            style.configure("TNotebook.Tab", background=dark_main_bg, foreground="#7a8b9e", borderwidth=0)
            style.map("TNotebook.Tab", 
                      background=[("selected", dark_panel_bg), ("active", "#253245")], 
                      foreground=[("selected", dark_accent), ("active", "white")])
            
            style.configure("TFrame", background=dark_main_bg)
            style.configure("TLabelframe", background=dark_main_bg, bordercolor=dark_border)
            style.configure("TLabelframe.Label", background=dark_main_bg, foreground=dark_accent)

            # 6. Widgets Nativos (Console)
            self.console_text.config(bg=dark_input_bg, fg="#a8b6c9", insertbackground="white", 
                                     selectbackground=dark_accent, highlightthickness=0)
            self.target_entry.config(background=dark_input_bg) 

            if hasattr(self, 'log_display'):
                self.log_display.config(bg=dark_input_bg, fg="#a8b6c9", highlightthickness=0)

            if hasattr(self, 'tab_traffic'):
                self.tab_traffic.update_theme(True)

            if hasattr(self, 'tab_visual'):
                self.tab_visual.update_theme(True)

            self.btn_theme.config(text="☀️ Light Mode")
            self.is_dark_mode = True
            
        else:
            # ========================================================
            # RESTAURAR LIGHT MODE (RESET TOTAL)
            # ========================================================
            style.theme_use('clam')
            self._set_window_titlebar_color(False)
            self.root.configure(bg=light_bg)
            
            # 1. Reset Global
            style.configure(".", background=light_bg, foreground=light_fg, bordercolor=light_border)
            
            # 2. Reset Scrollbar
            style.configure("Vertical.TScrollbar", 
                            background="#e1e1e1", troughcolor="#f0f0f0",
                            bordercolor="#adadad", arrowcolor="black", relief="raised")
            style.map("Vertical.TScrollbar", background=[("active", "#d0d0d0")])

            # 3. Reset Inputs e Combobox
            style.configure("TEntry", fieldbackground="white", foreground="black", bordercolor=light_border)
            
            style.configure("TCombobox", 
                            fieldbackground="white", background="white",    
                            foreground="black", arrowcolor="black", bordercolor=light_border)
            
            # RESET DO ESTADO READONLY (Importante para o texto preto)
            style.map("TCombobox", 
                      fieldbackground=[("readonly", "white"), ("disabled", "#f0f0f0")],
                      background=[("readonly", "white"), ("disabled", "#f0f0f0")],
                      foreground=[("readonly", "black"), ("disabled", "#a3a3a3")],
                      selectforeground=[("readonly", "white")],     
                      selectbackground=[("readonly", "#0078d7")])   

            # --- CORREÇÃO DO DROPDOWN (A LISTA SUSPENSA) ---
            # Força o reset para todas as listas, garantindo que o Combobox obedeça
            self.root.option_add('*TCombobox*Listbox.background', 'white')
            self.root.option_add('*TCombobox*Listbox.foreground', 'black')
            self.root.option_add('*TCombobox*Listbox.selectBackground', '#0078d7')
            self.root.option_add('*TCombobox*Listbox.selectForeground', 'white')
            
            # Redundância para garantir (caso o tema capture *Listbox)
            self.root.option_add('*Listbox.background', 'white')
            self.root.option_add('*Listbox.foreground', 'black')

            # 4. Reset Botões
            style.configure("TButton", background="#e1e1e1", foreground="black", bordercolor="#adadad")
            style.map("TButton", 
                      background=[("active", "#e5f1fb"), ("disabled", "#f0f0f0")], 
                      foreground=[("active", "black"), ("disabled", "#a3a3a3")])
            
            style.configure("Green.TButton", background="#4caf50", foreground="white")
            style.map("Green.TButton", background=[("active", "#45a049"), ("disabled", "#d3d3d3")])
            style.configure("Red.TButton", background="#f44336", foreground="white")
            style.map("Red.TButton", background=[("active", "#d32f2f"), ("disabled", "#d3d3d3")])

            # 5. Reset Abas
            style.configure("TNotebook", background=light_bg)
            style.configure("TNotebook.Tab", background="#d9d9d9", foreground="black", borderwidth=1)
            style.map("TNotebook.Tab", background=[("selected", "white")], foreground=[("selected", "black")])
            
            style.configure("TFrame", background=light_bg)
            style.configure("TLabelframe", background=light_bg, bordercolor=light_border)
            style.configure("TLabelframe.Label", background=light_bg, foreground="black")

            # 6. Reset Nativos
            self.console_text.config(bg="white", fg="black", insertbackground="black", highlightthickness=1)
            if hasattr(self, 'log_display'):
                self.log_display.config(bg="white", fg="black", highlightthickness=1)

            if hasattr(self, 'tab_traffic'):
                self.tab_traffic.update_theme(False)

            if hasattr(self, 'tab_visual'):
                self.tab_visual.update_theme(False)

            self.target_entry.config(background="white") 

            self.btn_theme.config(text="🌙 Dark Mode")
            self.is_dark_mode = False

    def _set_window_titlebar_color(self, dark_mode=True):
        """Força a barra de título do Windows a ficar escura (Requires Windows 10/11)."""
        try:
            import ctypes
            # Constantes da API do Windows DWM
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            set_value = ctypes.c_int(1 if dark_mode else 0)
            # Obtém o identificador da janela (HWND)
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            # Aplica o atributo
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(set_value), 4)
            
            # Força o redesenho da janela para aplicar a mudança instantaneamente
            self.root.update()
        except Exception:
            pass # Ignora se não for Windows ou versão antiga

    def fill_local_ip(self):
        current_ip = net_utils.get_local_ip()
        subnet = ".".join(current_ip.split('.')[:3]) + ".0/24"
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, subnet)
        self.log_to_console(f"Reset target to local subnet: {subnet}")

    # NOT theme mode, but operation mode
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
        self.task_running = running
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

        if hasattr(self, 'task_running') and self.task_running:
            self.log_to_console("⚠️ Aguardando a tarefa anterior finalizar completamente...")
            # Attempts again after 500ms until flag is False
            self.root.after(800, self.start_selected_task)
            return
        
        mode = self.mode_var.get()
        target = self.target_entry.get().strip()
        
        # Gets target from IP field and verifies with regex. This protects the modes from executing malicious or incorrect commands
        if(is_valid_target(target)):

            self.stop_btn.config(state="normal")
            self.start_btn.config(state="disabled")

            if mode == "Ping Host":
                target = target.split("/")[0]
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
                def traceroute_progress(msg):
                    self.log_to_console(msg)
                evt = utils.run_in_background(
                    net_utils.perform_traceroute, 
                    self.handle_generic_finish, 
                    progress_callback=traceroute_progress, # Usa o logger local
                    target_ip=target, 
                    resolve_dns=resolve_dns
                )
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
                
                filter_ip = self.tab_traffic.get_filter_ip()
                if filter_ip:
                    self.log_to_console(f"Applying filter: Host {filter_ip}")
                
                evt = utils.run_in_background(
                    net_utils.monitor_traffic, 
                    self.handle_generic_finish, 
                    progress_callback=self.handle_traffic_update,
                    filter_ip=filter_ip
                )
                self.set_task_running(True, evt)
        else:
            self.log_to_console(f"Target {target} is invalid. Insert a valid IP address, network or domain name.")
            self.log_to_console("Example: 1.1.1.1, 192.168.0.0/24 ou google.com")
    
    # --- Result Handlers ---
    def handle_generic_finish(self, result_msg):
        # 1. Garante que os dados do mapa sejam salvos ANTES da finalização da UI
        if isinstance(result_msg, list) and len(result_msg) > 0:
                self.last_hops = result_msg
                # DEBUG extra para confirmar o salvamento
                print(f"DEBUG [GUI]: Dados salvos em self.last_hops. Pronto para o mapa.")

        # 2. Chama a finalização da UI
        self.root.after(0, self._finalize_task_ui, result_msg)

    def open_map_window(self, map_file_path):
        import subprocess
        import sys
        
        self.log_to_console(f"Wait for map rendering...")
        # Garante caminho absoluto
        abs_path = os.path.abspath(map_file_path)
        
        # Script "voador" que cria a janela do mapa usando o motor do Edge
        viewer_script = f"""
import webview
import os
import sys

# Configura o caminho do arquivo
map_url = "file:///" + r"{abs_path}".replace("\\\\", "/")

if __name__ == '__main__':
    # Cria a janela nativa flutuante
    webview.create_window('Global Network Route', map_url, width=1100, height=750)
    webview.start()
"""
        # Salva esse mini-script temporário
        viewer_path = os.path.join(os.path.dirname(abs_path), "map_viewer_temp.py")
        with open(viewer_path, "w", encoding="utf-8") as f:
            f.write(viewer_script)
            
        print(f"DEBUG [GUI]: Lançando visualizador nativo para {abs_path}")
        
        # Dispara o processo separado (não trava o seu app principal!)
        subprocess.Popen([sys.executable, viewer_path])
        self.log_to_console(f"Map ready.")

    def _finalize_task_ui(self, result_msg):
        elapsed_str = ""
        if self.task_start_time:
            duration = time.time() - self.task_start_time
            elapsed_str = f" in {duration:.1f}s"
        
        self.set_task_running(False)
        
        # Loga mensagens de texto simples
        if result_msg and isinstance(result_msg, str):
            self.log_to_console(result_msg)
            
        self.log_to_console(f"Task Completed{elapsed_str}.")
        
        # --- CORREÇÃO DA LÓGICA DO MAPA ---
        # Verifica se temos hops salvos E se o result_msg é uma lista (sucesso do traceroute)
        if hasattr(self, 'last_hops') and self.last_hops:
            # Aceita se for lista OU se a string de sucesso estiver presente (híbrido)
            if isinstance(result_msg, list) or "Trace complete" in str(result_msg):
                try:
                    import report_utils
                    print("DEBUG [GUI]: Gerando mapa visual...")
                    map_file = report_utils.generate_visual_map(self.last_hops)
                    
                    if map_file:
                        print(f"DEBUG [GUI]: Mapa salvo em {map_file}. Abrindo...")
                        self.open_map_window(map_file)
                    else:
                        print("DEBUG [GUI]: Arquivo de mapa não retornado.")
                except Exception as e:
                    print(f"ERRO [GUI] Map Gen: {e}")

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
        if devices:
            self.tab_scanner.populate(devices)
            self.tab_visual.update_map(devices)

    def handle_traffic_update(self, data):
        try:
            if isinstance(data, str):
                self.log_to_console(data)
            
            # Supports format (Total, Filtered, Lista_IPs) from Rust
            elif isinstance(data, (tuple, list)):
                if len(data) == 3:
                    total, filtered, ip_list = data
                    
                    # 1. Atualiza o Gráfico (apenas números)
                    self.root.after(0, self.tab_traffic.add_data_point, (total, filtered))
                    
                    # 2. Atualiza a Tabela de IPs (lista)
                    self.root.after(0, self.tab_traffic.update_ip_table, ip_list)
                
                # fallback Python
                elif len(data) == 2:
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


# --- ENTRY POINT & SPLASH SCREEN LOGIC ---

def open_launcher():
    if not check_npcap_silent():
        prompt_npcap_install()

    selection_window = tk.Tk()
    setup_window_icon(selection_window)
    selection_window.title("PyNetSketch - Launcher")
    selection_window.geometry("500x480")
    
    # Center Window
    sc_width = selection_window.winfo_screenwidth()
    sc_height = selection_window.winfo_screenheight()
    x = (sc_width // 2) - (250)
    y = (sc_height // 2) - (240)
    selection_window.geometry(f"+{x}+{y}")

    # Shared State
    selection_state = {
        "mode": None, 
        "session_name": "My PyNetSketch Probe",
        "dark_mode": False # Default state
    }

    # --- THEME LOGIC FOR LAUNCHER ---
    style = ttk.Style()
    
    def apply_launcher_theme():
        is_dark = selection_state["dark_mode"]
        
        # Colors (Matching your App)
        bg = "#121b29" if is_dark else "#f0f0f0"
        fg = "#e1e6ef" if is_dark else "black"
        panel_bg = "#1c2636" if is_dark else "#e1e1e1"
        btn_fg = "white" if is_dark else "black"
        sub_fg = "#999999" if is_dark else "#666666"

        selection_window.configure(bg=bg)
        
        style.theme_use('clam')
        style.configure(".", background=bg, foreground=fg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TFrame", background=bg)
        style.configure("TLabelframe", background=bg, foreground=fg, bordercolor=sub_fg)
        style.configure("TLabelframe.Label", background=bg, foreground=fg)
        
        # Custom Styles
        style.configure("LauncherTitle.TLabel", font=("Segoe UI", 20, "bold"), background=bg, foreground=fg)
        style.configure("LauncherSub.TLabel", font=("Segoe UI", 10), foreground=sub_fg, background=bg)
        style.configure("Feature.TLabel", font=("Consolas", 10), background=bg, foreground=fg)
        
        # Button Styles
        style.configure("Big.TButton", font=("Segoe UI", 11, "bold"), background=panel_bg, foreground=btn_fg)
        style.map("Big.TButton", background=[("active", "#3b8ed0")], foreground=[("active", "white")])
        
        style.configure("Theme.TButton", font=("Segoe UI", 9))
        
        # Update Toggle Button Text
        if 'btn_theme' in globals() or 'btn_theme' in locals():
            btn_text = "☀️ Light Mode" if is_dark else "🌙 Dark Mode"
            btn_theme.config(text=btn_text)

        # Force Title Bar Dark (Windows only)
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(selection_window.winfo_id())
            val = ctypes.c_int(1 if is_dark else 0)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(val), 4)
        except: pass

    def toggle_launcher():
        selection_state["dark_mode"] = not selection_state["dark_mode"]
        apply_launcher_theme()

    # --- UI LAYOUT ---
    
    # Theme Button (Top Right)
    top_bar = ttk.Frame(selection_window)
    top_bar.pack(fill="x", padx=10, pady=5)
    btn_theme = ttk.Button(top_bar, text="🌙 Dark Mode", command=toggle_launcher, style="Theme.TButton", width=12)
    btn_theme.pack(side="right")

    # Header
    header_frame = ttk.Frame(selection_window)
    header_frame.pack(pady=(5, 10))
    
    ttk.Label(header_frame, text="PyNetSketch", style="LauncherTitle.TLabel").pack()
    ttk.Label(header_frame, text="Network Analysis & Monitoring Tool", style="LauncherSub.TLabel").pack()

    # Info Area
    info_frame = ttk.LabelFrame(selection_window, text=" System Capabilities ", padding=15)
    info_frame.pack(fill="x", padx=30, pady=15)

    features = [
        "⚡- Rust Acceleration Engine (High Performance)",
        "📊- Real-time Traffic Monitor (Live Charts)",
        "🔍- Multi-threaded Port Scanner",
        "🕸️- Layer 2/3 Topology Mapper",
        "🛡️- Passive Network Sniffer"
    ]

    for feat in features:
        ttk.Label(info_frame, text=feat, style="Feature.TLabel").pack(anchor="w", pady=2)

    # Action Area
    action_frame = ttk.Frame(selection_window)
    action_frame.pack(pady=10, fill="x", padx=30)
    
    ttk.Label(action_frame, text="Select Operation Mode:", font=("Segoe UI", 10, "bold")).pack(anchor="center", pady=(10, 5))
    
    def select_standalone():
        selection_state["mode"] = "standalone"
        selection_window.destroy()

    def select_server():
        name = simpledialog.askstring("Session Name", "Name this probe/server:", initialvalue="Lab Probe 01")
        if name:
            selection_state["mode"] = "server"
            selection_state["session_name"] = name
            selection_window.destroy()

    btn_gui = ttk.Button(action_frame, text="🖥️  Standalone Client (GUI)", command=select_standalone, style="Big.TButton")
    btn_gui.pack(fill="x", pady=5, ipady=5)
    
    btn_server = ttk.Button(action_frame, text="📡  Remote Server Probe (Headless)", command=select_server, style="Big.TButton")
    btn_server.pack(fill="x", pady=5, ipady=5)
    
    ttk.Label(selection_window, text="v2.0", font=("Segoe UI", 8), foreground="#999999").pack(side="bottom", pady=10)

    # Apply default theme on start
    apply_launcher_theme()
    
    selection_window.mainloop()

    # --- LAUNCH NEXT STAGE ---
    if selection_state["mode"] == "standalone":
        root = tk.Tk()
        # PASSING THE STATE HERE
        app = NetworkApp(root, initial_dark_mode=selection_state["dark_mode"])
        root.mainloop()
    elif selection_state["mode"] == "server":
        root = tk.Tk()
        # PASSING THE STATE HERE
        app = NetworkServerMode(root, session_name=selection_state["session_name"], dark_mode=selection_state["dark_mode"])
        root.mainloop()

def main():
    root = tk.Tk()
    root.withdraw()

    try:
        from interface.startup_screen import SplashScreen
    except ImportError:
        from interface.startup_screen import SplashScreen

    splash_icon = resource_path(os.path.join("assets", "app_icon.png"))
    splash = SplashScreen(root, image_path=splash_icon)
    setup_window_icon(root)

    def load_extensions():
        try:
            global net_utils, utils, report_utils, set_app_icon
            global NetworkServerMode, ScannerTab, TopologyTab, TrafficTab
            
            splash.update_status("Initializing Logging & Utils...", 10)
            import utils as u_mod
            utils = u_mod
            utils._log_operation("Application Boot Sequence Initiated.")
            time.sleep(0.2)
            
            splash.update_status("Loading Network Engine (Scapy/Rust)...", 30)
            import net_utils as nu_mod
            net_utils = nu_mod
            
            if hasattr(net_utils, 'RUST_AVAILABLE') and net_utils.RUST_AVAILABLE:
                utils._log_operation("Rust Acceleration Engine: ACTIVE")
            else:
                utils._log_operation("Rust Engine: INACTIVE (Using Python Fallback)", "WARN")
            time.sleep(0.3)

            splash.update_status("Loading UI Components...", 60)
            import report_utils as ru_mod
            report_utils = ru_mod
            
            from interface.ui_helpers import set_app_icon as sai
            set_app_icon = sai
            
            from interface.server_mode import NetworkServerMode as nsm
            NetworkServerMode = nsm
            
            from interface.scanner_tab import ScannerTab as st
            ScannerTab = st
            
            from interface.topology_tab import TopologyTab as tt
            TopologyTab = tt
            
            from interface.traffic_tab import TrafficTab as trt
            TrafficTab = trt
            
            splash.update_status("Checking Network Drivers...", 90)
            if not check_npcap_silent():
                utils._log_operation("Npcap missing! Will prompt user.", "WARN")
            
            splash.update_status("Ready.", 100)
            time.sleep(0.5)
            
            root.after(0, finish_loading)
            
        except Exception as e:
            print(f"Critical Startup Error: {e}")
            if utils: utils._log_operation(f"Startup Crash: {e}", "CRITICAL")
            root.after(0, finish_loading)

    def finish_loading():
        splash.close()
        root.destroy()
        open_launcher()

    threading.Thread(target=load_extensions, daemon=True).start()
    
    root.mainloop()

if __name__ == "__main__":
    import ctypes
    import sys

    # Correção do AppUserModelID (Para o ícone separar do Python)
    if sys.platform.startswith('win'):
        try:
            myappid = 'kretlij.pynetsketch.thesis.v2.0'
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

        # CORREÇÃO DE DPI 
        # diz ao Windows para renderizar o app na resolução nativa do monitor
        try:
            # Tenta API do Windows 8.1+ (Mais robusta)
            ctypes.windll.shcore.SetProcessDpiAwareness(1) 
        except Exception:
            try:
                # Fallback para Windows Vista/7
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass

    main()