import tkinter as tk
from tkinter import ttk, scrolledtext
import sys
import net_utils
import utils
import host_functions
from interface.ui_helpers import set_app_icon

class NetworkServerMode:
    def __init__(self, root, session_name="Unnamed Probe"):
        self.root = root
        set_app_icon(self.root)
        self.root.title(f"PyNetSketch Server - {session_name}")
        self.root.geometry("500x450")
        
        # Interface Visual
        header_frame = ttk.Frame(root)
        header_frame.pack(pady=(15, 5))
        
        ttk.Label(header_frame, text="📡 Server mode active", font=("Arial", 14, "bold")).pack()
        ttk.Label(header_frame, text=f"Session: {session_name}", font=("Arial", 11)).pack()
        
        info_frame = ttk.LabelFrame(root, text="Connection Info", padding=10)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        local_ip = net_utils.get_local_ip()
        ttk.Label(info_frame, text=f"Local IP: {local_ip}", font=("Consolas", 10, "bold")).pack(anchor="w")
        ttk.Label(info_frame, text=f"Command port (TCP): {host_functions.CMD_PORT}").pack(anchor="w")
        ttk.Label(info_frame, text=f"Discovery port (UDP): {host_functions.DISCOVERY_PORT}").pack(anchor="w")
        
        self.fw_label = ttk.Label(info_frame, text="Configuring Firewall...", foreground="orange", font=("Arial", 8))
        self.fw_label.pack(anchor="w", pady=(5,0))
        
        ttk.Label(root, text="Event log:", font=("Arial", 9, "bold")).pack(anchor="w", padx=10)

        self.log_area = scrolledtext.ScrolledText(root, height=10, width=50, state='disabled', font=("Consolas", 8))
        self.log_area.pack(fill="both", expand=True, padx=10, pady=5)
        
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Stop Server", command=self.stop_server).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(side="left", padx=5)
        
        self.server_manager = host_functions.ProbeServer(
            port=host_functions.CMD_PORT, 
            session_name=session_name, 
            log_callback=self.update_log
        )
        self.server_manager.start()
        
        self.root.after(1000, self.run_firewall_setup)

    def run_firewall_setup(self):
        success, msg = utils.configure_firewall()
        color = "green" if success else "grey"
        if "Erro" in msg: color = "red"
        self.fw_label.config(text=msg, foreground=color)
        self.update_log(msg)

    def update_log(self, message):
        if self.root.winfo_exists():
            self.root.after(0, lambda: self._append_text(message))

    def _append_text(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"> {message}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state='disabled')

    def clear_log(self):
        self.log_area.config(state='normal')
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state='disabled')

    def stop_server(self):
        self.server_manager.stop()
        self.root.destroy()
        sys.exit(0)