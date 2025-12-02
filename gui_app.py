import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, simpledialog, Menu
import math
import collections
import net_utils
import utils
import report_utils
import os # Added for path handling
import platform # Added for OS check

class NetworkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PyNetSketch")
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
        
        # For Traffic Monitor Graph (deque stores last 60 points)
        self.traffic_data = collections.deque([0]*60, maxlen=60)

        # --- Layout ---
        self.create_top_bar() 
        self.create_tabs()
        self.create_bottom_bar() # New About button here
        
        # --- Icon Setup (Moved inside class to prevent Garbage Collection) ---
        self.setup_icon()

        self.fill_local_ip()
        self.log_to_console(f"App started. Local IP: {self.local_ip}")

    def setup_icon(self):
        """Loads the application icon in a cross-platform way"""
        try:
            # Check both "assets" folder AND current folder
            base_path = os.path.dirname(__file__)
            possible_paths = [
                os.path.join(base_path, "assets", "app_icon.png"),
                os.path.join(base_path, "app_icon.png")
            ]
            
            icon_path = None
            for p in possible_paths:
                if os.path.exists(p):
                    icon_path = p
                    break
            
            if icon_path:
                # Keep a reference to the image object (self.icon_img)
                # to prevent Garbage Collection from removing it
                self.icon_img = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, self.icon_img)
                print(f"Debug: Icon successfully applied from {icon_path}")
            else:
                print("Debug: Warning - app_icon.png not found.")
                
        except Exception as e:
            print(f"Debug: Icon load error: {e}")

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
        self.mode_combo['values'] = ("Ping Host", "Trace Route", "ARP Scan", "Port Scan", "Traffic Monitor")
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

        # 1. Console
        self.tab_console = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_console, text="Console & Logs")
        self.console_text = scrolledtext.ScrolledText(self.tab_console, state='disabled', font=("Consolas", 10))
        self.console_text.pack(fill="both", expand=True, padx=5, pady=5)

        # 2. Scanner (Treeview)
        self.tab_scanner = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_scanner, text="Network Scanner")
        
        self.tree = ttk.Treeview(self.tab_scanner, columns=("ip", "mac", "vendor"), show="headings")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("vendor", text="Vendor")
        self.tree.column("ip", width=150); self.tree.column("mac", width=150); self.tree.column("vendor", width=300)
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add Right-Click Menu
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Wake-on-LAN (WoL)", command=self.wol_selected_device)
        self.context_menu.add_command(label="Port Scan This Host", command=self.port_scan_selected_device)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # 3. Topology
        self.tab_visual = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_visual, text="Network Topology")
        self.canvas = tk.Canvas(self.tab_visual, bg="white")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Button-1>", self.on_canvas_click)
        
        # 4. Traffic Monitor
        self.tab_traffic = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_traffic, text="Traffic Monitor")
        self.traffic_canvas = tk.Canvas(self.tab_traffic, bg="#222222") # Dark background for graph
        self.traffic_canvas.pack(fill="both", expand=True, padx=5, pady=5)

    def create_bottom_bar(self):
        """Creates a minimal footer with an About button"""
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side="bottom", fill="x", padx=10, pady=5)
        
        # Spacer to push button to the right
        ttk.Label(bottom_frame, text="").pack(side="left", expand=True)
        
        ttk.Button(bottom_frame, text="About", width=8, command=self.show_about_dialog).pack(side="right")

    def show_about_dialog(self):
        messagebox.showinfo(
            "About PyNetSketch", 
            "PyNetSketch v1.1\n\n"
            "A Python-based Network Scanner & Visualization Tool.\n"
            "Proof of Concept (PoC)\n\n"
            "Created for Educational Purposes by KretliJ.\n"
            "License: MIT"
        )

    # --- UI Logic ---

    def fill_local_ip(self):
        current_ip = net_utils.get_local_ip()
        subnet = ".".join(current_ip.split('.')[:3]) + ".0/24"
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, subnet)
        self.log_to_console(f"Reset target to local subnet: {subnet}")

    def on_mode_change(self, event):
        """Auto-switch tabs based on mode for better UX"""
        mode = self.mode_var.get()
        if mode == "Traffic Monitor":
            self.notebook.select(self.tab_traffic)
        elif mode == "ARP Scan":
            self.notebook.select(self.tab_scanner)
        else:
            self.notebook.select(self.tab_console)

    def set_task_running(self, running, stop_event=None):
        """Updates UI state based on whether a task is running"""
        if running:
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.mode_combo.config(state="disabled")
            self.current_stop_event = stop_event
        else:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.mode_combo.config(state="readonly")
            self.current_stop_event = None

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
        self.console_text.insert(tk.END, f">> {message}\n")
        self.console_text.see(tk.END)
        self.console_text.config(state='disabled')

    def clear_logs(self):
        self.console_text.config(state='normal')
        self.console_text.delete(1.0, tk.END)
        self.console_text.config(state='disabled')

    def show_context_menu(self, event):
        """Show Right-Click menu on Treeview"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    # --- Core Functions ---

    def start_selected_task(self):
        mode = self.mode_var.get()
        target = self.target_entry.get()
        
        if mode == "Ping Host":
            target = target.split("/")[0] # Clean CIDR
            self.log_to_console(f"Pinging {target}...")
            
            # Formatter for Ping Result (Tuple -> String)
            def ping_formatter(result):
                success, rtt = result
                status = "ONLINE" if success else "OFFLINE"
                msg = f"Ping Result: {target} is {status}"
                if success:
                    msg += f" (RTT: {rtt}ms)"
                self.handle_generic_finish(msg)

            evt = utils.run_in_background(net_utils.ping_host, 
                                          ping_formatter, 
                                          progress_callback=self.log_to_console, # Added for fallback logs
                                          target_ip=target)
            self.set_task_running(True, evt)
            
        elif mode == "Trace Route":
            target = target.split("/")[0]
            self.log_to_console(f"Tracing {target}...")
            evt = utils.run_in_background(net_utils.perform_traceroute, 
                                          self.handle_generic_finish, 
                                          progress_callback=self.log_to_console,
                                          target_ip=target)
            self.set_task_running(True, evt)
            
        elif mode == "ARP Scan":
            self.log_to_console(f"Scanning {target}...")
            for i in self.tree.get_children(): self.tree.delete(i)
            
            evt = utils.run_in_background(net_utils.arp_scan, 
                                          self.handle_scan_result, 
                                          progress_callback=self.log_to_console,
                                          network_cidr=target)
            self.set_task_running(True, evt)
            
        elif mode == "Port Scan":
            target = target.split("/")[0]
            self.log_to_console(f"Port scanning {target}...")
            evt = utils.run_in_background(net_utils.scan_ports, 
                                          self.handle_generic_finish, 
                                          progress_callback=self.log_to_console,
                                          target_ip=target)
            self.set_task_running(True, evt)
            
        elif mode == "Traffic Monitor":
            self.log_to_console("Starting Traffic Monitor...")
            self.notebook.select(self.tab_traffic)
            self.traffic_data = collections.deque([0]*60, maxlen=60)
            
            evt = utils.run_in_background(net_utils.monitor_traffic, 
                                          self.handle_generic_finish, 
                                          progress_callback=self.handle_traffic_update)
            self.set_task_running(True, evt)

    # --- Result Handlers ---

    def handle_generic_finish(self, result_msg):
        """Thread-safe handler for task completion"""
        self.root.after(0, self._finalize_task_ui, result_msg)

    def _finalize_task_ui(self, result_msg):
        self.set_task_running(False)
        # Log the actual result if one exists (e.g. from Ping)
        if result_msg and isinstance(result_msg, str):
            self.log_to_console(result_msg)
        self.log_to_console("Task Completed.")

    def handle_scan_result(self, devices):
        """Thread-safe handler for scan completion"""
        self.root.after(0, self._process_scan_data, devices)

    def _process_scan_data(self, devices):
        self.set_task_running(False)
        if not devices: return
        self.latest_scan_results = devices
        
        for dev in devices:
            vendor = dev.get('vendor', 'Unknown')
            if vendor == 'Unknown':
                vendor = net_utils.resolve_mac_vendor(dev['mac'])
            self.tree.insert("", tk.END, values=(dev['ip'], dev['mac'], vendor))
        
        self.draw_topology_map()

    def handle_traffic_update(self, data):
        """Called repeatedly by sniffer thread"""
        try:
            if isinstance(data, str):
                self.log_to_console(data)
            elif isinstance(data, (int, float)):
                self.root.after(0, self._update_graph_on_main_thread, data)
        except Exception as e:
            print(f"Graph update error: {e}")

    def _update_graph_on_main_thread(self, data):
        self.traffic_data.append(data)
        self.draw_traffic_graph()

    # --- WoL & Context Actions ---

    def wol_selected_device(self):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])
        mac = item['values'][1]
        
        if messagebox.askyesno("Wake-on-LAN", f"Send Magic Packet to {mac}?"):
            success, msg = net_utils.send_magic_packet(mac)
            self.log_to_console(msg)
            if success:
                messagebox.showinfo("WoL", msg)
            else:
                messagebox.showerror("WoL Failed", msg)

    def port_scan_selected_device(self):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])
        ip = item['values'][0]
        
        self.mode_var.set("Port Scan")
        self.target_entry.delete(0, tk.END)
        self.target_entry.insert(0, ip)
        self.start_selected_task()

    # --- Export ---

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

    # --- Visualization (Graph & Map) ---

    def draw_traffic_graph(self):
        self.traffic_canvas.delete("all")
        w = self.traffic_canvas.winfo_width()
        h = self.traffic_canvas.winfo_height()
        if w < 50: w=800; h=400
        
        data = list(self.traffic_data)
        max_val = max(data) if data and max(data) > 10 else 10
        x_step = w / (len(data) - 1) if len(data) > 1 else w
        h_factor = (h - 20) / max_val
        
        self.traffic_canvas.create_line(0, h-20, w, h-20, fill="gray")
        self.traffic_canvas.create_text(10, 10, text=f"Max: {max_val} pkts", fill="white", anchor="nw")

        points = []
        for i, val in enumerate(data):
            x = i * x_step
            y = h - (val * h_factor) - 10 
            points.append(x)
            points.append(y)
        
        if len(points) >= 4:
            self.traffic_canvas.create_line(points, fill="#00ff00", width=2, smooth=True)

    def draw_topology_map(self):
        self.canvas.delete("all")
        self.canvas.update_idletasks()
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 50: w=800; h=600
        
        subnets = net_utils.organize_scan_results_by_subnet(self.latest_scan_results)
        if not subnets: return

        cx, cy = w // 2, h // 2
        count = len(subnets)
        rad = min(w,h)//3 if count > 1 else 0
        step = 360/count if count>0 else 360
        
        gw_nodes = []
        for i, (gw_ip, devs) in enumerate(subnets.items()):
            angle = math.radians(i * step)
            gx = cx + rad * math.cos(angle)
            gy = cy + rad * math.sin(angle)
            gw_nodes.append((gx, gy, gw_ip, devs))
            
        if count > 1:
            for j in range(count):
                curr = gw_nodes[j]
                nxt = gw_nodes[(j+1)%count]
                self.canvas.create_line(curr[0], curr[1], nxt[0], nxt[1], fill="#4a90e2", width=4)
        
        for gx, gy, gw_ip, devs in gw_nodes:
            self.draw_cluster(gx, gy, devs)
            self.draw_node(gx, gy, f"GW\n{gw_ip}", "blue", True, gw_ip)

    def draw_cluster(self, gx, gy, devices):
        total = len(devices)
        if total == 0: return
        cur_r = 120; placed = 0; step_r = 60
        
        while placed < total:
            cap = max(1, int((2*math.pi*cur_r)/35))
            count = min(total - placed, cap)
            angle_step = 360/count
            
            for i in range(count):
                dev = devices[placed+i]
                rad = math.radians(i*angle_step)
                dx = gx + cur_r * math.cos(rad)
                dy = gy + cur_r * math.sin(rad)
                dash = (2,4) if cur_r > 120 else (2,2)
                self.canvas.create_line(gx, gy, dx, dy, fill="#dddddd", dash=dash)
                self.draw_node(dx, dy, f".{dev['ip'].split('.')[-1]}", "green", False, dev['ip'])
            
            placed += count
            cur_r += step_r

    def draw_node(self, x, y, text, color, is_gw, ip):
        r = 25 if is_gw else 15
        tag = f"device:{ip}"
        self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color, outline="black", tags=tag)
        self.canvas.create_text(x, y+r+12, text=text, font=("Arial", 8), tags=tag)

    def on_canvas_click(self, event):
        item = self.canvas.find_closest(event.x, event.y)
        if not item: return
        tags = self.canvas.gettags(item[0])
        for tag in tags:
            if tag.startswith("device:"):
                ip = tag.split(":", 1)[1]
                dev = next((d for d in self.latest_scan_results if d['ip'] == ip), None)
                vendor = "Unknown"
                mac = "Unknown"
                if dev:
                    mac = dev['mac']
                    vendor = dev.get('vendor', 'Unknown')
                messagebox.showinfo(f"Details: {ip}", f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}")
                break

if __name__ == "__main__":
    # 1. Taskbar Icon Fix for Windows
    if platform.system() == "Windows":
        try:
            import ctypes
            myappid = 'student.project.network.scanner.poc' 
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception:
            pass

    root = tk.Tk()
    
    # 2. Initialize App (Icon loading is now INSIDE the class)
    app = NetworkApp(root)
    root.mainloop()