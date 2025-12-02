import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import math
import net_utils
import utils

class NetworkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Network Manager")
        self.root.geometry("1000x700")
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Store scan results for visualization
        self.latest_scan_results = []
        self.local_ip = net_utils.get_local_ip()

        # --- Layout ---
        self.create_top_bar()
        self.create_tabs()
        
        # Log startup
        self.log_to_console(f"Application started. Local IP: {self.local_ip}")

    def create_top_bar(self):
        # Top control panel for inputs and buttons
        control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        control_frame.pack(fill="x", padx=10, pady=5)

        # Input Label
        ttk.Label(control_frame, text="Target IP / Range:").pack(side="left", padx=5)
        
        # Entry Box (Default to local subnet)
        default_range = ".".join(self.local_ip.split('.')[:3]) + ".0/24"
        self.target_entry = ttk.Entry(control_frame, width=20)
        self.target_entry.insert(0, default_range)
        self.target_entry.pack(side="left", padx=5)

        # Buttons
        ttk.Button(control_frame, text="Ping Host", command=self.start_ping).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Trace Route", command=self.start_trace).pack(side="left", padx=5)
        ttk.Button(control_frame, text="ARP Scan (Admin)", command=self.start_scan).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side="right", padx=5)

    def create_tabs(self):
        # Notebook with tabs for different views
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        # Tab 1: Console / Logs
        self.tab_console = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_console, text="Console & Logs")
        
        self.console_text = scrolledtext.ScrolledText(self.tab_console, state='disabled', font=("Consolas", 10))
        self.console_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Tab 2: Scanner Results
        self.tab_scanner = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_scanner, text="Network Scanner")
        
        columns = ("ip", "mac", "vendor")
        self.tree = ttk.Treeview(self.tab_scanner, columns=columns, show="headings")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("vendor", text="Vendor")
        
        self.tree.column("ip", width=150)
        self.tree.column("mac", width=150)
        self.tree.column("vendor", width=300)
        
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)

        # Tab 3: Visualization
        self.tab_visual = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_visual, text="Network Topology")
        
        self.canvas = tk.Canvas(self.tab_visual, bg="white")
        self.canvas.pack(fill="both", expand=True)
        
        # Bind click event for interactivity
        self.canvas.bind("<Button-1>", self.on_canvas_click)

    # --- Helper Functions ---

    def log_to_console(self, message):
        # Thread-safe logging to the text widget and main log file
        # Log to the main file via utils
        utils._log_operation(message, "GUI")

        # Update the GUI console
        self.console_text.config(state='normal')
        self.console_text.insert(tk.END, f">> {message}\n")
        self.console_text.see(tk.END)
        self.console_text.config(state='disabled')

    def clear_logs(self):
        self.console_text.config(state='normal')
        self.console_text.delete(1.0, tk.END)
        self.console_text.config(state='disabled')

    # --- Button Commands ---

    def start_ping(self):
        target = self.target_entry.get()
        # Clean target if it's a CIDR range
        if "/" in target:
            target = target.split("/")[0]
            if target.endswith(".0"): 
                target = target[:-1] + "1"
        
        self.log_to_console(f"Pinging {target}...")
        
        utils.run_in_background(
            target_func=net_utils.ping_host,
            callback_func=lambda result: self.root.after(0, self.handle_ping_result, target, result),
            target_ip=target
        )

    def start_trace(self):
        target = self.target_entry.get()
        if "/" in target:
            target = target.split("/")[0]
            
        self.log_to_console(f"Starting Traceroute to {target} (This may take time)...")
        
        utils.run_in_background(
            target_func=net_utils.perform_traceroute,
            callback_func=lambda result: self.root.after(0, self.handle_trace_result, result),
            target_ip=target
        )

    def start_scan(self):
        target_range = self.target_entry.get()
        self.log_to_console(f"Starting ARP Scan on {target_range}...")
        
        # Clear previous tree data
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        utils.run_in_background(
            target_func=net_utils.arp_scan,
            callback_func=lambda result: self.root.after(0, self.handle_scan_result, result),
            network_cidr=target_range
        )

    # --- Callbacks ---

    def handle_ping_result(self, target, is_up):
        status = "ONLINE" if is_up else "OFFLINE/UNREACHABLE"
        self.log_to_console(f"Ping Result: Host {target} is {status}")

    def handle_trace_result(self, hops):
        if not hops:
            self.log_to_console("Traceroute failed or returned no data.")
            return
            
        self.log_to_console("--- Traceroute Complete ---")
        for hop in hops:
            self.log_to_console(f"Hop {hop['ttl']}: {hop['ip']}")

    def handle_scan_result(self, devices):
        if not devices:
            self.log_to_console("Scan found 0 devices or failed.")
            return

        self.latest_scan_results = devices
        self.log_to_console(f"Scan Finished. Found {len(devices)} devices.")
        
        for dev in devices:
            vendor = net_utils.resolve_mac_vendor(dev['mac'])
            # Store full device data in tree for lookups if needed
            self.tree.insert("", tk.END, values=(dev['ip'], dev['mac'], vendor))
            
        self.notebook.select(self.tab_scanner)
        self.draw_topology_map()

    # --- Visualization Logic ---

    def draw_topology_map(self):
        # Draws a topology map, grouping by subnet
        self.canvas.delete("all")
        self.canvas.update_idletasks()
        
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        # Fallback dimensions
        if width < 50: width = 800
        if height < 50: height = 600
        
        # Group by subnet
        subnets = net_utils.organize_scan_results_by_subnet(self.latest_scan_results)
        subnet_count = len(subnets)
        
        if subnet_count == 0:
            return

        # Canvas Center
        cx, cy = width // 2, height // 2
        
        # Layout strategy:
        # If 1 subnet: Center the gateway at (cx, cy).
        # If >1 subnets: Arrange gateways in a circle around (cx, cy).
        
        subnet_orbit_radius = min(width, height) // 3 if subnet_count > 1 else 0
        
        gw_angle_step = 360 / subnet_count if subnet_count > 0 else 360
        
        for i, (gateway_ip, devices) in enumerate(subnets.items()):
            # Calculate Gateway Position
            gw_angle_rad = math.radians(i * gw_angle_step)
            gx = cx + subnet_orbit_radius * math.cos(gw_angle_rad)
            gy = cy + subnet_orbit_radius * math.sin(gw_angle_rad)
            
            # Draw Gateway
            self.draw_node(gx, gy, f"GW\n{gateway_ip}", "blue", is_gateway=True, ip=gateway_ip)
            
            # Draw Devices for this Gateway
            self.draw_subnet_devices(gx, gy, devices)

    def draw_subnet_devices(self, gx, gy, devices):
        count = len(devices)
        if count == 0: return
        
        # Device orbit radius
        # Smaller radius if many subnets to avoid overlap
        radius = 120 
        
        angle_step = 360 / count
        
        for i, dev in enumerate(devices):
            angle_rad = math.radians(i * angle_step)
            
            dx = gx + radius * math.cos(angle_rad)
            dy = gy + radius * math.sin(angle_rad)
            
            # Draw Link
            self.canvas.create_line(gx, gy, dx, dy, fill="#dddddd", dash=(2, 2))
            
            # Draw Device Node
            short_ip = dev['ip'].split('.')[-1]
            color = "green" if i % 2 == 0 else "darkgreen"
            
            # Tag the node with "device:{ip}" for click detection
            self.draw_node(dx, dy, f".{short_ip}", color, is_gateway=False, ip=dev['ip'])

    def draw_node(self, x, y, text, color, is_gateway, ip):
        # Helper to draw a node with a tag
        r = 25 if is_gateway else 15
        
        # Create unique tag
        tag = f"device:{ip}"
        
        # Draw Circle
        item_id = self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color, outline="black", tags=tag)
        
        # Draw Text (disable click on text to keep it simple, or tag it too)
        self.canvas.create_text(x, y + r + 12, text=text, font=("Arial", 8), tags=tag)

    def on_canvas_click(self, event):
        # Handle clicks on nodes
        # Find item closest to click
        item = self.canvas.find_closest(event.x, event.y)
        if not item:
            return
            
        tags = self.canvas.gettags(item[0])
        
        # Look for our custom tag
        target_ip = None
        for tag in tags:
            if tag.startswith("device:"):
                target_ip = tag.split(":", 1)[1]
                break
        
        if target_ip:
            self.show_host_details(target_ip)

    def show_host_details(self, ip):
        # Opens a popup with host info
        # Find the device data
        device_data = next((d for d in self.latest_scan_results if d['ip'] == ip), None)
        
        # If it's a gateway synthesized in visualization, we might not have mac/vendor
        if not device_data:
            # Check if it was a generated gateway key
            device_data = {'ip': ip, 'mac': 'Gateway/Router', 'vendor': 'Network Infrastructure'}

        vendor = net_utils.resolve_mac_vendor(device_data.get('mac', ''))

        # Create Popup
        popup = tk.Toplevel(self.root)
        popup.title(f"Host Details: {ip}")
        popup.geometry("300x200")
        
        ttk.Label(popup, text="IP Address:", font=("Arial", 10, "bold")).pack(pady=(10,0))
        ttk.Label(popup, text=ip).pack()
        
        ttk.Label(popup, text="MAC Address:", font=("Arial", 10, "bold")).pack(pady=(10,0))
        ttk.Label(popup, text=device_data.get('mac', 'Unknown')).pack()
        
        ttk.Label(popup, text="Vendor:", font=("Arial", 10, "bold")).pack(pady=(10,0))
        ttk.Label(popup, text=vendor).pack()
        
        ttk.Button(popup, text="Close", command=popup.destroy).pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkApp(root)
    root.mainloop()