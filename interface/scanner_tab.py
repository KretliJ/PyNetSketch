import tkinter as tk
from tkinter import ttk, Menu, messagebox
import net_utils

class ScannerTab(ttk.Frame):
    def __init__(self, parent, app_controller, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.app_controller = app_controller  # Reference to main app to trigger tasks
        self._create_widgets()

    def _create_widgets(self):
        self.tree = ttk.Treeview(self, columns=("ip", "mac", "vendor"), show="headings")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("mac", text="MAC Address")
        self.tree.heading("vendor", text="Vendor")
        self.tree.column("ip", width=150)
        self.tree.column("mac", width=150)
        self.tree.column("vendor", width=300)
        self.tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.context_menu = Menu(self, tearoff=0)
        self.context_menu.add_command(label="Wake-on-LAN (WoL)", command=self.wol_selected_device)
        self.context_menu.add_command(label="Port Scan This Host", command=self.port_scan_selected_device)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def populate(self, devices):
        # Clear existing
        for i in self.tree.get_children(): 
            self.tree.delete(i)
        
        # Add new
        for dev in devices:
            vendor = dev.get('vendor', 'Unknown')
            if vendor == 'Unknown':
                vendor = net_utils.resolve_mac_vendor(dev['mac'])
            self.tree.insert("", tk.END, values=(dev['ip'], dev['mac'], vendor))

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def wol_selected_device(self):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])
        mac = item['values'][1]
        
        if messagebox.askyesno("Wake-on-LAN", f"Send Magic Packet to {mac}?"):
            success, msg = net_utils.send_magic_packet(mac)
            self.app_controller.log_to_console(msg)
            if success:
                messagebox.showinfo("WoL", msg)
            else:
                messagebox.showerror("WoL Failed", msg)

    def port_scan_selected_device(self):
        sel = self.tree.selection()
        if not sel: return
        item = self.tree.item(sel[0])
        ip = item['values'][0]
        
        # Use the controller to trigger a scan
        self.app_controller.mode_var.set("Port Scan")
        self.app_controller.target_entry.delete(0, tk.END)
        self.app_controller.target_entry.insert(0, ip)
        self.app_controller.start_selected_task()