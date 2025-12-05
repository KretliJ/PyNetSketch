import tkinter as tk
from tkinter import ttk, messagebox
import math
import net_utils

class TopologyTab(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.latest_scan_data = []
        self.canvas = tk.Canvas(self, bg="white")
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Button-1>", self.on_canvas_click)

    def update_map(self, devices):
        self.latest_scan_data = devices
        self.draw_topology_map()

    def draw_topology_map(self):
        self.canvas.delete("all")
        self.canvas.update_idletasks()
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 50: w=800; h=600
        
        subnets = net_utils.organize_scan_results_by_subnet(self.latest_scan_data)
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
            self._draw_cluster(gx, gy, devs)
            self._draw_node(gx, gy, f"GW\n{gw_ip}", "blue", True, gw_ip)

    def _draw_cluster(self, gx, gy, devices):
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
                self._draw_node(dx, dy, f".{dev['ip'].split('.')[-1]}", "green", False, dev['ip'])
            placed += count
            cur_r += step_r

    def _draw_node(self, x, y, text, color, is_gw, ip):
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
                dev = next((d for d in self.latest_scan_data if d['ip'] == ip), None)
                vendor = "Unknown"
                mac = "Unknown"
                if dev:
                    mac = dev['mac']
                    vendor = dev.get('vendor', 'Unknown')
                messagebox.showinfo(f"Details: {ip}", f"IP: {ip}\nMAC: {mac}\nVendor: {vendor}")
                break