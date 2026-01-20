import tkinter as tk
from tkinter import ttk, messagebox
import math
import net_utils

class TopologyTab(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.latest_scan_data = []
        
        # --- ESTADO DE TEMA (Inicia Light por padrão) ---
        self.colors = {
            "bg": "white",
            "link_gw": "#4a90e2",   # Azul Conexão GW
            "link_dev": "#dddddd",  # Cinza Conexão Device
            "node_gw": "blue",
            "node_dev": "green",
            "outline": "black",
            "text": "black"
        }

        # Inicializa Canvas com a cor de fundo dinâmica
        self.canvas = tk.Canvas(self, bg=self.colors["bg"], highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        self.canvas.bind("<Button-1>", self.on_canvas_click)

    # --- NOVO MÉTODO: TROCA DE TEMA ---
    def update_theme(self, is_dark):
        if is_dark:
            # Paleta Cyberpunk
            self.colors = {
                "bg": "#161e2b",         # Fundo igual ao app
                "link_gw": "#3b8ed0",    # Azul Neon para GW
                "link_dev": "#2a3b55",   # Azul Escuro Sutil para Devices
                "node_gw": "#3b8ed0",    # Ciano
                "node_dev": "#00ff00",   # Verde Matrix
                "outline": "#e1e6ef",    # Borda Clara
                "text": "#e1e6ef"        # Texto Claro
            }
        else:
            # Paleta Clássica
            self.colors = {
                "bg": "white",
                "link_gw": "#4a90e2",
                "link_dev": "#dddddd",
                "node_gw": "blue",
                "node_dev": "green",
                "outline": "black",
                "text": "black"
            }
        
        # Aplica a cor de fundo imediatamente
        self.canvas.config(bg=self.colors["bg"])
        
        # Se houver dados, redesenha o mapa inteiro com as novas cores
        if self.latest_scan_data:
            self.draw_topology_map()

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
                # USA A COR DINÂMICA
                self.canvas.create_line(curr[0], curr[1], nxt[0], nxt[1], fill=self.colors["link_gw"], width=4)
        
        for gx, gy, gw_ip, devs in gw_nodes:
            self._draw_cluster(gx, gy, devs)
            # USA A COR DINÂMICA
            self._draw_node(gx, gy, f"GW\n{gw_ip}", self.colors["node_gw"], True, gw_ip)

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
                # USA A COR DINÂMICA
                self.canvas.create_line(gx, gy, dx, dy, fill=self.colors["link_dev"], dash=dash)
                self._draw_node(dx, dy, f".{dev['ip'].split('.')[-1]}", self.colors["node_dev"], False, dev['ip'])
            placed += count
            cur_r += step_r

    def _draw_node(self, x, y, text, color, is_gw, ip):
        r = 25 if is_gw else 15
        tag = f"device:{ip}"
        # USA A COR DINÂMICA (Outline e Texto)
        self.canvas.create_oval(x-r, y-r, x+r, y+r, fill=color, outline=self.colors["outline"], tags=tag)
        self.canvas.create_text(x, y+r+12, text=text, font=("Arial", 8), fill=self.colors["text"], tags=tag)

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