import tkinter as tk
from tkinter import ttk
import collections

class TrafficTab(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        
        # --- Toolbar de Filtro ---
        self.control_frame = ttk.Frame(self)
        self.control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(self.control_frame, text="Filter IP:").pack(side="left")
        
        self.filter_entry = ttk.Entry(self.control_frame, width=15)
        self.filter_entry.pack(side="left", padx=5)
        
        ttk.Label(self.control_frame, text="(Leave empty for all traffic)").pack(side="left", padx=5)

        # --- Área do Gráfico ---
        self.traffic_canvas = tk.Canvas(self, bg="#222222") 
        self.traffic_canvas.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Filas de dados para as duas linhas (Total e Filtrado)
        self.total_data = collections.deque([0]*60, maxlen=60)
        self.filtered_data = collections.deque([0]*60, maxlen=60)

    def get_filter_ip(self):
        """Retorna o IP digitado ou None se vazio. É chamado pelo gui_app.py"""
        val = self.filter_entry.get().strip()
        return val if val else None

    def reset_data(self):
        self.total_data = collections.deque([0]*60, maxlen=60)
        self.filtered_data = collections.deque([0]*60, maxlen=60)

    def add_data_point(self, data):
        # Suporta tanto tupla (total, filtrado) quanto int único (apenas total)
        if isinstance(data, (tuple, list)):
            total, filtered = data
        else:
            total = data
            filtered = 0 
            
        self.total_data.append(total)
        self.filtered_data.append(filtered)
        self.draw_traffic_graph()

    def draw_traffic_graph(self):
        self.traffic_canvas.delete("all")
        w = self.traffic_canvas.winfo_width()
        h = self.traffic_canvas.winfo_height()
        if w < 50: w=800; h=400
        
        # Pega o máximo baseado no TOTAL para escala
        data_total = list(self.total_data)
        data_filtered = list(self.filtered_data)
        
        max_val = max(data_total) if data_total and max(data_total) > 10 else 10
        h_factor = (h - 20) / max_val
        x_step = w / (len(data_total) - 1) if len(data_total) > 1 else w

        # Legendas
        self.traffic_canvas.create_text(10, 10, text=f"Max Total: {max_val} pps", fill="#00ff00", anchor="nw")
        
        last_filtered = data_filtered[-1] if data_filtered else 0
        self.traffic_canvas.create_text(10, 25, text=f"Filtered: {last_filtered} pps", fill="yellow", anchor="nw")

        # Função auxiliar para gerar coordenadas
        def get_points(dataset):
            pts = []
            for i, val in enumerate(dataset):
                x = i * x_step
                y = h - (val * h_factor) - 10
                pts.append(x)
                pts.append(y)
            return pts

        # Desenha Linha TOTAL (Verde)
        points_total = get_points(data_total)
        if len(points_total) >= 4:
            self.traffic_canvas.create_line(points_total, fill="#00ff00", width=2, smooth=True)

        # Desenha Linha FILTRADA (Amarela)
        if max(data_filtered) > 0:
            points_filtered = get_points(data_filtered)
            if len(points_filtered) >= 4:
                self.traffic_canvas.create_line(points_filtered, fill="yellow", width=2, smooth=True, dash=(4, 2))