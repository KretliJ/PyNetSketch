import tkinter as tk
from tkinter import ttk
import collections

class TrafficTab(ttk.Frame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.traffic_canvas = tk.Canvas(self, bg="#222222") 
        self.traffic_canvas.pack(fill="both", expand=True, padx=5, pady=5)
        # deque stores last 60 points
        self.traffic_data = collections.deque([0]*60, maxlen=60)

    def reset_data(self):
        self.traffic_data = collections.deque([0]*60, maxlen=60)

    def add_data_point(self, value):
        self.traffic_data.append(value)
        self.draw_traffic_graph()

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
        self.traffic_canvas.create_text(10, 10, text=f"Max: {max_val:.2f} pps", fill="white", anchor="nw")

        points = []
        for i, val in enumerate(data):
            x = i * x_step
            y = h - (val * h_factor) - 10 
            points.append(x)
            points.append(y)
        
        if len(points) >= 4:
            self.traffic_canvas.create_line(points, fill="#00ff00", width=2, smooth=True)