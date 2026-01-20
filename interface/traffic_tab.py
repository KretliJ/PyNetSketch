import tkinter as tk
from tkinter import ttk
import collections

# --- MODEL / LOGIC ---
class TrafficDataManager:
    """
    Responsável apenas por gerenciar os dados:
    - Acumular totais de pacotes por IP.
    - Manter o histórico (deque) para o gráfico.
    - Ordenar e preparar dados para exibição.
    """
    def __init__(self):
        self.persistent_totals = {} # {ip: total_count}
        self.total_data = collections.deque([0]*60, maxlen=60)
        self.filtered_data = collections.deque([0]*60, maxlen=60)

    def reset(self):
        self.persistent_totals.clear()
        self.total_data = collections.deque([0]*60, maxlen=60)
        self.filtered_data = collections.deque([0]*60, maxlen=60)

    def add_graph_point(self, data):
        """Adiciona ponto ao histórico do gráfico."""
        if isinstance(data, (tuple, list)):
            total, filtered = data
        else:
            total = data
            filtered = 0 
        
        self.total_data.append(total)
        self.filtered_data.append(filtered)

    def process_ip_batch(self, incoming_data):
        """
        Recebe a lista do Rust, atualiza persistência e retorna lista ordenada para UI.
        incoming_data: lista [(ip, count), ...] ou dict {ip: count}
        """
        # Normaliza entrada para dict
        if isinstance(incoming_data, dict):
            current_batch = incoming_data
        else:
            current_batch = {ip: count for ip, count in incoming_data}

        # Atualiza totais (Lógica de Negócio)
        for ip, count in current_batch.items():
            self.persistent_totals[ip] = self.persistent_totals.get(ip, 0) + count

        # Prepara lista para exibição (View Model)
        display_list = []
        for ip, total in self.persistent_totals.items():
            current_speed = current_batch.get(ip, 0)
            display_list.append((ip, current_speed, total))

        # Ordena por Total (Decrescente)
        display_list.sort(key=lambda x: x[2], reverse=True)
        
        return display_list

    def get_graph_data(self):
        return list(self.total_data), list(self.filtered_data)


# --- VIEW / UI ---
class TrafficTab(ttk.Frame):
    def __init__(self, master, *args, app=None, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.app = app
        self.manager = TrafficDataManager()
        
        # --- ESTADO DE CORES (Padrão Dark inicial) ---
        self.colors = {
            "bg": "#222222",
            "line_total": "#00ff00",     # Verde Matrix
            "line_filter": "yellow",     # Amarelo
            "text": "#00ff00",
            "grid": "#333333"
        }

        # --- Toolbar de Filtro ---
        self.control_frame = ttk.Frame(self)
        self.control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(self.control_frame, text="Filter IP:").pack(side="left")
        
        self.filter_entry = ttk.Entry(self.control_frame, width=15)
        self.filter_entry.config(state="disabled")
        self.filter_entry.pack(side="left", padx=5)
        
        ttk.Label(self.control_frame, text="(Right-click list to filter)").pack(side="left", padx=5)

        # --- Layout Dividido ---
        self.paned = ttk.PanedWindow(self, orient=tk.VERTICAL)
        self.paned.pack(fill="both", expand=True, padx=5, pady=5)

        # 1. Gráfico (Canvas)
        self.graph_frame = ttk.Frame(self.paned)
        self.traffic_canvas = tk.Canvas(self.graph_frame, bg=self.colors["bg"], height=200, highlightthickness=0) 
        self.traffic_canvas.pack(fill="both", expand=True)
        self.paned.add(self.graph_frame, weight=3)
        
        # 2. Lista (Treeview)
        self.list_frame = ttk.Frame(self.paned)
        self.paned.add(self.list_frame, weight=2)

        columns = ("source_ip", "current", "total")
        self.ip_tree = ttk.Treeview(self.list_frame, columns=columns, show="headings")
        
        self.ip_tree.heading("source_ip", text="Source IP")
        self.ip_tree.heading("current", text="PPS (Current)")
        self.ip_tree.heading("total", text="Total Packets")
        
        self.ip_tree.column("source_ip", width=200, anchor="center")
        self.ip_tree.column("current", width=120, anchor="center")
        self.ip_tree.column("total", width=120, anchor="center")
        
        self.scrollbar = ttk.Scrollbar(self.list_frame, orient="vertical", command=self.ip_tree.yview)
        self.ip_tree.configure(yscroll=self.scrollbar.set)
        
        self.ip_tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Menu de Contexto
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Filter by this Host", command=self.apply_selected_filter)
        self.ip_tree.bind("<Button-3>", self.show_context_menu)

    # --- NOVO MÉTODO: ATUALIZAÇÃO DE TEMA ---
    def update_theme(self, is_dark):
        if is_dark:
            self.colors = {
                "bg": "#161e2b",         # Fundo Cyberpunk Dark
                "line_total": "#00ff00", # Verde Neon
                "line_filter": "yellow",
                "text": "#e1e6ef",
                "grid": "#2a3b55"
            }
        else:
            self.colors = {
                "bg": "#ffffff",         # Fundo Branco
                "line_total": "#0078d7", # Azul Windows
                "line_filter": "#ff8c00",# Laranja Escuro (legível no branco)
                "text": "#000000",
                "grid": "#e0e0e0"
            }
        
        # Atualiza o fundo do Canvas imediatamente
        self.traffic_canvas.config(bg=self.colors["bg"])
        # Redesenha o gráfico com as novas cores
        self.draw_traffic_graph()

    def show_context_menu(self, event):
        """Seleciona a linha sob o cursor e mostra o menu."""
        # Identifica a linha onde ocorreu o clique
        item_id = self.ip_tree.identify_row(event.y)
        
        if item_id:
            # Seleciona visualmente a linha clicada
            self.ip_tree.selection_set(item_id)
            # Exibe o menu na posição do mouse
            self.context_menu.post(event.x_root, event.y_root)

    def update_theme(self, is_dark):
        style = ttk.Style()
        
        if is_dark:
            # --- MODO DARK ---
            graph_bg = "#161e2b"      # Fundo Azul Profundo (App)
            list_bg = "#161e2b"       # Fundo da Lista
            list_fg = "white"         # Texto da Lista
            list_field = "#161e2b"    # Área vazia da lista
            
            self.colors = {
                "bg": graph_bg,
                "line_total": "#00ff00", # Verde Neon
                "line_filter": "yellow",
                "text": "#e1e6ef",       # Texto do Gráfico
                "grid": "#2a3b55"
            }
        else:
            # --- MODO LIGHT (Híbrido) ---
            # O usuário pediu fundo do gráfico escuro mesmo no modo claro
            graph_bg = "#333333"      # Cinza Carvão (Dark Gray)
            
            # A lista deve ser clara para combinar com o resto do app Light
            list_bg = "white"
            list_fg = "black"
            list_field = "white"

            self.colors = {
                "bg": graph_bg,          # Gráfico continua escuro
                "line_total": "#00ff00", # Mantemos Verde (contrasta bem com cinza escuro)
                "line_filter": "yellow", # Mantemos Amarelo
                "text": "white",         # Texto do gráfico branco (pois o fundo é escuro)
                "grid": "#555555"
            }
        
        # 1. Atualiza o Canvas do Gráfico
        self.traffic_canvas.config(bg=self.colors["bg"])
        
        # 2. Atualiza a Lista (Treeview) - AQUI ESTAVA O PROBLEMA
        # Configuramos o estilo globalmente para garantir que pegue
        style.configure("Treeview", 
                        background=list_bg, 
                        foreground=list_fg, 
                        fieldbackground=list_field,
                        borderwidth=0)
        
        # Configura a cor da seleção (Azul padrão)
        select_bg = "#3b8ed0" if is_dark else "#0078d7"
        style.map("Treeview", 
                  background=[('selected', select_bg)], 
                  foreground=[('selected', 'white')])
        
        # Força atualização do cabeçalho também (opcional, mas bom para garantir)
        head_bg = "#1c2636" if is_dark else "#e1e1e1"
        head_fg = "white" if is_dark else "black"
        style.configure("Treeview.Heading", background=head_bg, foreground=head_fg)

        # 3. Redesenha o gráfico
        self.draw_traffic_graph()

    def apply_selected_filter(self):
        """Pega o IP da seleção atual e coloca no campo de filtro."""
        selected_items = self.ip_tree.selection()
        if not selected_items:
            return
            
        # Pega os valores da linha selecionada
        item = self.ip_tree.item(selected_items[0])
        values = item.get("values")
        
        if values:
            ip = values[0] # A primeira coluna é o Source IP
            
            # Atualiza o campo de texto
            self.filter_entry.config(state="normal")
            self.filter_entry.delete(0, tk.END)
            self.filter_entry.insert(0, ip)
            self.filter_entry.config(state="disabled")

            if hasattr(self, 'app') and (self.app.mode_var.get() == "Traffic Monitor"):
                self.app.stop_current_task()
                self.app.mode_var.set("Traffic Monitor")
                self._safe_restart_monitor(attempts=0)
            
            # Opcional: Feedback visual ou log (se necessário)
            # print(f"Filter set to {ip}. Please restart scan to apply.")

    def get_filter_ip(self):
        val = self.filter_entry.get().strip()
        return val if val else None

    def reset_data(self):
        # Reseta Lógica
        self.manager.reset()
        # Reseta Visual
        for item in self.ip_tree.get_children():
            self.ip_tree.delete(item)
        self.draw_traffic_graph()

    def add_data_point(self, data):
        # 1. Atualiza Modelo
        self.manager.add_graph_point(data)
        # 2. Atualiza Visual
        self.draw_traffic_graph()

    def _safe_restart_monitor(self, attempts=0):
        # Se a tarefa ainda consta como rodando e não tentou demais (limite de 3s)
        if self.app.task_running and attempts < 10:
            # Espera mais 300ms e tenta verificar de novo
            self.after(300, lambda: self._safe_restart_monitor(attempts + 1))
        else:
            # A pista está limpa (ou estourou o tempo), agora sim iniciamos
            self.app.start_selected_task() 

    def update_ip_table(self, incoming_data):
        # 1. Processa dados no Modelo
        display_data = self.manager.process_ip_batch(incoming_data)

        # 2. Atualiza Visual (apenas renderização)
        selected_items = self.ip_tree.selection()
        # Salva IPs selecionados para restaurar seleção após refresh
        selected_ips = [self.ip_tree.item(i)['values'][0] for i in selected_items] if selected_items else []

        for item in self.ip_tree.get_children():
            self.ip_tree.delete(item)

        for ip, current, total in display_data:
            item_id = self.ip_tree.insert("", "end", values=(ip, current, total))
            
            # Se este IP estava selecionado antes, seleciona de novo
            if str(ip) in selected_ips:
                self.ip_tree.selection_add(item_id)

    def draw_traffic_graph(self):
        self.traffic_canvas.delete("all")
        w = self.traffic_canvas.winfo_width()
        h = self.traffic_canvas.winfo_height()
        if w < 50: return 
        
        data_total, data_filtered = self.manager.get_graph_data()
        
        max_val = max(data_total) if data_total and max(data_total) > 10 else 10
        h_factor = (h - 20) / max_val
        x_step = w / (len(data_total) - 1) if len(data_total) > 1 else w

        # Grid Horizontal (Opcional, para visual pro)
        self.traffic_canvas.create_line(0, h-10, w, h-10, fill=self.colors["grid"])
        self.traffic_canvas.create_line(0, 10, w, 10, fill=self.colors["grid"])

        # Legendas Dinâmicas
        self.traffic_canvas.create_text(10, 10, text=f"Max: {max_val} pps", fill=self.colors["text"], anchor="nw", font=("Consolas", 9))
        
        last_filtered = data_filtered[-1] if data_filtered else 0
        if max(data_filtered) > 0:
            self.traffic_canvas.create_text(10, 25, text=f"Filter: {last_filtered} pps", fill=self.colors["line_filter"], anchor="nw", font=("Consolas", 9))

        def get_points(dataset):
            pts = []
            for i, val in enumerate(dataset):
                x = i * x_step
                y = h - (val * h_factor) - 10
                pts.append(x)
                pts.append(y)
            return pts

        # Linha Total
        points_total = get_points(data_total)
        if len(points_total) >= 4:
            self.traffic_canvas.create_line(points_total, fill=self.colors["line_total"], width=2, smooth=True)
            # Área sob a curva (opcional, efeito bonito)
            # poly_pts = points_total + [w, h, 0, h]
            # self.traffic_canvas.create_polygon(poly_pts, fill=self.colors["line_total"], stipple="gray25")

        # Linha Filtro
        if max(data_filtered) > 0:
            points_filtered = get_points(data_filtered)
            if len(points_filtered) >= 4:
                self.traffic_canvas.create_line(points_filtered, fill=self.colors["line_filter"], width=2, smooth=True, dash=(4, 2))