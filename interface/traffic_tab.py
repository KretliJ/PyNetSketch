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
    """
    Responsável apenas por desenhar na tela.
    Não faz cálculos de soma nem decide ordenação.
    """
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        
        # Injeção/Composição do Gerenciador de Dados
        self.manager = TrafficDataManager()

        # --- Toolbar de Filtro ---
        self.control_frame = ttk.Frame(self)
        self.control_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(self.control_frame, text="Filter IP:").pack(side="left")
        
        self.filter_entry = ttk.Entry(self.control_frame, width=15)
        self.filter_entry.pack(side="left", padx=5)
        
        ttk.Label(self.control_frame, text="(Leave empty for all traffic)").pack(side="left", padx=5)

        # --- Layout Dividido (PanedWindow) ---
        self.paned = ttk.PanedWindow(self, orient=tk.VERTICAL)
        self.paned.pack(fill="both", expand=True, padx=5, pady=5)

        # 1. Área do Gráfico (Topo)
        self.graph_frame = ttk.Frame(self.paned)
        self.traffic_canvas = tk.Canvas(self.graph_frame, bg="#222222", height=200) 
        self.traffic_canvas.pack(fill="both", expand=True)
        self.paned.add(self.graph_frame, weight=3)
        
        # 2. Área da Lista de IPs (Fundo)
        self.list_frame = ttk.Frame(self.paned)
        self.paned.add(self.list_frame, weight=2)

        # --- Configuração da Tabela ---
        columns = ("source_ip", "current", "total")
        self.ip_tree = ttk.Treeview(self.list_frame, columns=columns, show="headings")
        
        self.ip_tree.heading("source_ip", text="Source IP")
        self.ip_tree.heading("current", text="Last Interval (pps)")
        self.ip_tree.heading("total", text="Total Packets")
        
        self.ip_tree.column("source_ip", width=200, anchor="center")
        self.ip_tree.column("current", width=120, anchor="center")
        self.ip_tree.column("total", width=120, anchor="center")
        
        self.scrollbar = ttk.Scrollbar(self.list_frame, orient="vertical", command=self.ip_tree.yview)
        self.ip_tree.configure(yscroll=self.scrollbar.set)
        
        self.ip_tree.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # --- Menu de Contexto (Right Click) ---
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Filter by this Host", command=self.apply_selected_filter)
        
        # Vincula o botão direito (Button-3 no Windows/Linux, Button-2 no Mac às vezes)
        self.ip_tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Seleciona a linha sob o cursor e mostra o menu."""
        # Identifica a linha onde ocorreu o clique
        item_id = self.ip_tree.identify_row(event.y)
        
        if item_id:
            # Seleciona visualmente a linha clicada
            self.ip_tree.selection_set(item_id)
            # Exibe o menu na posição do mouse
            self.context_menu.post(event.x_root, event.y_root)

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
            self.filter_entry.delete(0, tk.END)
            self.filter_entry.insert(0, ip)
            
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
        
        # Pega dados limpos do Manager
        data_total, data_filtered = self.manager.get_graph_data()
        
        max_val = max(data_total) if data_total and max(data_total) > 10 else 10
        h_factor = (h - 20) / max_val
        
        x_step = w / (len(data_total) - 1) if len(data_total) > 1 else w

        # Desenha legendas
        self.traffic_canvas.create_text(10, 10, text=f"Max Total: {max_val} pps", fill="#00ff00", anchor="nw")
        last_filtered = data_filtered[-1] if data_filtered else 0
        self.traffic_canvas.create_text(10, 25, text=f"Filtered: {last_filtered} pps", fill="yellow", anchor="nw")

        def get_points(dataset):
            pts = []
            for i, val in enumerate(dataset):
                x = i * x_step
                y = h - (val * h_factor) - 10
                pts.append(x)
                pts.append(y)
            return pts

        points_total = get_points(data_total)
        if len(points_total) >= 4:
            self.traffic_canvas.create_line(points_total, fill="#00ff00", width=2, smooth=True)

        if max(data_filtered) > 0:
            points_filtered = get_points(data_filtered)
            if len(points_filtered) >= 4:
                self.traffic_canvas.create_line(points_filtered, fill="yellow", width=2, smooth=True, dash=(4, 2))