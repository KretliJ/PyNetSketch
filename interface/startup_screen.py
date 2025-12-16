import tkinter as tk
import os

class SplashScreen:
    def __init__(self, root, image_path=None):
        self.root = root
        self.splash = tk.Toplevel(root)
        
        # --- Configurações Visuais ---
        self.width = 420
        self.height = 500
        self.bg_color = '#2b2b2b'
        self.border_color = '#444444'
        self.accent_color = '#00ff00'
        self.text_color = '#e0e0e0'
        self.corner_radius = 25

        # Centralizar
        ws = self.splash.winfo_screenwidth()
        hs = self.splash.winfo_screenheight()
        x = (ws // 2) - (self.width // 2)
        y = (hs // 2) - (self.height // 2)
        self.splash.geometry(f'{self.width}x{self.height}+{x}+{y}')

        # Transparência e Canvas
        self.splash.overrideredirect(True)
        self.transparent_key = '#ff00ff' 
        self.splash.attributes('-transparentcolor', self.transparent_key)
        self.splash.config(bg=self.transparent_key)

        self.canvas = tk.Canvas(
            self.splash, 
            width=self.width, height=self.height, 
            bg=self.transparent_key, 
            highlightthickness=0
        )
        self.canvas.pack(fill='both', expand=True)

        self._draw_rounded_panel(2, 2, self.width-3, self.height-3, self.corner_radius)

        # --- ELEMENTOS VISUAIS (LAYOUT FLUIDO) ---
        
        # Cursor vertical inicial (Padding do topo)
        current_y = 30 

        # 1. LOGO (Lógica de "Objeto Sólido") 👇
        self.logo_img = None
        if image_path and os.path.exists(image_path):
            try:
                self.logo_img = tk.PhotoImage(file=image_path)
                img_w = self.logo_img.width()
                img_h = self.logo_img.height()
                
                # Se a imagem for muito grande, limitamos o espaço visual
                # Mas aqui desenhamos ela considerando seu centro
                self.canvas.create_image(
                    self.width // 2, 
                    current_y + (img_h // 2), # O Canvas ancora no centro da imagem
                    image=self.logo_img, 
                    anchor='center'
                )
                
                # A MÁGICA: Empurramos o cursor para baixo baseando-se na ALTURA REAL + Padding
                current_y += img_h + 10 
            except: 
                pass
        else:
            # Se não tem imagem, dá um espacinho extra para o texto não colar no teto
            current_y += 20
        # 👆 Fim da Lógica da Logo

        # 2. Título
        self.canvas.create_text(
            self.width // 2, current_y+10,
            text="PyNetSketch",
            font=("Consolas", 22, "bold"),
            fill=self.accent_color
        )
        # Empurra cursor (Tamanho da fonte aprox + padding)
        current_y += 35 

        # 3. Subtítulo
        self.canvas.create_text(
            self.width // 2, current_y,
            text="Network Analysis Tool",
            font=("Segoe UI", 9),
            fill="#888888"
        )
        current_y += 40 

        # 4. Throbber (Spinner)
        # Ajustamos o centro do throbber para o novo Y
        self.spinner_angle = 0
        self.spinner_ids = []
        self.throbber_x = self.width // 2
        self.throbber_y = current_y + 15 # +15 é o raio aproximado para centralizar o círculo
        self.throbber_radius = 22
        
        self._animate_throbber()

        # Empurra cursor (Tamanho do Throbber + padding)
        current_y += 60 

        # 5. Texto de Status
        self.status_text_id = self.canvas.create_text(
            self.width // 2, current_y,
            text="Initializing...", 
            font=("Segoe UI", 10), 
            fill=self.text_color
        )
        current_y += 20

        # 6. Porcentagem
        self.pct_text_id = self.canvas.create_text(
            self.width // 2, current_y,
            text="0%",
            font=("Consolas", 8),
            fill="#666666"
        )
        
        self.splash.update()
    # --- Métodos Públicos ---
    def update_status(self, text, progress_val):
        self.canvas.itemconfig(self.status_text_id, text=text)
        self.canvas.itemconfig(self.pct_text_id, text=f"{progress_val}%")
        self.splash.update()

    def close(self):
        self.splash.destroy()

    # --- Métodos Internos de Desenho ---

    def _animate_throbber(self):
        if not self.splash.winfo_exists(): return

        for item in self.spinner_ids: self.canvas.delete(item)
        self.spinner_ids.clear()

        # 1. Anel de fundo (Mais fino e sutil agora)
        bg_ring = self.canvas.create_oval(
            self.throbber_x - self.throbber_radius, self.throbber_y - self.throbber_radius,
            self.throbber_x + self.throbber_radius, self.throbber_y + self.throbber_radius,
            outline="#3a3a3a", width=3 # Cinza bem escuro e fino
        )
        self.spinner_ids.append(bg_ring)

        # 2. Arco ativo (Verde brilhante)
        # Extensão de 90 graus para parecer mais rápido
        arc = self.canvas.create_arc(
            self.throbber_x - self.throbber_radius, self.throbber_y - self.throbber_radius,
            self.throbber_x + self.throbber_radius, self.throbber_y + self.throbber_radius,
            start=self.spinner_angle, extent=100, style="arc",
            outline=self.accent_color, width=3 # Mesma largura do fundo
        )
        self.spinner_ids.append(arc)

        # Gira mais rápido (20 graus por frame)
        self.spinner_angle = (self.spinner_angle - 20) % 360 
        self.root.after(30, self._animate_throbber)

    def _draw_rounded_panel(self, x1, y1, x2, y2, r):
        """Desenha o painel de fundo usando um polígono suavizado"""
        # Truque para suavizar bordas no Tkinter: desenhar a borda e o preenchimento separadamente
        
        # Pontos do polígono arredondado
        points = (x1+r, y1, x1+r, y1, x2-r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y1+r, 
                  x2, y2-r, x2, y2-r, x2, y2, x2-r, y2, x2-r, y2, x1+r, y2, x1+r, y2, 
                  x1, y2, x1, y2-r, x1, y2-r, x1, y1+r, x1, y1+r, x1, y1)
        
        # Desenha o preenchimento (sem borda)
        self.canvas.create_polygon(points, fill=self.bg_color, outline="", smooth=True)
        
        # Desenha a borda por cima (mais fina para esconder serrilhados)
        self.canvas.create_polygon(points, fill="", outline=self.border_color, width=1.5, smooth=True)