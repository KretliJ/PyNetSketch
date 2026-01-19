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

        # --- CORREÇÃO DE JANELA (Sempre no Topo) ---
        self.splash.overrideredirect(True)
        self.splash.attributes('-topmost', True) 
        self.splash.lift()                        
        self.splash.focus_force()

# Configuração de Transparência Multiplataforma
        self.transparent_key = '#ff00ff'
        
        if os.name == 'nt': # Windows
            try:
                self.splash.attributes('-transparentcolor', self.transparent_key)
                self.splash.config(bg=self.transparent_key)
            except:
                self.splash.config(bg=self.bg_color)
        else: # Linux / macOS
            self.splash.attributes('-alpha', 0.95)
            self.splash.config(bg=self.bg_color)

        self.canvas = tk.Canvas(
            self.splash, 
            width=self.width, height=self.height, 
            bg=self.bg_color if os.name != 'nt' else self.transparent_key, 
            highlightthickness=0
        )
        self.canvas.pack(fill='both', expand=True)

        self._draw_rounded_panel(2, 2, self.width-3, self.height-3, self.corner_radius)

        # --- ELEMENTOS VISUAIS ---
        current_y = 30 
        self.logo_img = None
        if image_path and os.path.exists(image_path):
            try:
                self.logo_img = tk.PhotoImage(file=image_path)
                img_h = self.logo_img.height()
                self.canvas.create_image(
                    self.width // 2, current_y + (img_h // 2),
                    image=self.logo_img, anchor='center'
                )
                current_y += img_h + 10 
            except: pass
        else:
            current_y += 20

        self.canvas.create_text(self.width // 2, current_y+20, text="PyNetSketch", font=("Consolas", 22, "bold"), fill=self.accent_color)
        current_y += 35 

        self.canvas.create_text(self.width // 2, current_y+10, text="Network Analysis Tool", font=("Segoe UI", 9), fill="#888888")
        current_y += 40 

        # Throbber
        self.spinner_angle = 0
        self.spinner_ids = []
        self.throbber_x = self.width // 2
        self.throbber_y = current_y + 15 
        self.throbber_radius = 22
        
        self.animation_id = None 
        self._animate_throbber()

        current_y += 60 

        self.status_text_id = self.canvas.create_text(self.width // 2, current_y, text="Initializing...", font=("Segoe UI", 10), fill=self.text_color)
        current_y += 20

        self.pct_text_id = self.canvas.create_text(self.width // 2, current_y, text="0%", font=("Consolas", 8), fill="#666666")
        
        # Não chamamos self.splash.update() aqui pois o mainloop cuidará disso
        # Apenas forçamos o processamento inicial de eventos
        self.splash.update_idletasks()

    def update_status(self, text, progress_val):
        """
        ATENÇÃO: Este método agora é Thread-Safe.
        Ele não atualiza a GUI diretamente, mas agenda a atualização
        para a thread principal usando self.root.after.
        """
        try:
            self.root.after(0, lambda: self._safe_update(text, progress_val))
        except:
            pass

    def _safe_update(self, text, progress_val):
        """Método interno que roda apenas na thread principal"""
        if not self.splash.winfo_exists(): return
        self.canvas.itemconfig(self.status_text_id, text=text)
        self.canvas.itemconfig(self.pct_text_id, text=f"{progress_val}%")
        # Removido self.splash.update() pois é redundante e perigoso com mainloop rodando

    def close(self):
        if self.animation_id:
            try:
                self.root.after_cancel(self.animation_id)
                self.animation_id = None
            except: pass
            
        try:
            self.splash.destroy()
        except: pass

    def _animate_throbber(self):
        if not self.splash.winfo_exists(): return

        for item in self.spinner_ids: self.canvas.delete(item)
        self.spinner_ids.clear()

        bg_ring = self.canvas.create_oval(
            self.throbber_x - self.throbber_radius, self.throbber_y - self.throbber_radius,
            self.throbber_x + self.throbber_radius, self.throbber_y + self.throbber_radius,
            outline="#3a3a3a", width=3
        )
        self.spinner_ids.append(bg_ring)

        arc = self.canvas.create_arc(
            self.throbber_x - self.throbber_radius, self.throbber_y - self.throbber_radius,
            self.throbber_x + self.throbber_radius, self.throbber_y + self.throbber_radius,
            start=self.spinner_angle, extent=100, style="arc",
            outline=self.accent_color, width=3
        )
        self.spinner_ids.append(arc)

        self.spinner_angle = (self.spinner_angle - 20) % 360 
        
        self.animation_id = self.root.after(30, self._animate_throbber)

    def _draw_rounded_panel(self, x1, y1, x2, y2, r):
        points = (x1+r, y1, x1+r, y1, x2-r, y1, x2-r, y1, x2, y1, x2, y1+r, x2, y1+r, 
                  x2, y2-r, x2, y2-r, x2, y2, x2-r, y2, x2-r, y2, x1+r, y2, x1+r, y2, 
                  x1, y2, x1, y2-r, x1, y2-r, x1, y1+r, x1, y1+r, x1, y1)
        self.canvas.create_polygon(points, fill=self.bg_color, outline="", smooth=True)
        self.canvas.create_polygon(points, fill="", outline=self.border_color, width=1.5, smooth=True)