import os
import sys
import tkinter as tk

def set_app_icon(root):
    """Safely loads the application icon."""
    try:
        # PyInstaller logic (sys._MEIPASS is temp folder where it unzips)
        if getattr(sys, 'frozen', False):
            base_path = sys._MEIPASS
        else:
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        possible_paths = [
            os.path.join(base_path, "assets", "app_icon.png"),
            os.path.join(base_path, "app_icon.png")
        ]
        
        icon_path = None
        for p in possible_paths:
            if os.path.exists(p):
                icon_path = p
                break
        
        if icon_path:
            icon_img = tk.PhotoImage(file=icon_path)
            root.iconphoto(True, icon_img)
            # Keep reference to avoid Garbage Collection
            root._icon_ref = icon_img 
    except Exception as e:
        print(f"Debug: Icon load error: {e}")