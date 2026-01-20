
import webview
import os
import sys

# Configura o caminho do arquivo
map_url = "file:///" + r"C:\Users\jonas\Desktop\PyNetSketch\PyNetSketch\traceroute_map.html".replace("\\", "/")

if __name__ == '__main__':
    # Cria a janela nativa flutuante
    webview.create_window('Global Network Route', map_url, width=1100, height=750)
    webview.start()
