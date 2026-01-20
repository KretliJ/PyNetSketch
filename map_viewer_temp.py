
import webview
import os
import sys

# --- CORREÇÃO PARA LINUX (ROOT) ---
# O QtWebEngine bloqueia execução como root.
# Precisamos passar a flag --no-sandbox via variável de ambiente.
if hasattr(sys, 'platform') and sys.platform.startswith('linux'):
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox"

# Configura o caminho do arquivo
map_url = "file:///" + r"/home/jonas/Área de trabalho/PyNetSketch/PyNetSketch/traceroute_map.html".replace("\\", "/")

if __name__ == '__main__':
    webview.create_window('Global Network Route', map_url, width=1100, height=750)
    webview.start()
