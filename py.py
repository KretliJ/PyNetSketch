from PIL import Image

img = Image.open("assets/app_icon.png")

# Removemos o 16x16 da lista.
# Mantemos 256 (Explorer Grande), 48 (Atalhos) e 32 (Barra de Tarefas/Janela)
img.save("assets/app_icon.ico", format='ICO', sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32)])

print("Ícone Golden Master gerado (Sem camada 16x16).")