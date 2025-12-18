from PIL import Image

# Abre o PNG original
img = Image.open("assets/app_icon.png")

# Salva como ICO contendo APENAS o tamanho máximo
# O Windows será forçado a usar este e reduzir conforme necessário
img.save("assets/app_icon.ico", format='ICO', sizes=[(32, 32)])

print("Ícone de força bruta (256x256) gerado.")