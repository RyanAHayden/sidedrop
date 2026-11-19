import sys
from PIL import Image, ImageDraw
og_path, icon_path = sys.argv[1], sys.argv[2]
og = Image.open(og_path).convert("RGB")
icon = Image.open(icon_path).convert("RGB")
S = 8  # supersample the mask for a smooth edge
m = Image.new("L", (300 * S, 300 * S), 0)
ImageDraw.Draw(m).rounded_rectangle((0, 0, 300 * S - 1, 300 * S - 1), radius=60 * S, fill=255)
m = m.resize((300, 300), Image.LANCZOS)
og.paste(icon, (150, 209), m)
og.save(og_path, optimize=True)
