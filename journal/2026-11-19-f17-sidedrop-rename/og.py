"""Redraw static/og.png's words for F17: SideDrop in the nav bar and the title, the new tagline under it.

The card has no source file, so this keeps its pixels (nav gradient, pinstripes, the F6 icon and its shadow), paints the
old words out with copies of clean background, and draws the new ones in Liberation Sans at the sizes and colours
measured from the old card. Run: python og.py static/og.png
"""
import sys
from PIL import Image, ImageDraw, ImageFont

path = sys.argv[1]
im = Image.open(path).convert("RGB")
W, H = im.size
REG, BOLD = "/usr/share/fonts/liberation/LiberationSans-Regular.ttf", "/usr/share/fonts/liberation/LiberationSans-Bold.ttf"

# paint out: the nav gradient is the same in every column, the pinstripes the same in every row below the nav
col = im.crop((100, 0, 101, 88))
for x in range(300, 900):
    im.paste(col, (x, 0))
row = im.crop((470, 620, W, 621))
for y in range(250, 520):
    im.paste(row, (470, y))

d = ImageDraw.Draw(im)


def fit(font_path, sample, height):
    """The size at which `sample`'s ink is `height` px tall (the old card's measured box)."""
    s = 100
    for _ in range(4):
        b = ImageFont.truetype(font_path, s).getbbox(sample)
        s = round(s * height / (b[3] - b[1]))
    return ImageFont.truetype(font_path, s)


def text(xy, s, font, fill, shadow, off):
    d.text((xy[0] + off[0], xy[1] + off[1]), s, font=font, fill=shadow)
    d.text(xy, s, font=font, fill=fill)


# nav: white, a dark line above (iOS 6 bar title), centred like the old one (ink 518..681, 29..65 for "sidedrop")
nav = fit(BOLD, "sidedrop", 65 - 29)
b = nav.getbbox("SideDrop")
x, y = (W - (b[2] - b[0])) // 2 - b[0], 29 - nav.getbbox("sidedrop")[1]
text((x, y), "SideDrop", nav, (255, 255, 255), (62, 80, 105), (0, -1))

# title: #14161a with a white line under it; old ink 523..913, 285..381
title = fit(REG, "sidedrop", 381 - 285)
text((523 - title.getbbox("S")[0], 285 - title.getbbox("sidedrop")[1]), "SideDrop", title, (20, 22, 26), (255, 255, 255), (0, 3))

# tagline: bold #4c566c with a white line under it, two lines from x 525, the first ink top at 404, 54 px apart
tag = fit(BOLD, "Apps shared between friends,", 443 - 404)  # old first line's ink: 404..442, 525..1118
lines = ["Share an Apple developer account", "with friends and sideload apps."]
widest = max(tag.getbbox(s)[2] for s in lines)
if 525 + widest > W - 40:  # keep a margin on the right like the old card's
    tag = ImageFont.truetype(BOLD, int(tag.size * (W - 40 - 525) / widest))
top = 404 - tag.getbbox("Apps")[1]
for i, s in enumerate(lines):
    text((525, top + i * 54), s, tag, (76, 86, 108), (255, 255, 255), (0, 2))

im.save(path, optimize=True)
print("nav", nav.size, "title", title.size, "tagline", tag.size, "widest", widest)
