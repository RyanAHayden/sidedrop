"""F20 screenshots: the Settings tab (top and bottom) and, once it exists, Settings > Theme with its Light/Dark lists, in Classic
and OLED Black, on docs/readme_shots.py's demo data (its setup runs as is; only the captures are ours). 3x captures, plus 3x
zoomed crops of the controls (nav bar with back arrow, segmented control, switch, checkmark rows).

    uv run -q --no-project --with-requirements requirements.txt --with playwright --with pillow python \
        journal/2026-11-19-f20-ifizbox-theme-page/shots.py OUT [before]
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1])
before = len(sys.argv) > 2 and sys.argv[2] == "before"
out.mkdir(parents=True, exist_ok=True)
src = (ROOT / "docs" / "readme_shots.py").read_text()
sys.argv = [sys.argv[0], "--plain"]
g = {"__file__": str(ROOT / "docs" / "readme_shots.py"), "__name__": "shots"}
exec(compile(src[:src.index('raw = tmp / "raw"')], "readme_shots.py", "exec"), g)  # demo data, server and browser helpers
A = g["A"]
srv, BASE = g["serve"]()
from PIL import Image
from playwright.sync_api import sync_playwright

shots = []


def snap(pg, name):
    pg.wait_for_timeout(700)
    f = out / f"{name}.png"
    pg.screenshot(path=str(f))
    Image.open(f).resize((402, 874)).save(f, optimize=True)  # 1x for the journal; the zooms keep 3x
    shots.append(f)


def zoom(pg, name, sel):
    el = pg.locator(sel).first
    if el.count():
        el.screenshot(path=str(out / f"zoom-{name}.png"))


with sync_playwright() as p:
    browser, pg = g["browse"](p)
    pg.goto(f"{BASE}/?password=demo-admin-pass")
    pg.goto(f"{BASE}/?enrolled={A.device_token(g['UDID'])}")
    for tone, n in (("light", "classic"), ("dark", "oled")):
        pg.evaluate(f"localStorage.clear();localStorage.pushAsked=1;localStorage.mode='{tone}';localStorage['{tone}Theme']='{n}'")
        pg.goto(BASE + "/#settings")
        pg.reload()  # the same URL with a new hash doesn't load the page again
        pg.wait_for_load_state("networkidle")
        snap(pg, f"settings-{n}")
        pg.evaluate("scr.scrollTop=scr.scrollHeight")
        snap(pg, f"settings-bottom-{n}")
        pg.evaluate("scr.scrollTop=0")
        if before:
            continue
        pg.click("a[href='/theme']")
        snap(pg, f"theme-{n}")
        zoom(pg, f"nav-{n}", ".layer .nav")
        zoom(pg, f"seg-{n}", ".layer .seg")
        pg.click(f".layer a[href='/theme/{tone}']")
        snap(pg, f"theme-{tone}-{n}")
        zoom(pg, f"list-{n}", ".layer:last-of-type .g")
        zoom(pg, f"preview-{n}", ".layer:last-of-type .tpv")
        pg.go_back()
        pg.wait_for_timeout(500)
        pg.go_back()
        pg.wait_for_timeout(500)
    zoom(pg, "switch", ".sw")
    browser.close()
srv.shutdown()
ims = [Image.open(f).convert("RGB") for f in shots]
sheet = Image.new("RGB", (402 * len(ims) + 8 * (len(ims) - 1), 874), "white")
for i, im in enumerate(ims):
    sheet.paste(im, (i * 410, 0))
sheet.save(out / "sheet.png", optimize=True)
print("wrote", out / "sheet.png")
