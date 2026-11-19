"""F18 screenshots: Settings > Display, the Apps list and a pushed list page (iPhones, for the back arrow) in each of the nine
themes, on docs/readme_shots.py's demo data (its setup runs as is; only the captures are ours). One sheet per page, a column a theme.

    uv run -q --no-project --with-requirements requirements.txt --with playwright --with pillow python journal/2026-11-19-f18-themes/shots.py OUT
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
src = (ROOT / "docs" / "readme_shots.py").read_text()
sys.argv = [sys.argv[0], "--plain"]
g = {"__file__": str(ROOT / "docs" / "readme_shots.py"), "__name__": "shots"}
exec(compile(src[:src.index('raw = tmp / "raw"')], "readme_shots.py", "exec"), g)  # demo data, server and browser helpers
A = g["A"]
srv, BASE = g["serve"]()
from PIL import Image
from playwright.sync_api import sync_playwright

shots = {}
with sync_playwright() as p:
    browser, pg = g["browse"](p)
    pg.goto(f"{BASE}/?password=demo-admin-pass")
    pg.goto(f"{BASE}/?enrolled={A.device_token(g['UDID'])}")
    for n, (tone, label, color, _) in A.PALETTES.items():
        pg.evaluate(f"localStorage.clear();localStorage.pushAsked=1;localStorage.mode='{tone}';localStorage['{tone}Theme']='{n}'")
        for page, url, scroll in [("settings", "/#settings", "h3.hdr:text('Display')"), ("apps", "/#apps", None), ("iphones", "/admin/iphones", None)]:
            pg.goto(BASE + url)
            pg.wait_for_load_state("networkidle")
            if scroll:
                pg.evaluate("s=>{let e=[...document.querySelectorAll('h3.hdr')].find(h=>h.textContent==s);scr.scrollTop+=e.getBoundingClientRect().top-110}", "Display")
            pg.wait_for_timeout(700)
            assert pg.evaluate("[document.documentElement.dataset.theme,document.documentElement.dataset.palette]") == [tone, n]
            assert pg.evaluate("document.querySelector('meta[name=theme-color]').content") == color
            f = out / f"{page}-{n}.png"
            pg.screenshot(path=str(f))
            shots.setdefault(page, []).append(f)
    browser.close()
srv.shutdown()
for page, files in shots.items():  # a sheet: the nine side by side at 1/3 size (1x)
    ims = [Image.open(f).convert("RGB").resize((402, 874)) for f in files]
    sheet = Image.new("RGB", (402 * len(ims) + 8 * (len(ims) - 1), 874), "white")
    for i, im in enumerate(ims):
        sheet.paste(im, (i * 410, 0))
    sheet.save(out / f"sheet-{page}.png", optimize=True)
    print("wrote", out / f"sheet-{page}.png")
