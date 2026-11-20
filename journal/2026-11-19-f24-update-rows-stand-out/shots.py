"""F24 screenshots: the Apps tab on docs/readme_shots.py's demo data (its iPhone installed an older Trailhead, so that row is an
update), in light (Classic) and dark (OLED Black): a 1x view of the page and 3x zooms of the update row, an up-to-date row,
the update row with its UPDATE button held, and the tab bar with its count.

    uv run -q --no-project --with-requirements requirements.txt --with playwright --with pillow python \
        journal/2026-11-19-f24-update-rows-stand-out/shots.py OUT
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


def zoom(pg, name, loc):
    if loc.count():
        loc.first.screenshot(path=str(out / f"zoom-{name}.png"))
    else:
        print("missing", name)


with sync_playwright() as p:
    browser, pg = g["browse"](p)
    pg.goto(f"{BASE}/?password=demo-admin-pass")
    pg.goto(f"{BASE}/?enrolled={A.device_token(g['UDID'])}")
    for tone, n in (("light", "classic"), ("dark", "oled")):
        pg.evaluate(f"localStorage.clear();localStorage.pushAsked=1;localStorage.mode='{tone}';localStorage['{tone}Theme']='{n}'")
        pg.goto(BASE + "/#apps")
        pg.reload()
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(1500)
        up = pg.locator("#t-apps .row.up")
        pg.evaluate("document.querySelector('#t-apps .row.up').scrollIntoView({block:'center'})")  # clear of the fixed tab bar
        pg.wait_for_timeout(300)
        f = out / f"apps-{n}.png"
        pg.screenshot(path=str(f))
        Image.open(f).resize((402, 874)).save(f, optimize=True)
        zoom(pg, f"update-row-{n}", up)
        zoom(pg, f"plain-row-{n}", pg.locator("#t-apps .row:not(.up):has(.get)"))
        zoom(pg, f"tabbar-{n}", pg.locator(".tabs"))
        pg.evaluate("document.querySelector('#t-apps .row.up .get').classList.add('is-pressed')")
        zoom(pg, f"update-row-pressed-{n}", up)
        pg.evaluate("document.querySelector('#t-apps .row.up .get').classList.remove('is-pressed')")
    browser.close()
srv.shutdown()
print("wrote", out)
