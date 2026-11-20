"""F25 screenshots and a tap check: Home's iFizBox card at 375pt (iPhone SE/8 width) on docs/readme_shots.py's demo data, in light
(Classic) and dark (OLED Black); then its INSTALL tapped: the iFizBox page opens with the install console running, ifzRun ran once,
and leaving for Apps and coming back doesn't run it again.

    uv run -q --no-project --with-requirements requirements.txt --with playwright --with pillow python \
        journal/2026-11-19-f25-ifizbox-card-install/shots.py OUT
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
g["IPHONE"]["viewport"] = {"width": 375, "height": 667}
A = g["A"]
srv, BASE = g["serve"]()
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser, pg = g["browse"](p)
    pg.goto(f"{BASE}/?password=demo-admin-pass")
    pg.goto(f"{BASE}/?enrolled={A.device_token(g['UDID'])}")
    for tone, n in (("light", "classic"), ("dark", "oled")):
        pg.evaluate(f"localStorage.clear();localStorage.pushAsked=1;localStorage.mode='{tone}';localStorage['{tone}Theme']='{n}'")
        pg.goto(BASE + "/#apps")
        pg.reload()
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(1200)
        pg.evaluate("document.querySelector('.ifzr').scrollIntoView({block:'center'})")
        pg.wait_for_timeout(300)
        pg.locator(".ifzr").screenshot(path=str(out / f"card-{n}.png"))
        pg.screenshot(path=str(out / f"home-{n}.png"))
        print(n, "rec line", pg.evaluate("(()=>{let r=document.querySelector('.ifzr .rec');return {w:r.clientWidth,sw:r.scrollWidth,h:r.clientHeight}})()"),
              "button", pg.locator(".ifzr .get").inner_text(), pg.locator(".ifzr .get").get_attribute("class"))
    # the tap: count ifzRun's runs (the trailing 0: Playwright would call a function the expression returned)
    pg.evaluate("window.runs=0;let r0=ifzRun;ifzRun=function(){runs++;return r0.apply(this,arguments)};0")
    pg.evaluate("document.querySelector('.ifzr .get').click()")
    pg.wait_for_timeout(800)
    print("after tap: hash", pg.evaluate("location.hash"), "runs", pg.evaluate("runs"), "console open", pg.evaluate("!con.hidden"),
          "card", pg.evaluate("document.querySelector('.ifzr .get').textContent"))
    pg.screenshot(path=str(out / "after-tap.png"))
    pg.evaluate("conClose();go('apps');0")
    pg.wait_for_timeout(400)
    pg.evaluate("go('ifizbox');0")
    pg.wait_for_timeout(600)
    print("back and again: hash", pg.evaluate("location.hash"), "runs", pg.evaluate("runs"), "console open", pg.evaluate("!con.hidden"))
    browser.close()
srv.shutdown()
print("wrote", out)
