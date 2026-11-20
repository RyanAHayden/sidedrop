"""F26 screenshots on docs/readme_shots.py's demo data at 375pt: Settings (admin and friend), Help (with Register iPhone Didn't Work open),
Add to Home Screen, Manage, in Classic and OLED Black; then a push check: Help pushed from Settings, the alert's Show Me opening Help at
Developer Mode, and the Theme row's detail following a pick.

    uv run -q --no-project --with-requirements requirements.txt --with playwright --with pillow python \
        journal/2026-11-19-f26-settings-rewrite/shots.py OUT
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


def full(pg, path):
    """The page's whole scroller: #scr (a tab) or the page alone (a pushed page opened on its own) is made as tall as its content."""
    h = pg.evaluate("(()=>{let s=document.querySelector('.lscroll')||document.getElementById('scr')||document.scrollingElement;return s.scrollHeight})()")
    pg.set_viewport_size({"width": 375, "height": max(667, h + 60)})
    pg.wait_for_timeout(300)
    pg.screenshot(path=str(path))
    pg.set_viewport_size({"width": 375, "height": 667})


with sync_playwright() as p:
    browser, pg = g["browse"](p)
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(f"{BASE}/?password=demo-admin-pass")
    pg.goto(f"{BASE}/?enrolled={A.device_token(g['UDID'])}")
    for tone, n in (("light", "classic"), ("dark", "oled")):
        pg.evaluate(f"localStorage.clear();localStorage.pushAsked=1;localStorage.devTold=1;localStorage.mode='{tone}';localStorage['{tone}Theme']='{n}'")
        pg.goto(BASE + "/#settings")
        pg.reload()
        pg.wait_for_load_state("networkidle")
        pg.wait_for_timeout(800)
        print(n, "theme detail:", pg.inner_text("#themeV"))
        full(pg, out / f"settings-admin-{n}.png")
        for path, name in (("/help", "help"), ("/home-screen", "home-screen"), ("/admin", "manage")):
            pg.goto(BASE + path)
            pg.wait_for_load_state("networkidle")
            if name == "help":
                pg.evaluate("document.getElementById('register').open=true")
            full(pg, out / f"{name}-{n}.png")
    # pushes in the app: Settings > Help, back; the Developer Mode alert's Show Me; the Theme row after a pick
    pg.evaluate("localStorage.clear();localStorage.pushAsked=1;localStorage.devTold=1;localStorage.mode='light'")
    pg.goto(BASE + "/#settings")
    pg.reload()
    pg.wait_for_load_state("networkidle")
    pg.click("#helpRow")
    pg.wait_for_timeout(900)
    print("pushed:", pg.evaluate("L&&L.querySelector('h1').textContent"), "back says", pg.evaluate("L&&L.querySelector('.back').textContent"))
    pg.screenshot(path=str(out / "pushed-help.png"))
    pg.evaluate("history.back();0")
    pg.wait_for_timeout(900)
    print("after back: layers", pg.evaluate("LS.length"))
    pg.evaluate("go('apps');devAsk.hidden=false;0")
    pg.click("#devAsk button:not(.ok)")  # Show Me
    pg.wait_for_timeout(1400)
    print("Show Me: tab", pg.evaluate("cur"), "page", pg.evaluate("L&&L.querySelector('h1').textContent"),
          "dev open", pg.evaluate("!!(L&&L.querySelector('#dev').open)"))
    pg.screenshot(path=str(out / "show-me.png"))
    pg.evaluate("history.back();0")
    pg.wait_for_timeout(900)
    pg.click("#sTheme a[href='/theme']")
    pg.wait_for_timeout(900)
    pg.click("a[href='/theme/light']")
    pg.wait_for_timeout(900)
    pg.click("[data-v=sepia]")
    pg.wait_for_timeout(300)
    pg.evaluate("history.back();0")
    pg.wait_for_timeout(700)
    pg.evaluate("history.back();0")
    pg.wait_for_timeout(900)
    print("after picking Sepia, the Theme row says:", pg.inner_text("#themeV"))
    # the Apps header's Help tile
    pg.evaluate("go('apps');0")
    pg.click(".hw a[href='/help']")
    pg.wait_for_timeout(900)
    print("Help tile: tab", pg.evaluate("cur"), "page", pg.evaluate("L&&L.querySelector('h1').textContent"))
    pg.evaluate("history.back();0")
    pg.wait_for_timeout(700)
    pg.evaluate("go('apps');0")
    pg.wait_for_timeout(300)
    pg.screenshot(path=str(out / "apps-header.png"))
    # a friend (not the admin): no Manage row
    pg.goto(BASE + "/logout")
    pg.goto(f"{BASE}/?password=demo-friends-pass")
    pg.goto(BASE + "/#settings")
    pg.wait_for_load_state("networkidle")
    full(pg, out / "settings-friend-classic.png")
    print("friend: Manage row", pg.evaluate("!!document.getElementById('sManage')"))
    print("page errors:", errors)
    browser.close()
srv.shutdown()
print("wrote", out)
