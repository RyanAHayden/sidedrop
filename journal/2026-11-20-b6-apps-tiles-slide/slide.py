"""Scratch (B6): serve the page for a registered fake iPhone; in Chromium at 390 px tap Help and Registered on the Apps tab and sample the slide.
run: uv run --no-project --with-requirements requirements.txt --with playwright python -I slide.py <repo> <outdir>"""
import os, sys, tempfile, threading, json
from pathlib import Path
tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", PUBLIC_URL="http://127.0.0.1:5078", SECRET_KEY="k" * 32, BUNDLE_ID="com.me.*")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start, A.SOURCES = start, []
A.resign = lambda *a, **k: None
A.profile_udids = lambda: {"UDID-1"}
A.app.config["SESSION_COOKIE_SECURE"] = False
(tmp / "signed").mkdir(exist_ok=True)
(tmp / "devices.json").write_text(json.dumps({"at": 1, "data": [{"id": "D1", "attributes": {"udid": "UDID-1", "name": "Sam's iPhone", "model": "iPhone 15 Pro"}}]}))
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 5078, A.app, threaded=True); threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
out = sys.argv[2]
STATE = """() => {const L=[...document.querySelectorAll('.layer')];return {settingsShown:!document.getElementById('t-settings').hidden,
 appsShown:!document.getElementById('t-apps').hidden,hash:location.hash,nav:navT.textContent,
 layers:L.map(l=>({tab:l.dataset.tab,hidden:l.hidden,title:l.querySelector('h1').textContent,back:l.querySelector('.back').textContent,
  x:Math.round(l.getBoundingClientRect().left)}))}}"""
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    ctx = b.new_context(viewport={"width": 390, "height": 800}, has_touch=True, is_mobile=True, device_scale_factor=2)
    ctx.add_cookies([{"name": "device", "value": A.device_token("UDID-1"), "url": "http://127.0.0.1:5078"}])
    pg = ctx.new_page(); errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto("http://127.0.0.1:5078/?password=hunter2-but-longer"); pg.wait_for_timeout(800)

    def tap_and_sample(sel, name):
        pg.click(sel)
        samples = []
        for i in range(8):  # 8 samples over ~560 ms: the slide is 350 ms
            pg.wait_for_timeout(70); s = pg.evaluate(STATE); samples.append(s)
            if i == 2: pg.screenshot(path=f"{out}/{name}-mid.png")
        pg.screenshot(path=f"{out}/{name}-open.png")
        return samples

    def back_and_sample(name):
        pg.click(".layer:not([hidden]) .back")
        samples = []
        for i in range(8):
            pg.wait_for_timeout(70); samples.append(pg.evaluate(STATE))
            if i == 2: pg.screenshot(path=f"{out}/{name}-back-mid.png")
        pg.screenshot(path=f"{out}/{name}-back.png")
        return samples

    for sel, name in (("#t-apps a.tile[href='/help']", "help"), ("#t-apps a.tile.reg", "registered")):
        s = tap_and_sample(sel, name)
        print(name, "open: settings ever shown:", any(x["settingsShown"] for x in s), "hash:", {x["hash"] for x in s},
              "layer x over time:", [x["layers"][-1]["x"] if x["layers"] else None for x in s], "final:", s[-1]["layers"])
        if name == "registered": print("  rows:", pg.locator(".layer .row").all_inner_texts())
        s = back_and_sample(name)
        print(name, "back: settings ever shown:", any(x["settingsShown"] for x in s), "layer x over time:",
              [x["layers"][-1]["x"] if x["layers"] else None for x in s], "final:", s[-1])

    # Help from Settings: still pushed over Settings, Back says Settings
    pg.click(".tabs a[href='#settings']"); pg.wait_for_timeout(200)
    pg.click("#helpRow"); pg.wait_for_timeout(600); print("settings help:", pg.evaluate(STATE)["layers"])
    pg.click(".layer:not([hidden]) .back"); pg.wait_for_timeout(600); print("settings help back:", pg.evaluate(STATE)["layers"])

    # Theme pushed on Settings, then Help on Apps: Help's Back says SideDrop and returns to Apps; Settings still has Theme
    pg.click("a[href='/theme']"); pg.wait_for_timeout(600)
    pg.click(".tabs a[href='#apps']"); pg.wait_for_timeout(200)
    s = tap_and_sample("#t-apps a.tile[href='/help']", "help-over-theme")
    print("help over theme: settings ever shown:", any(x["settingsShown"] for x in s), s[-1]["layers"])
    back_and_sample("help-over-theme"); st = pg.evaluate(STATE); print("after back:", st)
    pg.click(".tabs a[href='#settings']"); pg.wait_for_timeout(200); print("settings tab:", pg.evaluate(STATE)["layers"])
    pg.click(".tabs a[href='#settings']"); pg.wait_for_timeout(600); print("settings tab tapped again (pops Theme):", pg.evaluate(STATE)["layers"])

    # Developer Mode alert's helpOpen('dev') from the iFizBox tab: pushed over iFizBox with Developer Mode open
    pg.click(".tabs a[href='#ifizbox']"); pg.wait_for_timeout(200)
    pg.evaluate("helpOpen('dev')"); pg.wait_for_timeout(900)
    print("dev from ifizbox:", pg.evaluate(STATE)["layers"], "dev open:", pg.evaluate("tabTop().querySelector('details#dev').open"))
    pg.screenshot(path=f"{out}/dev-ifizbox.png")
    pg.click(".layer:not([hidden]) .back"); pg.wait_for_timeout(600); print("back:", pg.evaluate(STATE))
    print("errors", errs)
    b.close()
srv.shutdown()
