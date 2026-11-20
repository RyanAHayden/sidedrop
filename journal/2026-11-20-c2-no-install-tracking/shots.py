"""Scratch (C2): serve SideDrop for a registered fake iPhone with iFizBox, two plain apps and one that brings a file; in Chromium at
375x667 shoot the Apps tab (light and Gunmetal dark), the tab after one GET tap (armed INSTALL), and after a 1 s press on a row (no sheet).
run: uv run --no-project --with-requirements requirements.txt --with playwright python -I shots.py <repo> <outdir>"""
import os, sys, tempfile, threading, json, plistlib, zipfile
from pathlib import Path
tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", ADMIN_PASSWORD="admin-pass-c2", PUBLIC_URL="http://127.0.0.1:5082",
                  SECRET_KEY="k" * 32, BUNDLE_ID="com.me.*")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start, A.SOURCES = start, []
A.resign = lambda *a, **k: None
A.profile_udids = lambda: {"UDID-1"}
A.app.config["SESSION_COOKIE_SECURE"] = False
(tmp / "signed").mkdir(exist_ok=True); (tmp / "apps").mkdir(exist_ok=True)
for name, bid, title, short in (("com.ryha.ifizbox", "com.ryha.ifizbox", "iFizBox", "2.4"), ("Spotlight", "com.me.spot", "Spotlight", "1.3"),
                                ("Notes", "com.me.notes", "Notes Plus", "4.0.1"), ("Game", "com.me.game", "Retro Game", "0.9")):
    with zipfile.ZipFile(tmp / "signed" / f"{name}.ipa", "w") as z:
        z.writestr(f"Payload/{title}.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": bid, "CFBundleVersion": "1", "CFBundleShortVersionString": short, "CFBundleName": title}))
(tmp / "appfiles" / "Game").mkdir(parents=True); (tmp / "appfiles" / "Game" / "pack.zip").write_bytes(b"x" * 300000)
(tmp / "devices.json").write_text(json.dumps({"at": 1, "data": [{"id": "D1", "attributes": {"udid": "UDID-1", "name": "Sam's iPhone", "model": "iPhone 15 Pro"}}]}))
(tmp / "first_run.json").write_text(json.dumps({"UDID-1": 1}))
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 5082, A.app, threaded=True); threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
out = sys.argv[2]
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    for scheme in ("light", "dark"):
        ctx = b.new_context(viewport={"width": 375, "height": 667}, has_touch=True, is_mobile=True, device_scale_factor=2, color_scheme=scheme)
        ctx.add_cookies([{"name": "device", "value": A.device_token("UDID-1"), "url": "http://127.0.0.1:5082"}])
        pg = ctx.new_page(); errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto("http://127.0.0.1:5082/?password=hunter2-but-longer"); pg.goto("http://127.0.0.1:5082/#apps")
        if scheme == "dark":
            pg.evaluate("try{localStorage.theme=JSON.stringify({mode:'dark'})}catch(e){}"); pg.reload()
        pg.wait_for_timeout(800)
        pg.evaluate("document.getElementById('scr').scrollTo(0, document.querySelector('#t-apps h3.hdr').offsetTop - 70)"); pg.wait_for_timeout(300)
        pg.screenshot(path=f"{out}/apps-{scheme}.png")
        print(scheme, "buttons:", pg.eval_on_selector_all("#t-apps .get", "bs=>bs.map(b=>b.textContent)"), "badge:", pg.locator(".badge").count(), "errors:", errs)
        if scheme == "light":
            pg.click('#t-apps .get[data-app="Spotlight"]'); pg.wait_for_timeout(500)
            print("after one tap:", pg.text_content('#t-apps .get[data-app="Spotlight"]'))
            pg.screenshot(path=f"{out}/apps-armed.png")
            pg.mouse.click(5, 300); pg.wait_for_timeout(400)  # a tap elsewhere disarms
            box = pg.locator('#t-apps .row:has([data-app="Notes"]) > div:not(.ico)').bounding_box()
            pg.mouse.move(box["x"] + 20, box["y"] + 10); pg.mouse.down(); pg.wait_for_timeout(1000); pg.mouse.up(); pg.wait_for_timeout(500)
            print("after a 1 s press:", "dialogs:", pg.locator("[role=dialog]:visible").count(), "held rows:", pg.locator(".row.held").count())
            pg.screenshot(path=f"{out}/apps-after-press.png")
        ctx.close()
    b.close()
srv.shutdown()
