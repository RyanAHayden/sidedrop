"""Scratch (B18): serve the page for a registered fake iPhone with one signed app; in Chromium at 375 px hold its Apps row, shoot the
action sheet open (light and dark), tap Mark as Installed and sample the sheet while it slides away.
run: uv run --no-project --with-requirements requirements.txt --with playwright python -I shots.py <repo> <outdir>"""
import os, sys, tempfile, threading, json, zipfile, plistlib
from pathlib import Path
tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", PUBLIC_URL="http://127.0.0.1:5079", SECRET_KEY="k" * 32, BUNDLE_ID="com.me.*")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start, A.SOURCES = start, []
A.resign = lambda *a, **k: None
A.profile_udids = lambda: {"UDID-1"}
A.app.config["SESSION_COOKIE_SECURE"] = False
(tmp / "signed").mkdir(exist_ok=True)
with zipfile.ZipFile(tmp / "signed" / "Plain.ipa", "w") as z:
    z.writestr("Payload/Plain.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.me.plain", "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0", "CFBundleName": "Plain"}))
(tmp / "devices.json").write_text(json.dumps({"at": 1, "data": [{"id": "D1", "attributes": {"udid": "UDID-1", "name": "Sam's iPhone", "model": "iPhone 15 Pro"}}]}))
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 5079, A.app, threaded=True); threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
out = sys.argv[2]
STATE = """() => {const s=mkSheet,p=s.querySelector('.mkp'),r=p.getBoundingClientRect();return {hidden:s.hidden,out:s.classList.contains('out'),
 top:Math.round(r.top),h:Math.round(r.height),dim:getComputedStyle(s.querySelector('.mkd')).opacity}}"""
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    for theme in ("light", "dark"):
        ctx = b.new_context(viewport={"width": 375, "height": 667}, has_touch=True, is_mobile=True, device_scale_factor=2, color_scheme=theme)
        ctx.add_cookies([{"name": "device", "value": A.device_token("UDID-1"), "url": "http://127.0.0.1:5079"}])
        pg = ctx.new_page(); errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto("http://127.0.0.1:5079/?password=hunter2-but-longer"); pg.wait_for_timeout(800)
        row = pg.locator("#t-apps .g .row", has=pg.locator('.get[data-app="Plain"]')).first
        row.scroll_into_view_if_needed(); bb = row.bounding_box()
        x, y = bb["x"] + 80, bb["y"] + bb["height"] / 2
        pg.mouse.move(x, y); pg.mouse.down(); pg.wait_for_timeout(700); pg.mouse.up()
        pg.wait_for_timeout(500)
        pg.screenshot(path=f"{out}/{theme}-open.png")
        print(theme, "open:", pg.evaluate(STATE), "buttons:", pg.locator("#mkB button").all_inner_texts())
        pg.click("#mkB button")
        samples = []
        for i in range(6):
            samples.append(pg.evaluate(STATE))
            if i == 1: pg.screenshot(path=f"{out}/{theme}-closing.png")
            pg.wait_for_timeout(60)
        pg.wait_for_timeout(300); samples.append(pg.evaluate(STATE))
        pg.screenshot(path=f"{out}/{theme}-closed.png")
        print(theme, "closing samples:", samples)
        print(theme, "button now:", pg.locator('.get[data-app="Plain"]').first.inner_text())
        print("errors", errs)
        ctx.close()
    print("errors", errs)
    b.close()
srv.shutdown()
