"""Scratch: serve the page for a registered fake iPhone and hold its rows in Chromium (touch emulation)."""
import os, sys, plistlib, tempfile, threading, zipfile, json
from pathlib import Path
tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", PUBLIC_URL="http://127.0.0.1:5077", SECRET_KEY="k" * 32, BUNDLE_ID="com.me.*")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start, A.SOURCES = start, []
A.resign = lambda *a, **k: None
A.profile_udids = lambda: {"UDID-1"}
A.app.config["SESSION_COOKIE_SECURE"] = False
(tmp / "signed").mkdir(exist_ok=True)
def ipa(name, short, build):
    with zipfile.ZipFile(tmp / "signed" / f"{name}.ipa", "w") as z:
        z.writestr(f"Payload/{name}.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": f"com.me.{name.lower()}", "CFBundleVersion": build, "CFBundleShortVersionString": short, "CFBundleName": name}))
ipa("Alpha", "1.0", "1"); ipa("Beta", "2.0", "5"); ipa("Gamma", "3.0", "1")
(tmp / "installed.json").write_text(json.dumps({"UDID-1": {"Beta": "1.9/4", "Gamma": "3.0/1"}}))
(tmp / "first_run.json").write_text(json.dumps({"UDID-1": 1}))
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 5077, A.app, threaded=True); threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    ctx = b.new_context(viewport={"width": 390, "height": 800}, has_touch=True, is_mobile=True, device_scale_factor=2)
    ctx.add_cookies([{"name": "device", "value": A.device_token("UDID-1"), "url": "http://127.0.0.1:5077"}])
    pg = ctx.new_page(); errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto("http://127.0.0.1:5077/?password=hunter2-but-longer"); pg.wait_for_timeout(800)
    out = sys.argv[2]
    print("badge", pg.inner_text("#badge"), pg.is_hidden("#badge"))
    def hold(name, ms=700):
        el = pg.locator(f'#t-apps .row:has([data-app="{name}"]) > div:not(.ico)').first
        box = el.bounding_box(); x, y = box["x"] + 20, box["y"] + box["height"] / 2
        pg.mouse.move(x, y); pg.mouse.down(); pg.wait_for_timeout(ms)
        held = pg.evaluate(f'document.querySelector(\'#t-apps .row:has([data-app="{name}"])\').classList.contains("held")')
        pg.screenshot(path=f"{out}/held-{name}.png"); pg.mouse.up(); pg.wait_for_timeout(300)
        return held, pg.is_visible("#mkSheet"), [t for t in pg.locator("#mkSheet button").all_inner_texts()]
    print("short hold", hold("Alpha", 200))
    print("Alpha", hold("Alpha"))
    pg.screenshot(path=f"{out}/sheet-Alpha.png")
    pg.click("#mkB button"); pg.wait_for_timeout(800)
    print("after mark Alpha:", pg.inner_text('#t-apps [data-app="Alpha"]'), json.loads((tmp / "installed.json").read_text()))
    print("Beta", hold("Beta")); pg.screenshot(path=f"{out}/sheet-Beta.png")
    pg.click("#mkB button >> text=Mark as Updated"); pg.wait_for_timeout(800)
    print("after Beta:", pg.inner_text('#t-apps [data-app="Beta"]'), pg.inner_text("#badge"), pg.is_hidden("#badge"))
    print("Gamma", hold("Gamma")); pg.click("#mkB button"); pg.wait_for_timeout(800)
    print("after Gamma:", pg.inner_text('#t-apps [data-app="Gamma"]'), json.loads((tmp / "installed.json").read_text()))
    print("Cancel", hold("Gamma")); pg.click(".mkc"); print("closed", pg.is_hidden("#mkSheet"), pg.evaluate('document.querySelectorAll(".row.held").length'))
    print("errors", errs)
    b.close()
srv.shutdown()
