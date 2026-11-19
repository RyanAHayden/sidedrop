"""Screenshots for F17 in headless Chromium, 390x844 at 2x: python ui.py <repo> <out dir> setup|friend
setup: a new server (no PASSWORD), signed in with the default password, on the setup splash.
friend: signed in with the friends' password, not registered: the sign-in page, Apps (setup tile open), About, Help.
"""
import os, sys, tempfile, threading
from pathlib import Path
mode = sys.argv[3]
d = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(d), SECRET_KEY="k" * 32, PUBLIC_URL="http://127.0.0.1:8766")
if mode == "friend":
    os.environ.update(PASSWORD="friends-pass-long", ADMIN_PASSWORD="admin-pass-long")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start = start
A.SOURCES = []
A.asc = lambda *a, **k: {"data": []}
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 8766, A.app, threaded=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
out = Path(sys.argv[2])
U = "http://127.0.0.1:8766"
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    pg = b.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2)
    if mode == "setup":
        pg.goto(U + "/")
        pg.fill("input[name=password]", "sidedrop")
        pg.click("form button")
        pg.wait_for_url(U + "/setup")
        pg.wait_for_timeout(500)
        pg.screenshot(path=out / "setup.png")
    else:
        pg.goto(U + "/")
        pg.wait_for_timeout(300)
        pg.screenshot(path=out / "signin.png")
        pg.fill("input[name=password]", "friends-pass-long")
        pg.click("form button")
        pg.wait_for_timeout(800)
        pg.screenshot(path=out / "apps.png")
        pg.click("header.nav button.bar")
        pg.wait_for_timeout(400)
        pg.screenshot(path=out / "about.png")
        pg.click("#about .ok")
        pg.click("#setupT")
        pg.evaluate("document.getElementById('reg').scrollIntoView()")
        pg.wait_for_timeout(300)
        pg.screenshot(path=out / "apps-register.png")
        pg.evaluate("go('settings')")
        pg.wait_for_timeout(400)
        pg.evaluate("document.getElementById('helpNote').scrollIntoView({block:'center'})")
        pg.wait_for_timeout(300)
        pg.screenshot(path=out / "help.png")
    b.close()
srv.shutdown()
