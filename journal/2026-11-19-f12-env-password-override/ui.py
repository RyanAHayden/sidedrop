"""Drive the Passwords page in WebKit: pushed from Manage, the .env confirm alert, then Use .env Password."""
import os, sys, tempfile, threading, json
from pathlib import Path
d = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(d), PASSWORD="env-friends-pass", ADMIN_PASSWORD="env-admin-pass", SECRET_KEY="k" * 32, PUBLIC_URL="http://127.0.0.1:8765")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start = start
A.SOURCES = []
A.asc = lambda *a, **k: {"data": []}
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 8765, A.app, threaded=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
shots = Path(sys.argv[2])
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    pg = b.new_page(viewport={"width": 390, "height": 844})
    pg.goto("http://127.0.0.1:8765/?password=env-admin-pass")
    pg.goto("http://127.0.0.1:8765/#settings")
    pg.wait_for_timeout(800)
    pg.click("a[href='/admin']")
    pg.wait_for_timeout(1200)
    pg.click(".layer a[href='/admin/passwords']")
    pg.wait_for_timeout(1500)
    pg.screenshot(path=shots / "0-after-click.png")
    print(pg.url, pg.evaluate("[...document.querySelectorAll('input[name=password]')].map(i=>i.closest('[class]').className+' / '+(i.closest('.layer')?'layer':'-'))"))
    pg.wait_for_selector(".layer input[name=password]")
    pg.wait_for_timeout(600)
    pg.screenshot(path=shots / "1-page.png")
    pg.fill(".layer input[name=password]", "new-friends-pass")
    pg.click(".layer form button:not(.grey)")
    pg.wait_for_selector(".layer .ask-env:not([hidden])")
    pg.wait_for_timeout(500)
    pg.screenshot(path=shots / "2-alert.png")
    assert not json.loads((d / "setup.json").read_text() if (d / "setup.json").exists() else "{}").get("password_override")
    pg.click(".layer .ask-env .ok")
    pg.wait_for_selector(".layer >> text=Saved.")
    print("override saved:", "password_override" in (d / "setup.json").read_text(), A.password_ok("new-friends-pass"))
    pg.wait_for_timeout(400)
    pg.screenshot(path=shots / "3-saved.png")
    pg.click(".layer form[data-ask=use] button")
    pg.wait_for_selector(".layer .ask-use:not([hidden])")
    pg.click(".layer .ask-use .ok")
    pg.wait_for_selector(".layer >> text=works again")
    print("env back:", A.password_ok("env-friends-pass"), "still admin:", "Use .env Password" not in pg.content())
    pg.screenshot(path=shots / "4-env.png")
    b.close()
srv.shutdown()
