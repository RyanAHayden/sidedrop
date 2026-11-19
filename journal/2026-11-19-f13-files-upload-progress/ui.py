"""Drive Manage > Files for Friends in headless Chromium with the upload throttled: rows mid-upload, leaving and coming back,
the finished rows, then an upload the server can't write (red row) and its Retry.
Run: uv run -q --no-project --with-requirements requirements.txt --with playwright python ui.py <repo> <shots dir>"""
import os, sys, tempfile, threading
from pathlib import Path
d = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(d), PASSWORD="friends-pass-long", ADMIN_PASSWORD="admin-pass-long", SECRET_KEY="k" * 32, PUBLIC_URL="http://127.0.0.1:8766")
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
shots = Path(sys.argv[2])
src = Path(tempfile.mkdtemp())
(src / "GMPE01.iso").write_bytes(os.urandom(27 * 1000 * 1000))
(src / "Save Data.zip").write_bytes(os.urandom(6 * 1000 * 1000))
(src / "readme.txt").write_bytes(b"hello")
(d / "files").mkdir()
(d / "files" / "old notes.txt").write_bytes(b"x" * 1234)
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    pg = b.new_page(viewport={"width": 390, "height": 844})
    cdp = pg.context.new_cdp_session(pg)
    pg.goto("http://127.0.0.1:8766/?password=admin-pass-long")
    pg.goto("http://127.0.0.1:8766/#settings")
    pg.wait_for_timeout(800)
    pg.click("a[href='/admin']")
    pg.wait_for_timeout(1200)
    pg.click(".layer a[href='/admin/files']")
    pg.wait_for_selector(".layer #upf", state="attached")
    pg.wait_for_timeout(600)
    print("upload button gone:", pg.locator(".layer button:visible", has_text="Upload").count() == 0)
    cdp.send("Network.enable")
    cdp.send("Network.emulateNetworkConditions", {"offline": False, "latency": 20, "downloadThroughput": -1, "uploadThroughput": 1500000})  # bytes/s
    pg.set_input_files(".layer #upf", [str(src / "GMPE01.iso"), str(src / "Save Data.zip")])
    pg.wait_for_timeout(4000)
    print("mid:", pg.locator(".layer .uprow small").all_text_contents())
    pg.screenshot(path=shots / "1-mid-upload.png")
    pg.set_input_files(".layer #upf", [str(src / "readme.txt")])  # more while others upload
    pg.go_back()
    pg.wait_for_timeout(1500)
    pg.click(".layer a[href='/admin/files']")
    pg.wait_for_selector(".layer .uprow")
    pg.wait_for_timeout(1000)
    print("reopened:", pg.locator(".layer .uprow small").all_text_contents())
    pg.screenshot(path=shots / "2-reopened.png")
    pg.wait_for_function("!document.querySelector('.layer .uprow')", timeout=120000)
    pg.wait_for_timeout(400)
    print("done rows:", pg.locator(".layer .row[data-file]").evaluate_all("rs=>rs.map(r=>r.innerText.replace(/\\n/g,' | '))"))
    print("on disk:", sorted((p.name, p.stat().st_size) for p in (d / "files").iterdir()))
    pg.screenshot(path=shots / "3-done.png")
    cdp.send("Network.emulateNetworkConditions", {"offline": False, "latency": 0, "downloadThroughput": -1, "uploadThroughput": -1})
    (d / "files").chmod(0o500)
    pg.set_input_files(".layer #upf", [str(src / "readme.txt")])
    pg.wait_for_selector(".layer .uprow.bad")
    pg.wait_for_timeout(300)
    print("error:", pg.locator(".layer .uprow.bad small").text_content())
    pg.screenshot(path=shots / "4-error.png")
    (d / "files").chmod(0o700)
    pg.click(".layer .uprow.bad button:has-text('RETRY')")
    pg.wait_for_function("!document.querySelector('.layer .uprow')", timeout=10000)
    print("retried:", (d / "files" / "readme.txt").read_bytes())
    b.close()
srv.shutdown()
