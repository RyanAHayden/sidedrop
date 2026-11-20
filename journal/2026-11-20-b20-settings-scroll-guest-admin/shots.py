"""Scratch (B20): serve SideDrop for a registered fake iPhone; in Chromium at 375x667 open the Settings tab as a password user (friend)
and as a one-iPhone invite guest, measure whether it scrolls, wheel/scroll it to the bottom and shoot it; then push Admin Login.
run: uv run --no-project --with-requirements requirements.txt --with playwright python -I shots.py <repo> <outdir>"""
import os, sys, tempfile, threading, json, time
from pathlib import Path
tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", ADMIN_PASSWORD="admin-pass-20", PUBLIC_URL="http://127.0.0.1:5080",
                  SECRET_KEY="k" * 32, BUNDLE_ID="com.me.*")
sys.path.insert(0, sys.argv[1])
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start, A.SOURCES = start, []
A.resign = lambda *a, **k: None
A.profile_udids = lambda: {"UDID-1", "UDID-2"}
A.app.config["SESSION_COOKIE_SECURE"] = False
(tmp / "devices.json").write_text(json.dumps({"at": 1, "data": [{"id": "D1", "attributes": {"udid": "UDID-1", "name": "Sam's iPhone", "model": "iPhone 15 Pro"}}]}))
(tmp / "invites.json").write_text(json.dumps({"tok20": {"name": "Sam", "made": int(time.time()), "exp": int(time.time()) + 86400, "udid": "UDID-2",
                                                       "device": "iPhone", "used": int(time.time()), "sid": "x"}}))
from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 5080, A.app, threaded=True); threading.Thread(target=srv.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright
out = sys.argv[2]


def drag(cdp, pg, x=187, y0=550, y1=150):
    """A finger drag up the screen in raw touch events (Input.synthesizeScrollGesture scrolled nothing, even a plain test scroller)."""
    cdp.send("Input.dispatchTouchEvent", {"type": "touchStart", "touchPoints": [{"x": x, "y": y0}]})
    for i in range(1, 21):
        cdp.send("Input.dispatchTouchEvent", {"type": "touchMove", "touchPoints": [{"x": x, "y": y0 + (y1 - y0) * i / 20}]}); pg.wait_for_timeout(16)
    cdp.send("Input.dispatchTouchEvent", {"type": "touchEnd", "touchPoints": []})



M = """() => {const s=document.getElementById('scr'),t=document.getElementById('t-settings'),cs=e=>{const c=getComputedStyle(e);return c.overflow+'/'+c.height};
 return {scrTop:s.scrollTop,scrH:s.scrollHeight,clientH:s.clientHeight,scr:cs(s),html:cs(document.documentElement),body:cs(document.body),tab:cs(t),
 tabHidden:t.hidden,admin:!!document.getElementById('adminRow'),signout:!!document.querySelector('a[href="/logout"]')}}"""
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    for who, udid, login in (("user", "UDID-1", "/?password=hunter2-but-longer"), ("guest", "UDID-2", "/invite/tok20")):
        ctx = b.new_context(viewport={"width": 375, "height": 667}, has_touch=True, is_mobile=True, device_scale_factor=2)
        ctx.add_cookies([{"name": "device", "value": A.device_token(udid), "url": "http://127.0.0.1:5080"}])
        pg = ctx.new_page(); errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
        pg.goto("http://127.0.0.1:5080" + login); pg.goto("http://127.0.0.1:5080/#settings"); pg.wait_for_timeout(800)
        print(who, "before:", pg.evaluate(M))
        cdp = ctx.new_cdp_session(pg)  # a finger drag, as on the iPhone (a wheel is not the person's gesture)
        for _ in range(3):
            drag(cdp, pg)
        pg.wait_for_timeout(800)
        print(who, "after touch drags:", pg.evaluate(M))
        if os.environ.get("PROBE"):  # what blocks it: the touch-action / overscroll of what's under the finger
            print(who, "under finger:", pg.evaluate("""() => {let out=[],e=document.elementFromPoint(187,500);for(;e;e=e.parentElement){let c=getComputedStyle(e);
             out.push((e.id||e.className||e.tagName)+' ta='+c.touchAction+' ob='+c.overscrollBehaviorY+' ov='+c.overflowY)}return out}"""))
            pg.add_style_tag(content=os.environ["PROBE"]); pg.wait_for_timeout(300)
            for _ in range(3):
                drag(cdp, pg)
            pg.wait_for_timeout(800); print(who, "with", os.environ["PROBE"], pg.evaluate(M)["scrTop"])
        pg.screenshot(path=f"{out}/{who}-settings-bottom.png")
        if pg.locator("#adminRow").count():
            pg.click("#adminRow"); pg.wait_for_timeout(900)
            pg.screenshot(path=f"{out}/{who}-admin-login.png")
            pg.fill(".layer input[name=password]", "admin-pass-20"); pg.click(".layer form button"); pg.wait_for_timeout(1500)
            pg.screenshot(path=f"{out}/{who}-admin-after.png")
            print(who, "after login, Admin Settings on /:", "Admin Settings" in ctx.request.get("http://127.0.0.1:5080/").text())
        print(who, "errors", errs)
        ctx.close()
    b.close()
srv.shutdown()
