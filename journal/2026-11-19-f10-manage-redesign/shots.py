"""F10 screenshots: Manage and its pages, rendered by the real app (Flask test client answers Chromium's requests)."""
import datetime, json, os, sys, tempfile, time
from pathlib import Path

repo, out = Path(sys.argv[1]), Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PUBLIC_URL="https://x.test", SECRET_KEY="k" * 32, BUNDLE_ID="com.me.*")
sys.path.insert(0, str(repo))
import threading
start, threading.Thread.start = threading.Thread.start, lambda self: None  # no source sync from the internet, as test_app.py
import app as A
threading.Thread.start, A.SOURCES = start, []
A.sync_if_stale = lambda *a: None
A.save_json(A.SETUP, {"password": A.hash_password("friends-pass-long"), "admin_password": A.hash_password("admin-pass-long"), "asc_role": "admin"})
from cryptography import x509 as X
from cryptography.hazmat.primitives import hashes as H, serialization as S
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12

k = ec.generate_private_key(ec.SECP256R1())
now = datetime.datetime.now(datetime.timezone.utc)
nm = X.Name([X.NameAttribute(X.oid.NameOID.COMMON_NAME, "Apple Distribution: Sam Test (TEAM123456)")])
crt = X.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(k.public_key()).serial_number(5) \
    .not_valid_before(now - datetime.timedelta(days=30)).not_valid_after(now + datetime.timedelta(days=20)).sign(k, H.SHA256())
A.P12.write_bytes(pkcs12.serialize_key_and_certificates(b"sd", k, crt, None, S.BestAvailableEncryption(b"pw")))
A.P12_PASSWORD = "pw"
A.ASC_KEY.write_text("x")
os.environ["ASC_KEY_ID"], os.environ["ASC_ISSUER_ID"] = "ABCDE12345", "i"
devs = [{"id": f"D{i}", "attributes": {"name": n, "udid": f"00008130-000{i}AB12CD34EF", "status": s, "addedDate": d + "T10:00:00.000+0000", "model": m}}
        for i, (n, m, s, d) in enumerate([("Ryan's iPhone", "iPhone 15 Pro", "ENABLED", "2026-03-02"), ("Sam's iPhone", "iPhone 13", "ENABLED", "2026-05-14"),
                                          ("Alex", "iPhone 12 mini", "ENABLED", "2026-08-21"), ("Old iPhone 8", "iPhone 8", "DISABLED", "2025-12-01")])]
A.save_json(A.DEVICES, {"at": time.time() - 3 * 86400, "data": devs[:3]})  # the saved list is older: Alex... and the disabled one come with Apple's answer
A.save_json(A.SEEN, {devs[0]["attributes"]["udid"]: int(time.time()), devs[1]["attributes"]["udid"]: int(time.time()) - 5 * 86400})
A.asc = lambda m, path, **kw: {"data": devs if path == "/devices" else []}
(tmp / "files").mkdir()
(tmp / "files" / "GMPE01.iso").write_bytes(b"x" * 300000)
(tmp / "files" / "notes.txt").write_bytes(b"hello")
A.cert_status()  # Apple's checks (stubbed) answered once, as on a running server

c = A.app.test_client()
assert c.get("/?password=admin-pass-long").status_code == 302

from playwright.sync_api import sync_playwright
held = []


def handle(route):
    req = route.request
    path = req.url.split("x.test", 1)[1] or "/"
    if path.startswith("/admin/devices.json") and hold["on"]:
        held.append(route)
        return
    r = c.open(path, method=req.method, data=req.post_data_buffer, headers={k: v for k, v in req.headers.items() if k.lower() == "content-type"})
    route.fulfill(status=r.status_code, headers={k: v for k, v in r.headers.items() if k.lower() not in ("content-length",)}, body=r.data)


hold = {"on": True}
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    for theme in ("light", "dark"):
        pg = b.new_page(viewport={"width": 390, "height": 760}, device_scale_factor=2, color_scheme=theme)
        pg.route("https://x.test/**", handle)
        shot = lambda name: pg.screenshot(path=str(out / f"{name}-{theme}.png"))
        pg.goto("https://x.test/#settings")
        pg.wait_for_timeout(800)
        pg.evaluate("document.querySelectorAll('.scrim').forEach(s=>s.hidden=true)")
        pg.click("a.tile[href='/admin']")
        pg.wait_for_timeout(700)
        shot("1-manage")
        hold["on"] = True
        pg.click(".layer a[href='/admin/iphones']")
        pg.wait_for_timeout(700)
        shot("2-iphones-loading")
        hold["on"] = False
        for r in held:
            handle(r)
        held.clear()
        pg.wait_for_timeout(500)
        shot("3-iphones")
        pg.click(".layer:last-of-type a[href='/admin/iphone/D1']")
        pg.wait_for_timeout(700)
        shot("4-iphone")
        assert pg.evaluate("LS.length") == 3, pg.evaluate("LS.length")
        pg.go_back(); pg.wait_for_timeout(600)
        pg.go_back(); pg.wait_for_timeout(600)
        assert pg.evaluate("LS.length") == 1
        for i, (href, name) in enumerate([("signing", "5-signing"), ("passwords", "6-passwords"), ("files", "7-files"),
                                          ("sources", "8-sources"), ("ifizbox", "9-ifizbox")]):
            pg.click(f".layer a.mrow[href='/admin/{href}']")
            pg.wait_for_timeout(700)
            if href == "signing":
                pg.click(".layer:last-of-type summary"); pg.wait_for_timeout(300)
                pg.set_viewport_size({"width": 390, "height": 1900})
            shot(name)
            pg.set_viewport_size({"width": 390, "height": 760})
            pg.go_back(); pg.wait_for_timeout(600)
        pg.close()
    b.close()
print("ok", out)
