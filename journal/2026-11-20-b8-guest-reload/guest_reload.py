"""B8 repro: a one-iPhone invite guest taps Reload in headless Chromium. Run from the worktree root:
uv run -q --no-project --with-requirements requirements.txt --with playwright python journal/2026-11-20-b8-guest-reload/guest_reload.py \
    [nodevice] [offline] [revoke] [nameinput] [click=SELECTOR]
Fake data only (made-up UDID, apps and invite); Apple and zsign are stubbed; system Chromium."""
import atexit, datetime, os, plistlib, shutil, sys, tempfile, threading, time, zipfile
from pathlib import Path

ROOT = Path.cwd()
for k in ("PASSWORD", "ADMIN_PASSWORD", "BUNDLE_ID", "ASC_KEY_ID", "ASC_ISSUER_ID", "P12_PASSWORD", "SECRET_KEY", "SYNC_TOKEN", "PROFILE_CERT_DIR"):
    os.environ.pop(k, None)
tmp = Path(tempfile.mkdtemp(prefix="b8-"))
atexit.register(shutil.rmtree, tmp, True)
os.environ.update(DATA=str(tmp), PUBLIC_URL="https://apps.example.com", PASSWORD="demo-friends-pass", ADMIN_PASSWORD="demo-admin-pass",
                  SECRET_KEY="d" * 32, BUNDLE_ID="com.example.sideload", ASC_KEY_ID="DEMOKEY123",
                  ASC_ISSUER_ID="00000000-0000-0000-0000-000000000000", P12_PASSWORD="demo")
sys.path.insert(0, str(ROOT))
start, threading.Thread.start = threading.Thread.start, lambda self: None
import app as A
threading.Thread.start, A.SOURCES = start, []

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
subj = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Apple Distribution: Demo (DEMO123456)")])
cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key()).serial_number(7)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=330)).sign(key, hashes.SHA256()))
A.P12.write_bytes(pkcs12.serialize_key_and_certificates(b"demo", key, cert, None, serialization.BestAvailableEncryption(b"demo")))
A.ASC_KEY.write_text("demo")
A.cert_status = A.cert_status_cached = lambda *a, **k: []
UDID = "00008120-000DEMO0RHYS0001"
DEVICES = [{"id": "DEV0", "attributes": dict(name="Rhys iPhone", model="iPhone 15", udid=UDID, status="ENABLED", deviceClass="IPHONE",
                                              addedDate="2026-11-01T00:00:00.000+0000")}]
A.asc = lambda m, p, **kw: {"data": DEVICES if p == "/devices" else []}
A.regen_profile = lambda: A.PROFILE.write_bytes(plistlib.dumps({"ProvisionedDevices": [UDID], "ExpirationDate": now + datetime.timedelta(days=330),
                                                                 "Entitlements": {"application-identifier": "DEMO123456.com.example.sideload"}}))
A.sign_ipa = lambda src, out: shutil.copyfile(src, out)
A.save_json(A.DEVICES, {"at": time.time(), "data": DEVICES})
A.regen_profile()
A.APPS.mkdir()


def add_app(name, ver="1.0"):
    with zipfile.ZipFile(A.APPS / f"{name}.ipa", "w") as z:
        z.writestr(f"Payload/{name}.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": f"com.example.{name.lower()}", "CFBundleVersion": ver,
                                                                       "CFBundleShortVersionString": ver, "CFBundleName": name}))


add_app("Notepad")
WITH_DEVICE = "nodevice" not in sys.argv
t = time.time()
A.save_json(A.INVITES, {"rhysInvite000001": {"name": "Rhys", "made": t - 86400, "exp": t + 6 * 86400}})
A.save_json(A.FIRST_RUN, {UDID: t})

from werkzeug.serving import make_server
srv = make_server("127.0.0.1", 0, A.app, threaded=True)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://localhost:{srv.server_port}"
from playwright.sync_api import sync_playwright
ok = True
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium")
    ctx = b.new_context(viewport={"width": 402, "height": 874}, is_mobile=True, has_touch=True)
    ctx.add_init_script("try{localStorage.pushAsked=1}catch(e){}")
    pg = ctx.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.on("console", lambda m: errs.append("console: " + m.text) if m.type == "error" else None)
    pg.goto(f"{BASE}/invite/rhysInvite000001")
    if WITH_DEVICE:  # the invite's iPhone registered: the profile install's 301 sets the device cookie
        ctx.add_cookies([{"name": "device", "value": A.device_token(UDID), "url": BASE}])
        invs = A.load_invites(); invs["rhysInvite000001"].update(udid=UDID, used=t, sid="x"); A.save_json(A.INVITES, invs)
    pg.goto(f"{BASE}/")
    print("session pv guest page:", pg.url, "Registered" in pg.content())
    for arg in sys.argv[1:]:
        if arg.startswith("click="):  # open a page first, e.g. click=a.tile.reg or click=#helpRow
            pg.evaluate("s=>document.querySelector(s).click()", arg[6:]); pg.wait_for_timeout(1200)
            print("layers:", pg.evaluate("document.querySelectorAll('.layer').length"), "inputs:", pg.evaluate("[...document.querySelectorAll('input[name=name]')].map(i=>!!i.oninput)"))
    slow = lambda route: (time.sleep(0.6), route.continue_())  # /refresh takes a moment, as a real source sync does
    pg.route("**/refresh", slow)
    if "nameinput" in sys.argv:  # an input[name=name] with no oninput in the DOM (a pushed form): it used to throw inside refreshIn
        pg.evaluate("document.body.insertAdjacentHTML('beforeend','<input name=name hidden>')")
    add_app("Trailhead")  # new on the server since the page loaded
    pg.evaluate("window.notReloaded=1;window.barLog=[];new MutationObserver(()=>barLog.push(document.documentElement.classList.contains('reloading'))).observe(document.documentElement,{attributes:true,attributeFilter:['class']})")
    pg.click("header .bar.r")
    pg.wait_for_timeout(200)
    pg.wait_for_timeout(2500)
    print("reloading bar shown then hidden:", pg.evaluate("barLog"))
    print("fresh list after Reload:", "Trailhead" in pg.inner_text("#t-apps"), "| same page (swapped in place):", pg.evaluate("!!window.notReloaded"),
          "| bar gone:", not pg.evaluate("document.documentElement.classList.contains('reloading')"), "| errors:", [e for e in errs if "404" not in e])
    if "offline" in sys.argv:  # the server can't be reached: the bar says so, then goes
        pg.unroute("**/refresh"); pg.route("**/*", lambda r: r.abort())
        pg.click("header .bar.r"); pg.wait_for_timeout(400)
        print("offline bar:", pg.inner_text("#rbarT"), pg.evaluate("rbar.classList.contains('fail')"))
        pg.wait_for_timeout(2700)
        print("offline after:", pg.inner_text("#rbarT"), pg.evaluate("document.documentElement.classList.contains('reloading')"))
        pg.unroute("**/*")
    if "revoke" in sys.argv:  # the invite revoked while the page is open: Reload lands on what the server shows them now
        A.save_json(A.INVITES, {})
        if WITH_DEVICE: ctx.clear_cookies(name="device")
        pg.click("header .bar.r"); pg.wait_for_timeout(2500)
        print("after revoke:", pg.url, "| reloaded:", not pg.evaluate("!!window.notReloaded"), "| page:", pg.inner_text("body")[:120].replace("\n", " "))
    b.close()
srv.shutdown()
