"""The README's screenshots: SideDrop run locally with demo data, shot by headless Chromium at 390x844 (CSS px, 3x).

    uv run -q --no-project --with-requirements requirements.txt --with playwright python docs/readme_shots.py

Nothing comes from a real server: Apple's API and zsign are stubbed, the apps are tiny fake IPAs, and every name, UDID and
domain is made up (example.com). Writes docs/img/*.png. Uses the system Chromium (CHROMIUM, default /usr/bin/chromium).
"""
import base64, datetime, os, plistlib, shutil, sys, tempfile, threading, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
SETUP_RUN = sys.argv[1:] == ["setup"]  # a new server: nothing in .env, so the default password opens the setup splash
tmp = Path(tempfile.mkdtemp(prefix="sidedrop-shots-"))
for k in ("PASSWORD", "ADMIN_PASSWORD", "BUNDLE_ID", "ASC_KEY_ID", "ASC_ISSUER_ID", "P12_PASSWORD", "SECRET_KEY", "SIDEDROP_COMMIT"):
    os.environ.pop(k, None)
os.environ.update(DATA=str(tmp), PUBLIC_URL="https://sidedrop.example.com")
if not SETUP_RUN:
    os.environ.update(PASSWORD="demo-friends-pass", ADMIN_PASSWORD="demo-admin-pass", SECRET_KEY="d" * 32, BUNDLE_ID="com.example.sideload",
                      ASC_KEY_ID="DEMOKEY123", ASC_ISSUER_ID="00000000-0000-0000-0000-000000000000", P12_PASSWORD="demo")
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)  # the repo's ifizbox-sources.txt and friends

start, threading.Thread.start = threading.Thread.start, lambda self: None  # no background source sync at import
import app as A
threading.Thread.start, A.SOURCES = start, []
A.COMMIT = "a1b2c3d"
IPHONE = dict(viewport={"width": 390, "height": 844}, device_scale_factor=3, is_mobile=True, has_touch=True,
              user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1")


def serve():
    from werkzeug.serving import make_server
    srv = make_server("127.0.0.1", 0, A.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://localhost:{srv.server_port}"


def shot(page, name):
    page.wait_for_timeout(700)  # tab and fold animations
    page.screenshot(path=str(OUT / f"{name}.png"))
    print("wrote", OUT / f"{name}.png")


if SETUP_RUN:
    from playwright.sync_api import sync_playwright
    srv, BASE = serve()
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"))
        pg = browser.new_context(**IPHONE).new_page()
        pg.goto(f"{BASE}/?password={A.DEFAULT_PASSWORD}")
        assert pg.url.endswith("/setup"), pg.url
        shot(pg, "setup")
        browser.close()
    srv.shutdown()
    shutil.rmtree(tmp)
    sys.exit()

# --- a fake Apple Distribution certificate (self-signed, made up holder and team) ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
subj = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Apple Distribution: Demo Developer (DEMO123456)"),
                  x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, "DEMO123456")])
cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key()).serial_number(7)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=330)).sign(key, hashes.SHA256()))
A.P12.write_bytes(pkcs12.serialize_key_and_certificates(b"demo", key, cert, None, serialization.BestAvailableEncryption(b"demo")))
A.ASC_KEY.write_text("demo, never used: Apple's API is stubbed")
A.cert_status = A.cert_status_cached = lambda *a, **k: []  # no OCSP or Apple checks; the fake cert would trip them

# --- demo devices: what App Store Connect would list ---
UDID = "00008120-000DEMO0DEMO0001"
days_ago = lambda d: (now - datetime.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
DEVICES = [{"id": f"DEV{i}", "attributes": dict(name=n, model=m, udid=u, status=s, addedDate=days_ago(a), deviceClass="IPHONE")}
           for i, (n, m, u, s, a) in enumerate([
               ("Demo iPhone iPhone15,2", "iPhone 14 Pro", UDID, "ENABLED", 40),
               ("Alex iPhone16,1", "iPhone 15 Pro", "00008130-000DEMO0DEMO0002", "ENABLED", 21),
               ("Jordan iPhone17,3", "iPhone 16", "00008140-000DEMO0DEMO0003", "ENABLED", 9),
               ("Old test phone", "iPhone 12", "00008101-000DEMO0DEMO0004", "DISABLED", 120)])]


def fake_asc(method, path, **kw):
    return {"data": DEVICES if path == "/devices" else []}


def fake_regen():
    A.PROFILE.write_bytes(plistlib.dumps({"ProvisionedDevices": [d["attributes"]["udid"] for d in DEVICES if d["attributes"]["status"] == "ENABLED"],
                                          "ExpirationDate": now + datetime.timedelta(days=330),
                                          "Entitlements": {"application-identifier": "DEMO123456.com.example.sideload"}}))


A.asc, A.regen_profile = fake_asc, fake_regen
A.sign_ipa = lambda src, out: shutil.copyfile(src, out)
A.save_json(A.DEVICES, {"at": time.time(), "data": DEVICES})
fake_regen()

# --- demo apps: tiny IPAs with an Info.plist, icons as inline SVG ---
ICON = lambda c1, c2, glyph: "data:image/svg+xml;base64," + base64.b64encode(f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 60 60">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient></defs>
<rect width="60" height="60" fill="url(#g)"/><text x="30" y="41" font-size="30" text-anchor="middle" fill="#fff" font-family="Helvetica, Arial, sans-serif"
 font-weight="bold">{glyph}</text></svg>""".encode()).decode()
ifz_png = Path.home() / "repos/iFizBox/web/app/icons/icon-glossy-152.png"  # iFizBox's public icon, if a checkout is beside this one
APPS = [  # name, bundle id, title, version, days ago, icon, description, third-party title
    ("com.ryha.ifizbox", "com.ryha.ifizbox", "iFizBox", "2.4", 2,
     "data:image/png;base64," + base64.b64encode(ifz_png.read_bytes()).decode() if ifz_png.exists() else ICON("#5aa0f0", "#1a62c0", "i"), "", ""),
    ("Notepad", "com.example.notepad", "Notepad", "3.1", 0, ICON("#ffd54a", "#e6a700", "N"), "Plain text notes that sync over iCloud Drive.", ""),
    ("PocketSynth", "com.example.synth", "Pocket Synth", "1.8", 0, ICON("#b36cf0", "#6a2bb5", "♪"), "A four-voice synth with a step sequencer.", ""),
    ("Trailhead", "com.example.trailhead", "Trailhead", "5.0", 3, ICON("#5cc35c", "#2a8a2a", "▲"), "Offline maps for hiking.", ""),
    ("RetroArcade", "com.example.retro", "Retro Arcade", "0.9.4", 6, ICON("#ff7a59", "#d23a1e", "★"), "Plays your own homebrew game files.", ""),
    ("Podcatch", "org.example.podcatch", "Podcatch", "2.2", 12, ICON("#ff5e8a", "#c2185b", "P"), "An open-source podcast player.", "Podcatch"),
]
A.APPS.mkdir()
for name, bid, title, ver, ago, icon, desc, third in APPS:
    with zipfile.ZipFile(A.APPS / f"{name}.ipa", "w") as z:
        z.writestr(f"Payload/{name}.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": bid, "CFBundleVersion": ver,
                                                                       "CFBundleShortVersionString": ver, "CFBundleName": title}))
    (A.APPS / f".{name}.icon").write_text(icon)
    (A.APPS / f".{name}.date").write_text((datetime.date.today() - datetime.timedelta(days=ago)).isoformat())
    (A.APPS / f".{name}.source").write_text("Example Source" if third else "SideDrop")
    if desc:
        (A.APPS / f".{name}.desc").write_text(desc)
    if third:
        (A.APPS / f".{name}.third").write_text(third)
(A.APP_FILES / "RetroArcade").mkdir(parents=True)  # an app with a file to download beside it
(A.APP_FILES / "RetroArcade" / "homebrew-pack.zip").write_bytes(b"\0" * 3_400_000)
(A.APP_FILES / "RetroArcade" / "labels.txt").write_text("homebrew-pack.zip = the homebrew pack\n")
A.FILES.mkdir()
(A.FILES / "Setup guide.pdf").write_bytes(b"%PDF-1.4 demo\n" * 1000)
# the demo iPhone: installed an older Trailhead (so Changes shows an update), seen today, through the first-install splash
A.save_json(A.INSTALLED, {UDID: {"Notepad": "3.1/3.1", "Trailhead": "4.2/4.2"}})
A.save_json(A.SEEN, {UDID: time.time() - 3600, DEVICES[1]["attributes"]["udid"]: time.time() - 2 * 86400})
A.save_json(A.FIRST_RUN, {UDID: time.time()})
A.save_product(UDID, "iPhone15,2")

# --- serve it on localhost ---
srv, BASE = serve()
from playwright.sync_api import sync_playwright

OUT.mkdir(parents=True, exist_ok=True)
with sync_playwright() as p:
    browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"))
    ctx = browser.new_context(**IPHONE)
    ctx.add_init_script("try{localStorage.pushAsked=1}catch(e){}")  # no notifications prompt over Changes
    pg = ctx.new_page()
    pg.goto(f"{BASE}/?password=demo-admin-pass")  # the admin's sign-in, so Settings shows Manage
    pg.goto(f"{BASE}/?enrolled={A.device_token(UDID)}")  # the 301 after the profile install: sets the device cookie
    pg.goto(f"{BASE}/#apps")
    shot(pg, "apps")
    pg.goto(f"{BASE}/#changes")
    shot(pg, "changes")
    pg.goto(f"{BASE}/#apps")
    pg.click("button.get[data-app=RetroArcade]")  # an app with a file: GET opens its install steps
    pg.evaluate("scr.scrollTop+=document.querySelector('button.get[data-app=RetroArcade]').getBoundingClientRect().top-330")
    shot(pg, "install")
    pg.goto(f"{BASE}/#settings")
    shot(pg, "settings")
    for path, name in [("/admin", "manage"), ("/admin/iphones", "iphones"), ("/admin/signing", "signing")]:
        pg.goto(BASE + path)
        pg.wait_for_load_state("networkidle")
        shot(pg, name)
    browser.close()
srv.shutdown()
shutil.rmtree(tmp)
import subprocess
subprocess.run([sys.executable, __file__, "setup"], check=True)
