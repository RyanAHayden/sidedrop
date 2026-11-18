"""Run: python test_app.py  (no network; App Store Connect and zsign are stubbed)."""
import os, plistlib, re, tempfile, time, zipfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", PUBLIC_URL="https://x.test", SECRET_KEY="k" * 32,
                  BUNDLE_ID="com.me.*", ADMIN_PASSWORD="admin-pass-also-long")
import threading
start, threading.Thread.start = threading.Thread.start, lambda self: None  # no background source sync in tests
import app as A
threading.Thread.start, A.SOURCES = start, []

(tmp / "apps").mkdir(); (tmp / "files").mkdir()
(tmp / "files" / "big.bin").write_bytes(b"0123456789")
with zipfile.ZipFile(tmp / "apps" / "Demo.ipa", "w") as z:
    z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(
        {"CFBundleIdentifier": "com.me.demo", "CFBundleVersion": "7", "CFBundleShortVersionString": "1.2", "CFBundleName": "Demo"}, fmt=plistlib.FMT_BINARY))

calls = []
def fake_regen():
    # real profiles are CMS-wrapped plists; junk bytes around it exercise embedded_plist
    A.PROFILE.write_bytes(b"\x30\x82junk" + plistlib.dumps({"ProvisionedDevices": [u for u, _ in calls], "Entitlements": {
        "application-identifier": "TEAM.com.me.*", "com.apple.developer.team-identifier": "TEAM",
        "keychain-access-groups": ["TEAM.*"], "get-task-allow": False}}) + b"\x00tail")
def fake_asc(method, path, **kw):
    return {"data": []}
signed_ents = []
def fake_run(cmd, **kw):
    signed_ents.append(plistlib.loads(Path(cmd[cmd.index("-e") + 1]).read_bytes()))
    Path(cmd[cmd.index("-o") + 1]).write_bytes((tmp / "apps" / "Demo.ipa").read_bytes())
A.regen_profile, A.asc, A.subprocess.run = fake_regen, fake_asc, fake_run
orig_register = A.register
A.register = lambda u, n: (calls.append((u, n)), orig_register(u, n))

c = A.app.test_client()
path_qs = lambda url: (lambda s: f"{s.path}?{s.query}")(urlsplit(url))

# login gate
assert b"Password" in c.get("/").data
assert c.post("/enroll").status_code == 403
A.time.sleep = lambda s: None
assert "err=1" in c.post("/login", data={"password": "nope"}).location
c.post("/login", data={"password": "hunter2-but-longer"})
assert b"Register iPhone" in c.get("/").data

# shareable link logs in and strips the password from the URL
link = A.app.test_client()
r = link.get("/?password=hunter2-but-longer")
assert r.status_code == 302 and r.location == "/" and b"Register iPhone" in link.get("/").data
assert "err=1" in A.app.test_client().get("/?password=wrong").location

# enrollment profile points at a signed /udid URL
prof = plistlib.loads(c.post("/enroll", data={"name": "Sam <script>"}).data)
url = prof["PayloadContent"]["URL"]
assert "/udid/Sam%20script?" in url, url

# with a cert dir set, the profile comes back CMS-signed with the whole chain attached
import datetime
from cryptography import x509 as X
from cryptography.hazmat.primitives import hashes as H, serialization as S
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7 as P7
k = ec.generate_private_key(ec.SECP256R1()); n = X.Name([X.NameAttribute(X.oid.NameOID.COMMON_NAME, "x.test")])
now = datetime.datetime.now(datetime.timezone.utc)
crt = X.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1) \
    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(k, H.SHA256())
cd = tmp / "tls"; cd.mkdir()
(cd / "fullchain.pem").write_bytes(crt.public_bytes(S.Encoding.PEM) * 2)  # leaf + "intermediate"
(cd / "privkey.pem").write_bytes(k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()))
A.PROFILE_CERT_DIR = str(cd)
der = c.post("/enroll", data={"name": "Sam"}).data
assert der[:1] == b"\x30" and A.embedded_plist(der)["PayloadType"] == "Profile Service"
assert len(P7.load_der_pkcs7_certificates(der)) == 2
A.PROFILE_CERT_DIR = ""

# iOS posts a CMS-signed plist; we register + regen + sign, then 301 back
body = b"\x30\x80" + plistlib.dumps({"UDID": "00008130-AAAA", "PRODUCT": "iPhone16,1"}) + b"\x00sig"
r = A.app.test_client().post(path_qs(url), data=body)  # no cookie, like iOS
assert r.status_code == 301 and r.location.endswith("/?enrolled=" + A.device_token("00008130-AAAA"))
assert calls == [("00008130-AAAA", "Sam script iPhone16,1")]
# landing back in Safari sets a device cookie (checked against the profile, survives sign-out); forged tokens do nothing
html = c.get("/").data
assert b"First, set up this iPhone" in html and b"/static/sdp1.jpg" in html and b"itms-services" not in html  # apps locked until registered
assert b"itms-services" not in c.get("/?enrolled=1").data and b"itms-services" not in c.get("/?enrolled=00008130-AAAA.x").data
html = c.get(r.location.replace("https://x.test", ""), base_url="https://localhost").data
assert b"This iPhone is registered" in html and b"href=/admin" in html and b"/static/sdp1.jpg" in html
c.get("/logout", base_url="https://localhost"); c.post("/login", data={"password": "hunter2-but-longer"}, base_url="https://localhost")
assert b"This iPhone is registered" in c.get("/", base_url="https://localhost").data
assert A.profile_udids() == {"00008130-AAAA"} and (tmp / "signed" / "Demo.ipa").exists()
# signed with the concrete app ID, never the profile's wildcard
assert signed_ents[-1]["application-identifier"] == "TEAM.com.me.demo"
assert signed_ents[-1]["keychain-access-groups"] == ["TEAM.com.me.demo"] and signed_ents[-1]["get-task-allow"] is False

# tampered / expired signatures are refused
assert A.app.test_client().post(path_qs(url).replace("Sam", "Eve"), data=body).status_code == 403
assert A.app.test_client().get("/f/big.bin?e=1&s=x").status_code == 403

# install page -> manifest -> ipa, all cookie-less
html = c.get("/").data.decode()
assert "Version 1.2<" in html  # marketing version, not the build number
m = unquote(re.search(r"download-manifest&url=([^\"]+)", html).group(1))
anon = A.app.test_client()
mf = plistlib.loads(anon.get(path_qs(m)).data)["items"][0]
assert mf["metadata"] == {"bundle-identifier": "com.me.demo", "bundle-version": "7", "kind": "software", "title": "Demo"}
assert anon.get(path_qs(mf["assets"][0]["url"])).status_code == 200

# file links work without login and support Range (resumable)
f = re.search(r'href="(https://x\.test/f/[^"]+)"', html).group(1).replace("&amp;", "&")
r = anon.get(path_qs(f), headers={"Range": "bytes=2-4"})
assert r.status_code == 206 and r.data == b"234"
assert anon.get(path_qs(f.replace("big.bin", "..%2Fadhoc.mobileprovision"))).status_code in (403, 404)

# AltStore source mirroring: downloads new versions, skips unchanged ones
class Resp:
    def __init__(s, body): s.body = body
    def json(s): return s.body
    def raise_for_status(s): pass
    def iter_content(s, n): yield s.body
    def __enter__(s): return s
    def __exit__(s, *a): pass
gets = []
def fake_get(url, **kw):
    gets.append(url)
    if url.endswith(".json"):
        return Resp({"apps": [{"bundleIdentifier": "io.x.tennis", "name": "TennisMod", "versions": [{"version": "1.5", "downloadURL": "https://gh/t.ipa"}]},
                              {"bundleIdentifier": "io.x.tennis", "versions": [{"version": "1.4", "downloadURL": "https://gh/old.ipa"}]}]})
    return Resp((tmp / "apps" / "Demo.ipa").read_bytes())
A.requests.get, A.SOURCES = fake_get, [("https://src/source.json", [], False)]
A.sync_sources(); A.sync_sources()
assert (tmp / "apps" / "io.x.tennis.ipa").read_bytes() == (tmp / "apps" / "Demo.ipa").read_bytes()
assert gets.count("https://gh/t.ipa") == 1 and "https://gh/old.ipa" not in gets  # first of a bundle ID only
# a third-party source takes only the listed bundle IDs and lists them on their own
A.SOURCES = [("https://other/source.json", ["io.x.tennis", "nope"], True)]
A.sync_sources()
assert (tmp / "apps" / ".io.x.tennis.third").exists()
html = c.get("/").get_data(as_text=True)
assert "Third-party apps" in html and "Install TennisMod" in html
A.SOURCES = [("https://other/source.json", ["nope"], True)]; (tmp / "apps" / ".io.x.tennis.version").unlink(); A.sync_sources()
assert not (tmp / "apps" / ".io.x.tennis.version").exists()
A.SOURCES = [("https://src/source.json", [], False)]; A.sync_sources()
assert not (tmp / "apps" / ".io.x.tennis.third").exists()
# the page's background check syncs the source, throttled to once a minute; page loads themselves don't wait on it
n = gets.count("https://src/source.json"); A.last_sync[0] = 0
c.get("/")
assert gets.count("https://src/source.json") == n
assert A.app.test_client().post("/check").status_code == 403
assert "stamp" in c.post("/check").json; c.post("/check")
assert gets.count("https://src/source.json") == n + 1

# CI trigger needs the token
A.SYNC_TOKEN = "tok"
assert anon.post("/sync").status_code == 403
assert anon.post("/sync", headers={"Authorization": "Bearer nope"}).status_code == 403
assert anon.post("/sync", headers={"Authorization": "Bearer tok"}).status_code == 202

# apps outside the wildcard get re-IDed under it; ones inside are left alone
assert A.fit_bundle_id("com.me.demo") is None
assert A.fit_bundle_id("com.mariopartyrd.partyboard") == "com.me.partyboard"
with zipfile.ZipFile(tmp / "pb.ipa", "w") as z:
    z.writestr("Payload/PB.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.mario.pb"}, fmt=plistlib.FMT_BINARY))
    z.writestr("Payload/PB.app/PlugIns/W.appex/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.mario.pb.widget"}))
    z.writestr("Payload/PB.app/Base.lproj/Info.plist", b"not a plist")
    z.writestr("Payload/PB.app/PB", b"\xca\xfe")
A.retarget(tmp / "pb.ipa", tmp / "pb2.ipa", "com.mario.pb", "com.me.pb")
with zipfile.ZipFile(tmp / "pb2.ipa") as z:
    assert plistlib.loads(z.read("Payload/PB.app/Info.plist"))["CFBundleIdentifier"] == "com.me.pb"
    assert plistlib.loads(z.read("Payload/PB.app/PlugIns/W.appex/Info.plist"))["CFBundleIdentifier"] == "com.me.pb.widget"
    assert z.read("Payload/PB.app/PB") == b"\xca\xfe"
# iFizBox gets our certificate inside it, so friends never pick one; other apps don't
A.P12.write_bytes(b"p12bytes")
with zipfile.ZipFile(tmp / "ifz.ipa", "w") as z:
    z.writestr("Payload/iFizBox.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.ryha.ifizbox"}))
    z.writestr("Payload/iFizBox.app/ifizbox-identity.plist", b"stale")
seen_in = []
A.subprocess.run, run0 = lambda cmd, **kw: seen_in.append(zipfile.ZipFile(cmd[-1]).read("Payload/iFizBox.app/ifizbox-identity.plist")), A.subprocess.run
A.sign_ipa(tmp / "ifz.ipa", tmp / "ifz-signed.ipa")
A.subprocess.run = lambda cmd, **kw: seen_in.append(zipfile.ZipFile(cmd[-1]).namelist())
A.sign_ipa(tmp / "apps" / "Demo.ipa", tmp / "demo-signed.ipa")
A.subprocess.run = run0
ident = plistlib.loads(seen_in[0])
assert ident == {"p12": b"p12bytes", "password": A.P12_PASSWORD, "profile": A.PROFILE.read_bytes()}, ident
assert not any("ifizbox-identity" in n for n in seen_in[1]) and not (tmp / ".ifz-signed.ipa.in").exists()
# iFizBox gets its own category above Apps
(tmp / "signed" / "com.ryha.ifizbox.ipa").write_bytes((tmp / "ifz.ipa").read_bytes())
html = c.get("/").data.decode()
assert html.index("<h3 class=hdr>iFizBox</h3>") < html.index("<h3 class=hdr>Apps</h3>") < html.index("Demo")
(tmp / "signed" / "com.ryha.ifizbox.ipa").unlink()
# per-app files sit under that app's Install button, not in Files
(tmp / "appfiles" / "Demo").mkdir(parents=True); (tmp / "appfiles" / "Demo" / "game.iso").write_bytes(b"iso")
html = c.get("/").data.decode()
a = re.search(r'href="(https://x\.test/af/Demo/game\.iso[^"]+)"', html).group(1).replace("&amp;", "&")
assert anon.get(path_qs(a)).data == b"iso" and "Files</h3>" in html and html.index("game.iso") < html.index("Files</h3>")
assert html.count("game.iso<") == 1
assert "steps(this)" in html and "Download game.iso" in html  # files turn INSTALL grey and become steps
(tmp / "appfiles" / "Demo" / "labels.txt").write_text("game.iso = the game disc\n")
html = c.get("/").data.decode()
assert "Download the game disc" in html and "labels.txt" not in html

# Manage and Sign open as pages pushed in place; pressed looks come from JS (.is-pressed), never :active, which iOS leaves stuck
html = c.get("/").data.decode()
assert "href=/admin data-push" in html and "action=/sign enctype=multipart/form-data data-push" in html and ":active{" not in html and ":active," not in html
# the inline scripts parse (a syntax error kills every button on the page)
import shutil, subprocess
if shutil.which("node"):
    for js in re.findall(r"<script>(.*?)</script>", html, re.S):
        (tmp / "inline.js").write_text(js)
        r = subprocess.Popen(["node", "--check", str(tmp / "inline.js")], stderr=subprocess.PIPE, text=True)  # subprocess.run is stubbed above
        assert r.wait() == 0, r.stderr.read()

# Feather sources come from the repo's feather-sources.txt and get a copy button
html = c.get("/").data.decode()
assert "https://provenance-emu.com/apps.json\nhttps://fizl0" in html and "Copy sources" in html

# custom signing: upload and URL both give a cookie-less install link; Feather sits in its own menu
html = c.get("/").data.decode()
assert "Sign your own IPA" in html and "claration/Feather" in html
assert A.app.test_client().post("/sign").status_code == 403
demo = (tmp / "apps" / "Demo.ipa").read_bytes()
import io
for data in ({"ipa": (io.BytesIO(demo), "x.ipa")}, {"url": "https://gh/t.ipa"}):
    html = c.post("/sign", data=data, content_type="multipart/form-data").data.decode()
    m = unquote(re.search(r"download-manifest&url=([^\"]+)", html).group(1))
    mf = plistlib.loads(anon.get(path_qs(m)).data)["items"][0]
    assert "/i/custom/" in mf["assets"][0]["url"] and anon.get(path_qs(mf["assets"][0]["url"])).status_code == 200
assert "Pick an .ipa" in c.post("/sign", data={"url": "file:///etc/passwd"}).data.decode()
assert not list((tmp / "signed" / "custom").glob(".*"))  # temp files cleaned up
# Changes tab: installs are recorded per phone, and a newer version then shows as an upgrade with a badge
html = c.get("/").data
assert b"id=t-changes" in html and b"Available Updates" not in html and b"from sidedrop" in html
assert A.app.test_client().post("/installed", data={"name": "Demo"}).status_code == 403
assert c.post("/installed", data={"name": "../x"}).status_code == 403
assert c.post("/installed", data={"name": "Demo"}).status_code == 204 and b"Available Updates" not in c.get("/").data
assert b'class="get done" data-app="Demo" aria-expanded=false onclick="steps(this)">INSTALLED<' in c.get("/").data
with zipfile.ZipFile(tmp / "apps" / "Demo.ipa", "w") as z:
    z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.me.demo", "CFBundleVersion": "8", "CFBundleShortVersionString": "1.3", "CFBundleName": "Demo"}))
os.utime(tmp / "apps" / "Demo.ipa", (time.time() + 5, time.time() + 5))
html = c.get("/").data.decode()
assert "Available Updates" in html and ">UPDATE</a>" in html and re.search(r"id=badge>1<", html), "upgrade offered"
assert 'data-app="Demo" aria-expanded=false onclick="steps(this)">UPDATE<' in html, "Apps list says UPDATE for an older install"
# admin: separate password, CSRF, lockout; lists devices and disables one
plain = A.app.test_client()
assert plain.get("/admin").status_code == 302 and plain.post("/admin/device").status_code == 403
assert b"Admin password" in c.get("/admin").data and c.post("/admin/device", data={"id": "D1", "status": "DISABLED"}).status_code == 403
assert b"Wrong admin password" in c.post("/admin", data={"password": "nope"}).data
patched, devs = [], [{"id": "D1", "attributes": {"name": "Sam <b>", "udid": "00008130-AAAA", "status": "ENABLED", "addedDate": "2026-11-03T10:00:00.000+0000", "model": "iPhone 15"}}]
A.asc = lambda m, path, **kw: (patched.append((m, path, kw)), {"data": devs if m == "GET" and path == "/devices" and "filter[udid]" not in kw.get("params", {}) else []})[1]
assert c.post("/admin", data={"password": "admin-pass-also-long"}).status_code == 302
html = c.get("/admin").data.decode()
assert "Sam &lt;b&gt;" in html and "this iPhone" in html and "added Nov 3, 2026" in html and "Last used today" in html
csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert c.post("/admin/device", data={"id": "D1", "status": "DISABLED", "csrf": "x"}).status_code == 403
assert c.post("/admin/device", data={"id": "../x", "status": "DISABLED", "csrf": csrf}).status_code == 400
assert c.post("/admin/device", data={"id": "D1", "status": "DISABLED", "csrf": csrf}).status_code == 302
assert ("PATCH", "/devices/D1") in [(m, p) for m, p, _ in patched]
A.asc = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("App Store Connect GET /devices: 500"))
assert b"didn't answer" in c.get("/admin").data
A.asc = fake_asc
locked = A.app.test_client(); locked.post("/login", data={"password": "hunter2-but-longer"})
for _ in range(5): locked.post("/admin", data={"password": "nope"})
assert b"Too many wrong passwords" in locked.post("/admin", data={"password": "admin-pass-also-long"}).data
A.admin_fails.clear()
assert b'og:image content="https://x.test/static/og.png"' in A.app.test_client().get("/").data  # link preview on the login page too
assert c.get("/static/sdp1.jpg").status_code == 200  # setup screenshots served
assert A.app.test_client().post("/refresh").status_code == 403 and c.post("/refresh").status_code == 204  # Reload button
fresh = A.app.test_client(); fresh.post("/login", data={"password": "hunter2-but-longer"}); e = "/?enrolled=" + A.device_token("00008130-AAAA")
assert b"Setup Complete" in fresh.get(e).data and b"Setup Complete" not in fresh.get("/").data
assert b"Setup Complete" not in fresh.get(e).data, "a Home Screen icon saved on /?enrolled= shows it only the first time"
# web push: subscribe per phone; upgrades already waiting count as told; one push per new version; 410 drops the subscription
import json
from pywebpush import WebPushException
sent = []
A.webpush = lambda sub, data, **kw: sent.append((sub["endpoint"], json.loads(data)))
assert len(A.vapid_public()) == 87 and A.vapid_public() in c.get("/").data.decode()
assert c.get("/sw.js").status_code == 200 and c.get("/manifest.webmanifest").json["display"] == "standalone"
sub = {"endpoint": "https://push.example/1", "keys": {"p256dh": "x", "auth": "y"}}
assert A.app.test_client().post("/push", json=sub).status_code == 403
assert c.post("/push", json={"endpoint": "http://x", "keys": {}}).status_code == 400
assert c.post("/push", json=sub).status_code == 204
A.notify_upgrades(); assert sent == []
def release(short, build):
    with zipfile.ZipFile(tmp / "apps" / "Demo.ipa", "w") as z:
        z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.me.demo", "CFBundleVersion": build, "CFBundleShortVersionString": short, "CFBundleName": "Demo"}))
    os.utime(tmp / "apps" / "Demo.ipa", (time.time() + 10, time.time() + 10))
    A.resign(force=True)
release("1.4", "9"); A.notify_upgrades(); A.notify_upgrades()
assert sent == [("https://push.example/1", {"title": "Update Available", "body": "Demo 1.4 is available.", "url": "/#changes"})], sent
def gone(*a, **k): raise WebPushException("gone", response=type("R", (), {"status_code": 410})())
A.webpush = gone
release("1.5", "10"); A.notify_upgrades()
assert A.load_json(A.PUSH) == {}
print("ok")
