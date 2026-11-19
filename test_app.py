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

(tmp / "apps").mkdir()
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
assert b"Set up this iPhone" in html and b"/static/sdp1.jpg" in html and b'href="itms-services' not in html and b"id=ifzb " not in html  # apps locked until registered
# Apps header: welcome, GitHub | iFizBox, then Help + Sign IPA and the setup tile, which folds the SDP + Register steps behind it
assert b"Welcome to sidedrop" in html and b"Ryan Hayden (Fizlo)</a>" in html and b"go('ifizbox')" in html and b"id=setupT" in html and b"<div id=setup hidden>" in html
assert b">Help</a>" in html and b"getElementById('sign')" in html and b'class="tile reg"' not in html and b"go('changes')" not in html
assert b'href="itms-services' not in c.get("/?enrolled=1").data and b'href="itms-services' not in c.get("/?enrolled=00008130-AAAA.x").data
html = c.get(r.location.replace("https://x.test", ""), base_url="https://localhost").data
assert b"This iPhone is registered" in html and b"href=/admin" not in html and b"/static/sdp1.jpg" in html  # Manage is the admin's only
assert b'class="tile reg"' in html and b"go('changes')" in html and b"id=setupT" not in html and b"id=setup " not in html  # registered: Changes and the green tile
c.get("/logout", base_url="https://localhost"); c.post("/login", data={"password": "hunter2-but-longer"}, base_url="https://localhost")
assert b"This iPhone is registered" in c.get("/", base_url="https://localhost").data
assert A.profile_udids() == {"00008130-AAAA"} and (tmp / "signed" / "Demo.ipa").exists()
# signed with the concrete app ID, never the profile's wildcard
assert signed_ents[-1]["application-identifier"] == "TEAM.com.me.demo"
assert signed_ents[-1]["keychain-access-groups"] == ["TEAM.com.me.demo"] and signed_ents[-1]["get-task-allow"] is False

# tampered / expired signatures are refused
assert A.app.test_client().post(path_qs(url).replace("Sam", "Eve"), data=body).status_code == 403
assert A.app.test_client().get("/af/Demo/game.iso?e=1&s=x").status_code == 403

# install page -> manifest -> ipa, all cookie-less
html = c.get("/").data.decode()
assert "Version 1.2<" in html  # marketing version, not the build number
m = unquote(re.search(r"download-manifest&url=([^\"]+)", html).group(1))
anon = A.app.test_client()
mf = plistlib.loads(anon.get(path_qs(m)).data)["items"][0]
assert mf["metadata"] == {"bundle-identifier": "com.me.demo", "bundle-version": "7", "kind": "software", "title": "Demo"}
assert anon.get(path_qs(mf["assets"][0]["url"])).status_code == 200

# first install tap: a one-time splash (SDP, then Developer Mode, Help's screenshots) holds the tap, then carries it on; remembered per phone
fr = html.split("id=firstRun")
assert len(fr) == 2 and "hidden data-due=1" in fr[1][:40] and "/static/sdp1.jpg" in fr[1] and "/static/dev3.jpg" in fr[1] and "firstRunGo(1)" in fr[1]
assert "e.target.closest('a[href^=\"itms-services:\"],#ifzb')" in html and html.count("/static/dev1.jpg") == 2  # catches every install link
assert A.app.test_client().post("/first-run").status_code == 403
assert c.post("/first-run").status_code == 204 and list(A.load_json(A.FIRST_RUN)) == ["00008130-AAAA"]
html = c.get("/").data.decode()
assert "id=firstRun" not in html and html.count("/static/dev1.jpg") == 1 and 'href="itms-services' in html  # second tap: straight to iOS

# install tracking for the install page: the manifest and app carry the page's token (outside the signature), the page polls it
tk = "ab" * 12
assert anon.get(path_qs(m) + "&t=" + tk).status_code == 200 and c.get(f"/install/{tk}").json == {"manifest": True, "started": False}
mf = plistlib.loads(anon.get(path_qs(m) + "&t=" + tk).data)["items"][0]
assert mf["assets"][0]["url"].endswith("&t=" + tk) and anon.get(path_qs(mf["assets"][0]["url"])).status_code == 200
assert c.get(f"/install/{tk}").json == {"manifest": True, "started": True} and anon.get(f"/install/{tk}").status_code == 403
assert anon.get(path_qs(m) + "&t=../x").status_code == 200 and "../x" not in A.INSTALLS

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
assert c.post("/check").json["build"] == A.BUILD and f"<meta name=build content={A.BUILD}>" in c.get("/").data.decode()  # an open page reloads on a new deploy
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
# and sidedrop's sources as web/transfer.link, iFizBox's import link (gzipped JSON, base64url)
import base64, gzip, json
with zipfile.ZipFile(tmp / "ifz-src.ipa", "w") as z:
    z.writestr("Payload/iFizBox.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.ryha.ifizbox"}))
A.subprocess.run = lambda cmd, **kw: seen_in.append(zipfile.ZipFile(cmd[-1]).read("Payload/iFizBox.app/web/transfer.link").decode())
A.sign_ipa(tmp / "ifz-src.ipa", tmp / "ifz-src-signed.ipa"); A.subprocess.run = run0
d = seen_in[-1].removeprefix("ifizbox://import?d=")
sent = json.loads(gzip.decompress(base64.urlsafe_b64decode(d + "=" * (-len(d) % 4))))
assert sent["v"] == 1 and sent["sources"][:2] == ["https://provenance-emu.com/apps.json", "https://fizl0.github.io/apps/source.json"], sent
assert not any("ifizbox-identity" in n for n in seen_in[1]) and not (tmp / ".ifz-signed.ipa.in").exists()
# iFizBox gets its own category above Apps
(tmp / "signed" / "com.ryha.ifizbox.ipa").write_bytes((tmp / "ifz.ipa").read_bytes())
html = c.get("/").data.decode()
assert html.index("<h3 class=hdr>iFizBox</h3>") < html.index("<h3 class=hdr>Apps</h3>") < html.index("Demo")
# its GET opens the iFizBox tab (the install is that page's button); the tab has the install button with the manifest and the benefits
assert 'href=#ifizbox onclick="go(\'ifizbox\');return false"' in html and 'id=t-ifizbox' in html and 'id=ifzb data-app="com.ryha.ifizbox" data-m="https://x.test/m/com.ryha.ifizbox.plist?e=' in html
assert "Your certificate, already in it" in html and "10 sources" in html
# tabs: Apps, Changes, iFizBox, Settings (no Feather, no Files, no More)
assert re.findall(r"<a href=#(\w+)><svg", html) == ["apps", "changes", "ifizbox", "settings"] and "t-feather" not in html and "t-files" not in html
(tmp / "signed" / "com.ryha.ifizbox.ipa").unlink()
# per-app files sit under that app's Install button, not in Files
(tmp / "appfiles" / "Demo").mkdir(parents=True); (tmp / "appfiles" / "Demo" / "game.iso").write_bytes(b"iso")
html = c.get("/").data.decode()
a = re.search(r'href="(https://x\.test/af/Demo/game\.iso[^"]+)"', html).group(1).replace("&amp;", "&")
assert anon.get(path_qs(a)).data == b"iso"
r = anon.get(path_qs(a), headers={"Range": "bytes=1-2"})  # resumable
assert r.status_code == 206 and r.data == b"so"
assert anon.get(path_qs(a.replace("game.iso", "..%2F..%2Fadhoc.mobileprovision"))).status_code in (403, 404)
assert html.count("game.iso<") == 1
assert "steps(this)" in html and "Download game.iso" in html  # files turn INSTALL grey and become steps
(tmp / "appfiles" / "Demo" / "labels.txt").write_text("game.iso = the game disc\n")
html = c.get("/").data.decode()
assert "Download the game disc" in html and "labels.txt" not in html

# Manage and Sign open as pages pushed in place; pressed looks come from JS (.is-pressed), never :active, which iOS leaves stuck
html = c.get("/").data.decode()
assert "action=/sign enctype=multipart/form-data data-push" in html and ":active{" not in html and ":active," not in html
# the inline scripts parse (a syntax error kills every button on the page)
import shutil, subprocess
if shutil.which("node"):
    for js in re.findall(r"<script>(.*?)</script>", html, re.S):
        (tmp / "inline.js").write_text(js)
        r = subprocess.Popen(["node", "--check", str(tmp / "inline.js")], stderr=subprocess.PIPE, text=True)  # subprocess.run is stubbed above
        assert r.wait() == 0, r.stderr.read()

# custom signing: upload and URL both give a cookie-less install link
html = c.get("/").data.decode()
assert "Sign your own IPA" in html
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

# admin through the friends' login link: Manage edits sources (saved in the data folder, the repo copy stays the default),
# uploads a file friends see and can fetch without a login, and replaces the signing files; a friend gets neither Manage nor its posts
boss = A.app.test_client()
r = boss.get("/?password=admin-pass-also-long")
assert r.status_code == 302 and r.location == "/"
html = boss.get("/").data.decode()
assert "href=/admin data-push" in html and "Register iPhone" in html
html = boss.get("/admin").data.decode()
assert "Choose Signing Files" in html and "Files for friends" in html and "iFizBox&#39;s starting sources" in html and "Admin password" not in html
csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
synced = []
A.sync_sources = lambda: synced.append(list(A.SOURCES))
repo_mirror = (Path(A.__file__).parent / "mirror-sources.txt").read_text()
r = boss.post("/admin/config", data={"csrf": csrf, "name": "mirror-sources.txt", "text": "https://src.test/a.json com.a.b\r\n"})
assert r.location == "/admin?done=sources" and (tmp / "config" / "mirror-sources.txt").read_text() == "https://src.test/a.json com.a.b\n"
assert A.SOURCES == [("https://src.test/a.json", ["com.a.b"], False)] + [s for s in A.SOURCES if s[2]]
assert (Path(A.__file__).parent / "mirror-sources.txt").read_text() == repo_mirror  # the repo file is untouched
assert "src.test/a.json" in boss.get("/admin").data.decode() and "Use Default" in boss.get("/admin").data.decode()
boss.post("/admin/config", data={"csrf": csrf, "name": A.IFIZBOX_SOURCES, "text": "https://one.test/s.json\nhttps://two.test/s.json"})
assert A.read_urls(A.IFIZBOX_SOURCES) == ["https://one.test/s.json", "https://two.test/s.json"]
assert b"isn&#39;t a JSON object" in boss.post("/admin/config", data={"csrf": csrf, "name": A.IFIZBOX_SETTINGS, "text": "[1]"}).data
boss.post("/admin/config", data={"csrf": csrf, "name": A.IFIZBOX_SETTINGS, "text": '{"theme": "dark"}'})
import gzip, base64, json
link_d = A.ifizbox_transfer().split("d=")[1]
payload = json.loads(gzip.decompress(base64.urlsafe_b64decode(link_d + "=" * (-len(link_d) % 4))))
assert payload["sources"] == ["https://one.test/s.json", "https://two.test/s.json"] and payload["settings"] == {"theme": "dark"}
assert boss.post("/admin/config", data={"csrf": csrf, "name": "../secret.key", "text": "x"}).status_code == 400
r = boss.post("/admin/config", data={"csrf": csrf, "name": "mirror-sources.txt", "text": "", "reset": "1"})
assert r.location == "/admin?done=default" and not (tmp / "config" / "mirror-sources.txt").exists()
assert [u for u, _, t in A.SOURCES if not t] == [u for u, _ in A.read_sources("mirror-sources.txt")]
r = boss.post("/admin/files", data={"csrf": csrf, "files": [(io.BytesIO(b"hello friends"), "notes v2.txt"), (io.BytesIO(b"x"), "../.hidden")]},
              content_type="multipart/form-data")
assert r.location == "/admin?done=files" and (tmp / "files" / "notes v2.txt").read_bytes() == b"hello friends"
assert sorted(p.name for p in (tmp / "files").iterdir()) == ["hidden", "notes v2.txt"]  # no paths, no dotfiles
friend = A.app.test_client(); friend.get("/?password=hunter2-but-longer")
html = friend.get("/").data.decode()
assert "notes v2.txt" in html and "href=/admin" not in html, "a friend sees the file and not Manage"
dl = re.search(r'href="(https://x\.test/f/notes%20v2\.txt\?[^"]+)"', html).group(1).replace("&amp;", "&")
assert A.app.test_client().get(path_qs(dl)).data == b"hello friends"  # no login needed, like the app files
assert A.app.test_client().get("/f/notes%20v2.txt").status_code == 403
assert b"Admin password" in friend.get("/admin").data  # a friend's Manage is only the old unlock form
for url, data in (("/admin/config", {"name": "mirror-sources.txt", "text": "https://evil.test/x.json"}), ("/admin/files", {}),
                  ("/admin/files/delete", {"name": "notes v2.txt"}), ("/admin/signing", {})):
    assert friend.post(url, data=dict(data, csrf=csrf)).status_code == 403
    assert boss.post(url, data=dict(data, csrf="wrong")).status_code == 403
assert (tmp / "files" / "notes v2.txt").exists() and not (tmp / "config" / "mirror-sources.txt").exists()
assert boss.post("/admin/files/delete", data={"csrf": csrf, "name": "../secret.key"}).status_code == 404
assert boss.post("/admin/files/delete", data={"csrf": csrf, "name": "hidden"}).location == "/admin?done=deleted" and not (tmp / "files" / "hidden").exists()
# new signing files, the same upload as the setup screen; a new certificate means a new profile and every app signed again
from cryptography.hazmat.primitives.serialization import pkcs12 as P12x
def dist_cert(cn="Apple Distribution: Sam Test (TEAM123456)", days=365, key=k):
    """A self-made certificate named like Apple's, valid for days from now (negative: already expired)."""
    nm, now = X.Name([X.NameAttribute(X.oid.NameOID.COMMON_NAME, cn)]), datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    start = now +datetime.timedelta(days=min(days, 0) - 400)
    return X.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(key.public_key()).serial_number(X.random_serial_number()) \
        .not_valid_before(start).not_valid_after(now + datetime.timedelta(days=days)).sign(k, H.SHA256())
dcrt = dist_cert()
# certificate checks (F4): each bad .p12 is refused at upload with its own message and the saved one stays
p12_of = lambda crt_, pw=b"pw", key=k: P12x.serialize_key_and_certificates(b"sd", key, crt_, None, S.BestAvailableEncryption(pw))
assert A.cert_problems(p12_of(dcrt), "pw") == []
assert A.cert_problems(p12_of(dcrt), "nope") == [("error", "The password doesn't open cert.p12.")]
assert "expired on" in A.cert_problems(p12_of(dist_cert(days=-3)), "pw")[0][1]
assert [l for l, _ in A.cert_problems(p12_of(dist_cert(days=12)), "pw")] == ["warning"] and "12 days" in A.cert_problems(p12_of(dist_cert(days=12)), "pw")[0][1]
assert "development certificate" in A.cert_problems(p12_of(dist_cert("Apple Development: Sam Test (X)")), "pw")[0][1]
assert "not an Apple Distribution" in A.cert_problems(p12_of(crt), "pw")[0][1]
assert "not its private key" in A.cert_problems(p12_of(dcrt, key=None), "pw")[0][1]
before = A.P12.read_bytes()
for blob, pw, says in ((p12_of(dcrt), "wrong", b"didn&#39;t open"), (p12_of(dist_cert(days=-3)), "pw", b"The certificate expired on"),
                       (p12_of(crt), "pw", b"not an Apple Distribution certificate")):
    r = boss.post("/admin/signing", data={"csrf": csrf, "p12_password": pw, "files": [(io.BytesIO(blob), "cert.p12")]}, content_type="multipart/form-data")
    assert says in r.data and A.P12.read_bytes() == before, says
# Apple's side: not in the account, the App ID missing, an explicit App ID without Push; a profile for another certificate
A.P12.write_bytes(p12_of(dist_cert(days=10))); A.P12_PASSWORD = "pw"
apple = {"/certificates": [], "/bundleIds": []}
A.asc = lambda m, path, **kw: {"data": apple.get(path, [])}
html = boss.get("/admin").data.decode()
assert "expires in 10 days" in html and "isn&#39;t in your developer account" in html and "The App ID com.me.* isn&#39;t" in html, html
_, mine, _ = P12x.load_key_and_certificates(A.P12.read_bytes(), b"pw")
apple["/certificates"] = [{"id": "C1", "attributes": {"serialNumber": f"{mine.serial_number:X}"}}]
apple["/bundleIds"] = [{"id": "B1", "attributes": {"identifier": "com.me.*"}}]
assert A.cert_account_problems() == []
A.BUNDLE_ID, apple["/bundleIds"] = "com.me.app", [{"id": "B2", "attributes": {"identifier": "com.me.app"}}]
assert [l for l, t in A.cert_account_problems() if "Push" in t] == ["warning"]
apple["/bundleIds/B2/bundleIdCapabilities"] = [{"attributes": {"capabilityType": "PUSH_NOTIFICATIONS"}}]
assert A.cert_account_problems() == []
prof_before = A.PROFILE.read_bytes() if A.PROFILE.exists() else None
A.PROFILE.write_bytes(plistlib.dumps({"DeveloperCertificates": [crt.public_bytes(S.Encoding.DER)]}))
assert "another certificate" in A.cert_account_problems()[0][1]
A.PROFILE.write_bytes(plistlib.dumps({"DeveloperCertificates": [mine.public_bytes(S.Encoding.DER)]}))
assert A.cert_account_problems() == []
A.PROFILE.write_bytes(prof_before) if prof_before is not None else A.PROFILE.unlink()
# revoked: Apple's OCSP responder (stubbed) says so, from the issuer fetched off the certificate's AIA
from cryptography.x509 import ocsp as O
ca_k = ec.generate_private_key(ec.SECP256R1()); ca_n = X.Name([X.NameAttribute(X.oid.NameOID.COMMON_NAME, "Fake WWDR")])
ca = X.CertificateBuilder().subject_name(ca_n).issuer_name(ca_n).public_key(ca_k.public_key()).serial_number(7) \
    .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=900)).sign(ca_k, H.SHA256())
AIA = X.oid.AuthorityInformationAccessOID
leaf = X.CertificateBuilder().subject_name(mine.subject).issuer_name(ca_n).public_key(k.public_key()).serial_number(mine.serial_number) \
    .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=200)) \
    .add_extension(X.AuthorityInformationAccess([X.AccessDescription(AIA.OCSP, X.UniformResourceIdentifier("http://ocsp.test/o")),
                                                 X.AccessDescription(AIA.CA_ISSUERS, X.UniformResourceIdentifier("http://certs.test/ca.der"))]), False) \
    .sign(ca_k, H.SHA256())
A.P12.write_bytes(p12_of(leaf))
gone_at = now - datetime.timedelta(days=2)
def fake_post(url, data=None, **kw):
    req = O.load_der_ocsp_request(data); assert url == "http://ocsp.test/o" and req.serial_number == leaf.serial_number
    resp = O.OCSPResponseBuilder().add_response(leaf, ca, H.SHA1(), O.OCSPCertStatus.REVOKED, now, None, gone_at, None) \
        .responder_id(O.OCSPResponderEncoding.HASH, ca).sign(ca_k, H.SHA256())
    return type("R", (), {"content": resp.public_bytes(S.Encoding.DER)})()
real_get, real_post = A.requests.get, A.requests.post
A.requests.get = lambda url, **kw: type("R", (), {"content": ca.public_bytes(S.Encoding.DER)})() if url == "http://certs.test/ca.der" else real_get(url, **kw)
A.requests.post = fake_post
apple["/certificates"] = []  # revoked certificates drop out of the account too; one message, the revoked one
assert [t for _, t in A.cert_account_problems()] == [f"Apple revoked this certificate on {gone_at:%b} {gone_at.day}, {gone_at.year}. Apps signed with it won't open; make a new Apple Distribution certificate."]
A.requests.get, A.requests.post = real_get, real_post  # the source sync's fake_get: OCSP now fails, which is only logged
A.asc = lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("App Store Connect GET /certificates: 500"))
assert [l for l, _ in A.cert_account_problems()] == ["warning"]
A.asc, A.BUNDLE_ID = fake_asc, "com.me.*"
import contextlib
log = io.StringIO()
with contextlib.redirect_stdout(log):
    A.log_cert_problems(A.cert_problems(p12_of(dist_cert(days=-3)), "pw"))
assert log.getvalue().startswith("certificate error: The certificate expired on"), log.getvalue()
A.P12.write_bytes(before)
p12_new = P12x.serialize_key_and_certificates(b"sd", k, dcrt, None, S.BestAvailableEncryption(b"new-p12-pw"))
resign_all_orig, resigns, A.resign_all = A.resign_all, [], lambda: resigns.append(1)
r = boss.post("/admin/signing", data={"csrf": csrf, "p12_password": "wrong", "files": [(io.BytesIO(p12_new), "cert.p12")]}, content_type="multipart/form-data")
assert b"didn&#39;t open" in r.data and A.P12.read_bytes() != p12_new and resigns == []
r = boss.post("/admin/signing", data={"csrf": csrf, "p12_password": "new-p12-pw", "bundle_id": "com.me.*", "files": [(io.BytesIO(p12_new), "cert.p12")]},
              content_type="multipart/form-data")
assert r.location == "/admin?done=signing" and A.P12.read_bytes() == p12_new and A.P12_PASSWORD == "new-p12-pw" and resigns == [1]
assert b"Apps are being signed" in boss.get(r.location).data
regens, A.regen_profile = [], lambda: regens.append(1)
A.resign_all = resign_all_orig
A.resign_all(); assert regens == [1]
A.regen_profile, A.SOURCES = fake_regen, []
boss.get("/logout")
assert b'og:image content="https://x.test/static/og.png"' in A.app.test_client().get("/").data  # link preview on the login page too
assert c.get("/static/sdp1.jpg").status_code == 200  # setup screenshots served
assert A.app.test_client().post("/refresh").status_code == 403 and c.post("/refresh").status_code == 204  # Reload button
fresh = A.app.test_client(); fresh.post("/login", data={"password": "hunter2-but-longer"}); e = "/?enrolled=" + A.device_token("00008130-AAAA")
assert b"Setup Complete" in fresh.get(e).data and b"Setup Complete" not in fresh.get("/").data
assert b"Setup Complete" not in fresh.get(e).data, "a Home Screen icon saved on /?enrolled= shows it only the first time"
assert b"id=firstRun" not in fresh.get("/").data, "the splash is remembered for the phone, so the Home Screen app skips it too"
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

# first run: no PASSWORD/ADMIN_PASSWORD in .env -> default password -> setup splash -> new passwords work, default refused
import importlib.util, io, sys
from cryptography.hazmat.primitives.serialization import pkcs12 as P12
def boot(data, **env):
    """A fresh start of the app on a data folder, with only these .env values."""
    for k in A.SETUP_KEYS + ("SECRET_KEY",):
        os.environ.pop(k, None)
    os.environ.update(DATA=str(data), PUBLIC_URL="https://x.test", **env)
    name = f"app_boot{len(sys.modules)}"
    spec = importlib.util.spec_from_file_location(name, Path(A.__file__))
    m = sys.modules[name] = importlib.util.module_from_spec(spec)
    threading.Thread.start = lambda self: None
    spec.loader.exec_module(m)
    threading.Thread.start = start
    return m
p12 = P12.serialize_key_and_certificates(b"sd", k, dcrt, None, S.BestAvailableEncryption(b"p12-secret"))
p8 = ec.generate_private_key(ec.SECP256R1()).private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption())
bundle = io.BytesIO()
with zipfile.ZipFile(bundle, "w") as z:
    z.writestr("certs/cert.p12", p12); z.writestr("certs/AuthKey_ABCDE12345.p8", p8)
    z.writestr("certs/password.txt", "Password: p12-secret\nissuer 69a6de7e-1111-47e3-e053-5b8c7c11a4d1\n"); z.writestr("__MACOSX/._cert.p12", b"x")
first = tmp / "first"
F = boot(first)
assert F.needs_setup() and (first / "secret.key").exists()
w = F.app.test_client()
assert b"default password, <b>sidedrop</b>" in w.get("/").data
assert "err=1" in w.post("/login", data={"password": "nope"}).location
assert w.post("/login", data={"password": "sidedrop"}).location == "/setup"
assert w.get("/").location == "/setup" and w.post("/check").status_code == 403  # the default password only opens the splash
assert b"Choose Signing Files" in w.get("/setup").data and F.app.test_client().get("/setup").location == "/"
up = lambda **f: w.post("/setup", data=dict(f, files=[(io.BytesIO(bundle.getvalue()), "signing.zip")]), content_type="multipart/form-data")
assert b"at least 8" in up(password="short", admin_password="admin-pass-x").data
assert (first / "cert.p12").read_bytes() == p12 and F.P12_PASSWORD == "p12-secret" and os.environ["ASC_KEY_ID"] == "ABCDE12345"  # kept for a retry
assert os.environ["ASC_ISSUER_ID"] == "69a6de7e-1111-47e3-e053-5b8c7c11a4d1" and (first / "asc.p8").read_bytes() == p8
assert b"App ID" in w.post("/setup", data={"password": "friends-pass", "admin_password": "admin-pass-x"}).data  # no BUNDLE_ID yet
assert b"different ones" in w.post("/setup", data={"password": "same-pass-x", "admin_password": "same-pass-x", "bundle_id": "com.me.*"}).data
bad = io.BytesIO(); zipfile.ZipFile(bad, "w").writestr("cert.p12", p12)
assert b"didn&#39;t open" in w.post("/setup", data={"password": "friends-pass", "admin_password": "admin-pass-x", "bundle_id": "com.me.*",
                                                    "files": [(io.BytesIO(bad.getvalue()), "c.zip")]}, content_type="multipart/form-data").data
r = w.post("/setup", data={"password": "friends-pass", "admin_password": "admin-pass-x", "bundle_id": "com.me.*"})
assert r.location == "/" and b"Register iPhone" in w.get("/").data and not F.needs_setup() and F.BUNDLE_ID == "com.me.*"
saved = (first / "setup.json").read_text()
assert "friends-pass" not in saved and "admin-pass-x" not in saved and "pbkdf2_sha256$" in saved
for M in (F, boot(first)):  # and after a restart
    assert M.P12_PASSWORD == "p12-secret" and M.BUNDLE_ID == "com.me.*" and os.environ["ASC_KEY_ID"] == "ABCDE12345"
    v = M.app.test_client()
    assert b"default password" not in v.get("/").data and "err=1" in v.post("/login", data={"password": "sidedrop"}).location
    assert v.get("/setup").location == "/" and b"Register iPhone" not in v.get("/").data
    assert v.post("/login", data={"password": "friends-pass"}).location == "/" and b"Register iPhone" in v.get("/").data
    assert b"Wrong admin password" in v.post("/admin", data={"password": "friends-pass"}).data
    assert v.post("/admin", data={"password": "admin-pass-x"}).location == "/admin"  # admin unlocked
    M.admin_fails.clear()
assert w.get("/setup").location == "/"  # done: the splash is gone for the one who set it up too
F.asc = fake_asc; fa = F.app.test_client(); assert fa.get("/?password=admin-pass-x").location == "/"  # the saved admin password signs in through the link too
html = fa.get("/admin").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert "App ID (BUNDLE_ID)" in html and b"doesn&#39;t look right" in fa.post("/admin/signing", data={"csrf": csrf, "bundle_id": "com.me.* x"}).data
assert fa.post("/admin/signing", data={"csrf": csrf, "bundle_id": "com.me.sideload"}).status_code == 302 and F.BUNDLE_ID == "com.me.sideload"
assert "pbkdf2_sha256$" in (first / "setup.json").read_text()  # Manage's save keeps the saved passwords
F.BUNDLE_ID = "com.me.*"; s = F.load_json(F.SETUP); s["bundle_id"] = "com.me.*"; F.save_json(F.SETUP, s)
assert boot(first, BUNDLE_ID="com.env.*").BUNDLE_ID == "com.env.*"  # .env still wins over the saved setup
# .env-configured start skips the splash; the default password is just a wrong one
E = boot(tmp / "envd", PASSWORD="env-pass-long", SECRET_KEY="e" * 32)
v = E.app.test_client()
assert not E.needs_setup() and b"default password" not in v.get("/").data and "err=1" in v.post("/login", data={"password": "sidedrop"}).location
assert v.post("/login", data={"password": "env-pass-long"}).location == "/" and b"Register iPhone" in v.get("/").data and E.app.test_client().get("/setup").location == "/"
assert not E.admin_enabled() and v.get("/admin").status_code == 404

# F9 setup with just the API key: a stubbed App Store Connect makes the App ID (with Push) and signs our CSR; at Apple's
# certificate limit the admin picks one to revoke, and nothing is revoked without that pick
class FakeApple:
    def __init__(s):
        s.calls, s.bundles, s.caps, s.certs, s.forbid, s.limit = [], {}, [], {}, False, 3
    def add_cert(s, crt_, name):
        cid = f"C{len(s.certs) + len(s.calls)}"
        s.certs[cid] = {"type": "certificates", "id": cid, "attributes": {
            "name": name, "displayName": name, "certificateType": "DISTRIBUTION", "serialNumber": f"{crt_.serial_number:X}",
            "expirationDate": crt_.not_valid_after_utc.isoformat(), "certificateContent": base64.b64encode(crt_.public_bytes(S.Encoding.DER)).decode()}}
        return cid
    def __call__(s, method, path, **kw):
        s.calls.append((method, path, kw))
        if (method, path) == ("GET", "/bundleIds"):
            return {"data": [b for b in s.bundles.values() if b["attributes"]["identifier"].startswith(kw["params"]["filter[identifier]"])]}
        if (method, path) == ("POST", "/bundleIds"):
            b = dict(kw["json"]["data"], id=f"B{len(s.bundles)}"); s.bundles[b["id"]] = b; return {"data": b}
        if (method, path) == ("POST", "/bundleIdCapabilities"):
            d = kw["json"]["data"]; s.caps.append((d["relationships"]["bundleId"]["data"]["id"], d["attributes"]["capabilityType"])); return {"data": d}
        if (method, path) == ("GET", "/certificates"):
            return {"data": list(s.certs.values())}
        if (method, path) == ("POST", "/certificates"):
            if s.forbid:
                raise RuntimeError('App Store Connect POST /certificates: 403 {"errors":[{"code":"FORBIDDEN_ERROR"}]}')
            if len(s.certs) >= s.limit:
                raise RuntimeError('App Store Connect POST /certificates: 409 {"errors":[{"code":"ENTITY_ERROR"}]}')
            attrs = kw["json"]["data"]["attributes"]
            assert attrs["certificateType"] == "DISTRIBUTION" and attrs["csrContent"].startswith("-----BEGIN CERTIFICATE REQUEST")
            csr = X.load_pem_x509_csr(attrs["csrContent"].encode())
            nm, now = X.Name([X.NameAttribute(X.oid.NameOID.COMMON_NAME, "Apple Distribution: Sam Test (TEAM123456)")]), datetime.datetime.now(datetime.timezone.utc)
            made = X.CertificateBuilder().subject_name(nm).issuer_name(nm).public_key(csr.public_key()).serial_number(X.random_serial_number()) \
                .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=365)).sign(k, H.SHA256())
            return {"data": s.certs[s.add_cert(made, "Sam Test")]}
        if method == "DELETE" and path.startswith("/certificates/"):
            del s.certs[path.rsplit("/", 1)[1]]; return {}
        return {"data": []}
import base64
G = boot(tmp / "apikey")
G.asc = apple = FakeApple()
g = G.app.test_client()
assert g.post("/login", data={"password": "sidedrop"}).location == "/setup"
html = g.get("/setup").data.decode()
assert "Choose API Key" in html and "Manual setup" in html and "developer-account.md#manual-setup" in html and "Choose Signing Files" in html
key_only = lambda **f: g.post("/setup", data=dict({"password": "friends-pass", "admin_password": "admin-pass-x", "bundle_id": "com.me.sideload",
    "asc_issuer_id": "69a6de7e-1111-47e3-e053-5b8c7c11a4d1"}, **f, files=[(io.BytesIO(p8), "AuthKey_KEYID12345.p8")]), content_type="multipart/form-data")
apple.forbid = True  # an App Manager key: Apple refuses the certificate, and the error says which role it needs
r = key_only()
assert b"Admin role" in r.data and not (tmp / "apikey" / "cert.p12").exists() and G.needs_setup()
assert [b["attributes"] for b in apple.bundles.values()] == [{"identifier": "com.me.sideload", "name": "sidedrop", "platform": "IOS"}]
assert apple.caps == [("B0", "PUSH_NOTIFICATIONS"), ("B0", "APP_GROUPS"), ("B0", "ASSOCIATED_DOMAINS")]
apple.forbid = False
r = key_only()
assert r.location == "/" and not G.needs_setup(), re.findall(rb"class=err>[^<]*", r.data)
made_p12 = (tmp / "apikey" / "cert.p12").read_bytes()
assert G.cert_problems(made_p12, G.P12_PASSWORD) == [] and len(G.P12_PASSWORD) >= 20  # signs: our key, Apple's Distribution cert
assert G.load_json(G.SETUP)["p12_password"] == G.P12_PASSWORD and os.environ["ASC_KEY_ID"] == "KEYID12345"
assert len(apple.bundles) == 1 and len(apple.caps) == 3 and len(apple.certs) == 1  # the App ID made once, not again on the retry
assert [m for m, p, _ in apple.calls].count("DELETE") == 0
assert G.ensure_app_id("com.me.*") and len(apple.caps) == 3 and not G.ensure_app_id("com.me.*")  # a wildcard gets no capabilities
# Manage: Make New Certificate with the account full lists the certificates and revokes nothing; the pick is revoked, then a new one made
apple.add_cert(dist_cert("Apple Distribution: Old Mac (TEAM123456)"), "Old Mac"); apple.add_cert(dist_cert(days=40), "Elsewhere")
ga = G.app.test_client(); assert ga.get("/?password=admin-pass-x").location == "/"
html = ga.get("/admin").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert "Make New Certificate" in html and "Choose API Key" in html and "Manual setup" in html
r = ga.post("/admin/signing", data={"csrf": csrf, "make": "1"}).data.decode()
assert "as many Apple Distribution certificates" in r and "stop opening" in r and r.count('name=revoke value=') == 3
assert "Old Mac" in r and "Elsewhere" in r and r.count("sidedrop's certificate") == 1 and "expires" in r and "made " in r
assert [m for m, p, _ in apple.calls].count("DELETE") == 0 and (tmp / "apikey" / "cert.p12").read_bytes() == made_p12
assert "isn&#39;t in your account" in ga.post("/admin/signing", data={"csrf": csrf, "make": "1", "revoke": "nope"}).data.decode()
old = next(i for i, c in apple.certs.items() if c["attributes"]["name"] == "Old Mac")
r = ga.post("/admin/signing", data={"csrf": csrf, "make": "1", "revoke": old})
assert r.location == "/admin?done=signing" and [p for m, p, _ in apple.calls if m == "DELETE"] == [f"/certificates/{old}"]
assert old not in apple.certs and len(apple.certs) == 3 and (tmp / "apikey" / "cert.p12").read_bytes() != made_p12
assert G.cert_problems((tmp / "apikey" / "cert.p12").read_bytes(), G.P12_PASSWORD) == [] and len(apple.bundles) == 2  # App ID kept
# the manual path still takes an uploaded cert.p12 on Manage, and asks Apple for nothing
before = len(apple.calls)
r = ga.post("/admin/signing", data={"csrf": csrf, "p12_password": "p12-secret", "files": [(io.BytesIO(p12), "cert.p12")]}, content_type="multipart/form-data")
assert r.location == "/admin?done=signing" and (tmp / "apikey" / "cert.p12").read_bytes() == p12 and G.P12_PASSWORD == "p12-secret"
assert all(m == "GET" for m, _, _ in apple.calls[before:])
assert ga.post("/admin/signing", data={"csrf": csrf, "bundle_id": "com.me.other"}).location == "/admin?done=signing"  # a new App ID is made
assert [b["attributes"]["identifier"] for b in apple.bundles.values()] == ["com.me.sideload", "com.me.*", "com.me.other"]
print("ok")
