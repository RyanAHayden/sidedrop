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
    assert "--rm_watch" in cmd  # no watch is ever in the profile
    signed_ents.append(plistlib.loads(Path(cmd[cmd.index("-e") + 1]).read_bytes()))
    Path(cmd[cmd.index("-o") + 1]).write_bytes((tmp / "apps" / "Demo.ipa").read_bytes())
A.regen_profile, A.asc, A.subprocess.run = fake_regen, fake_asc, fake_run
orig_register = A.register
A.register = lambda u, n, **kw: (calls.append((u, n)), orig_register(u, n, **kw))

c = A.app.test_client()
path_qs = lambda url: (lambda s: f"{s.path}?{s.query}")(urlsplit(url))
# B2: POST /enroll answers 303 to a signed GET link that serves the profile (Safari refetches downloads with GET)
enroll = lambda cl, **d: cl.get(path_qs(cl.post("/enroll", data=d).location)).data

# login gate
assert b"Password" in c.get("/").data and b"The friend who sent you the link has the password." in c.get("/").data
assert c.post("/enroll").status_code == 403
A.time.sleep = lambda s: None
assert "err=1" in c.post("/login", data={"password": "nope"}).location
c.post("/login", data={"password": "hunter2-but-longer"})
assert b"Register iPhone" in c.get("/").data

# shareable link logs in and strips the password from the URL
link = A.app.test_client()
r = link.get("/?password=hunter2-but-longer")
assert r.status_code == 302 and r.location == "/?go=setup" and b"Register iPhone" in link.get("/").data  # F30: a setup link
assert "err=1" in A.app.test_client().get("/?password=wrong").location

# enrollment profile points at a signed /udid URL
r = c.post("/enroll", data={"name": "Sam <script>"})
assert r.status_code == 303 and "/enroll/profile/Sam%20script?e=" in r.location, r.location
g = c.get(path_qs(r.location)); assert g.status_code == 200 and g.content_type == "application/x-apple-aspen-config"
assert A.app.test_client().get(path_qs(r.location)).status_code == 200  # no session needed: the signature is the auth
assert c.get(path_qs(r.location)).status_code == 200  # fetched twice: still fine
assert c.get(path_qs(r.location).replace("&s=", "&s=0")).status_code == 403
assert c.get("/enroll").status_code == 302
prof = plistlib.loads(g.data)
url = prof["PayloadContent"]["URL"]
assert "/udid/Sam%20script?" in url, url
# F17: what the Settings app shows says SideDrop; the identifier installed phones carry stays sidedrop.udid
assert (prof["PayloadDisplayName"], prof["PayloadOrganization"], prof["PayloadIdentifier"]) == ("SideDrop device registration", "SideDrop", "sidedrop.udid")

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
der = enroll(c, name="Sam")
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
# Apps header: welcome, GitHub | iFizBox, then Help (F26: no About) and the setup tile, which folds the SDP + Register steps behind it
assert b"just under your name" in html and b"<b>Install</b> in the top-right corner" in html and b"VPN &amp; Device Management" in html  # R1: where each tap is
assert b"Welcome to SideDrop" in html and b"<title>SideDrop</title>" in html and b"<h1 id=navT>SideDrop</h1>" in html and b"Ryan Hayden (Fizlo)</a>" in html and b"go('ifizbox')" in html and b"id=setupT" in html and b"<div id=setup hidden>" in html
# F26: the About alert, its nav button and its tiles are gone; Help is a pushed page
assert b"About" not in html and b"id=about" not in html and b"aboutT" not in html and b'<a class=tile href=/help onclick="return helpOpen()">' in html
# F17: the SideDrop name and what it's for, in the head, the header, the register step and Help; no lowercase name a person sees
assert html.count(b"Share an Apple developer account with friends and sideload apps.") == 2 and b"og:site_name content=SideDrop" in html
assert b"with a friend's Apple developer account.</p>" in html
assert b"adds your iPhone to the shared developer account" in html
assert b"sidedrop" not in re.sub(rb"sidedrop\.udid|/static/[\w.]+", b"", html), re.findall(rb".{40}sidedrop.{40}", html)
assert b">Help</a>" in html and b'class="tile reg"' not in html
# F22: no Changes tab and no signing your own IPA: nothing links to them, and Help points to iFizBox instead
for gone in (b"#changes", b"'changes'", b"t-changes", b">Changes<", b"/sign", b"getElementById('sign')", b"Sign IPA", b"Sign your own IPA", b"Choose .ipa File", b"name=ipa"):
    assert gone not in html, gone
hp = c.get("/help").data
assert b"for your own IPAs and other sources, use <a href=/#ifizbox" in hp and b"signed with a friend's developer certificate" in hp
assert b"sidedrop" not in re.sub(rb"sidedrop\.udid|/static/[\w.]+", b"", hp), re.findall(rb".{40}sidedrop.{40}", hp)
assert b'href="itms-services' not in c.get("/?enrolled=1").data and b'href="itms-services' not in c.get("/?enrolled=00008130-AAAA.x").data
html = c.get(r.location.replace("https://x.test", ""), base_url="https://localhost").data
assert b"Every app on the Apps tab can install on this iPhone." in html and b"href=/admin" not in html and b"/static/sdp1.jpg" not in html  # Manage is the admin's only; F26: SDP only in Help
assert b"id=sManage" not in html and b"<div>Manage</div>" not in html  # F26: the Manage row is the admin's only
assert b'class="tile reg"' in html and b"id=setupT" not in html and b"id=setup " not in html  # registered: the green tile
assert b"#changes" not in html and b"'changes'" not in html and b"t-changes" not in html and b"/sign" not in html and b"Sign IPA" not in html
c.get("/logout", base_url="https://localhost"); c.post("/login", data={"password": "hunter2-but-longer"}, base_url="https://localhost")
assert b"Every app on the Apps tab can install on this iPhone." in c.get("/", base_url="https://localhost").data
assert A.profile_udids() == {"00008130-AAAA"} and (tmp / "signed" / "Demo.ipa").exists()
# F15 version lines: the registered iPhone's PRODUCT and the commit at the bottom of Apps and Settings (F26: About is gone); unregistered: plain iPhone
os.environ["SIDEDROP_COMMIT"] = "9dc9923"; assert A.read_commit() == "9dc9923"; del os.environ["SIDEDROP_COMMIT"]
A.COMMIT = "9dc9923"
html = c.get("/", base_url="https://localhost").data.decode()
assert html.count('<p class=ver data-m="iPhone16,1">iPhone16,1, SideDrop</p><p class="ver vc">9dc9923</p>') == 2, html.count("class=ver")
apps_tab = html[html.index("id=t-apps"):]; apps_tab = apps_tab[:apps_tab.index("</section>")]
settings_tab = html[html.index("id=t-settings"):]; settings_tab = settings_tab[:settings_tab.index("</section>")]
assert "9dc9923" in apps_tab and "9dc9923" in settings_tab
assert settings_tab.index(">Sign Out</a>") < settings_tab.index("class=ver")  # Sign Out, then the version line
assert "navigator.language" in html and "like Mac OS X" in html
html = A.app.test_client().get("/?enrolled=" + A.device_token("00008130-AAAA")).data.decode()  # signed out: the sign-in page has it
assert 'data-m="iPhone16,1"' in html and "9dc9923" in html
anon = A.app.test_client(); anon.post("/login", data={"password": "hunter2-but-longer"})
html = anon.get("/").data.decode()
assert html.count('<p class=ver data-m="iPhone">iPhone, SideDrop</p>') == 2 and "iPhone16,1" not in html
(tmp / "products.json").unlink()  # registered before F15: the PRODUCT in Apple's device name, else its model
A.save_json(A.DEVICES, {"at": 1, "data": [{"attributes": {"udid": "00008130-AAAA", "name": "Sam iPhone15,2", "model": "iPhone 14 Pro"}}]})
assert A.device_model("00008130-AAAA") == "iPhone15,2"
A.save_json(A.DEVICES, {"at": 1, "data": [{"attributes": {"udid": "00008130-AAAA", "name": "Sam", "model": "iPhone 14 Pro"}}]})
assert A.device_model("00008130-AAAA") == "iPhone 14 Pro" and A.device_model("other") == "iPhone" and A.device_model(None) == "iPhone"
(tmp / "devices.json").unlink(); A.save_product("00008130-AAAA", "iPhone16,1")
A.COMMIT = ""
assert 'class="ver vc"' not in c.get("/", base_url="https://localhost").data.decode()  # no commit, no second line
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

# first install tap: a one-time splash (Developer Mode, Help's screenshots; F26: no Stolen Device Protection) holds the tap, then carries it on; remembered per phone
fr = html.split("id=firstRun")
assert len(fr) == 2 and "hidden data-due=1" in fr[1][:40] and "/static/sdp1.jpg" not in fr[1] and "Stolen Device" not in fr[1] and "/static/dev3.jpg" in fr[1] and "firstRunGo(1)" in fr[1]
# F23: Developer Mode stays for every profile kind (iOS 27 asks for it for Ad Hoc too) and each place says why, the same words
why = "iOS 27 asks for Developer Mode once for apps installed outside the App Store. Turn it on, restart, then the app opens."
assert A.DEV_WHY == why and f"<p class=lead>{why}</p>" in fr[1] and "One setting, once per iPhone" not in html
assert f"<h3 id=devT>Developer Mode Required</h3><p>{why}</p>" in html and "It needs Developer Mode, like every app here" not in html
assert "e.target.closest('a[href^=\"itms-services:\"],#ifzb')" in html and html.count("/static/dev1.jpg") == 1  # catches every install link; Developer Mode's steps also in Help (its own page)
assert A.app.test_client().post("/first-run").status_code == 403
assert c.post("/first-run").status_code == 204 and list(A.load_json(A.FIRST_RUN)) == ["00008130-AAAA"]
html = c.get("/").data.decode()
assert "id=firstRun" not in html and html.count("/static/dev1.jpg") == 0 and 'href="itms-services' in html  # second tap: straight to iOS (F26: Help's copy is on /help)

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
# an explicit App ID with Push (the paid-signing-service way): every app keeps its own bundle ID, iFizBox's too, extensions keep
# theirs; the entitlements carry the profile's App ID, the keychain group narrowed to it
prof0, bid0 = A.PROFILE.read_bytes(), A.BUNDLE_ID
A.BUNDLE_ID = "com.me.sideload"
A.PROFILE.write_bytes(plistlib.dumps({"Entitlements": {"application-identifier": "TEAM.com.me.sideload", "aps-environment": "production",
    "com.apple.developer.team-identifier": "TEAM", "keychain-access-groups": ["TEAM.*", "com.apple.token"], "get-task-allow": False,
    "com.apple.security.application-groups": []}}))
def look(cmd, **kw):
    with zipfile.ZipFile(cmd[-1]) as z:
        seen_in.append(({n: plistlib.loads(z.read(n))["CFBundleIdentifier"] for n in z.namelist() if n.endswith("/Info.plist") and ".lproj/" not in n},
                        plistlib.loads(Path(cmd[cmd.index("-e") + 1]).read_bytes()), "--rm_watch" in cmd))
A.subprocess.run = look
for ipa in ("pb.ipa", "ifz-src.ipa"):
    A.sign_ipa(tmp / ipa, tmp / "explicit-signed.ipa")
A.subprocess.run = run0
(pb_ids, pb_ents, pb_rm), (ifz_ids, ifz_ents, _) = seen_in[-2:]
assert pb_ids == {"Payload/PB.app/Info.plist": "com.mario.pb", "Payload/PB.app/PlugIns/W.appex/Info.plist": "com.mario.pb.widget"} and pb_rm
assert ifz_ids == {"Payload/iFizBox.app/Info.plist": "com.ryha.ifizbox"}
assert pb_ents == ifz_ents == {"application-identifier": "TEAM.com.me.sideload", "aps-environment": "production", "com.apple.developer.team-identifier": "TEAM",
    "keychain-access-groups": ["TEAM.com.me.sideload"], "get-task-allow": False, "com.apple.security.application-groups": []}, pb_ents
A.PROFILE.write_bytes(prof0); A.BUNDLE_ID = bid0
# iFizBox gets its own category above Apps
(tmp / "signed" / "com.ryha.ifizbox.ipa").write_bytes((tmp / "ifz.ipa").read_bytes())
html = c.get("/").data.decode()
assert html.index("<h3 class=hdr>iFizBox</h3>") < html.index("<h3 class=hdr>Apps</h3>") < html.index("Demo")
# its GET opens the iFizBox tab (the install is that page's button); the tab has the install button with the manifest and the benefits
assert 'href=#ifizbox onclick="go(\'ifizbox\');return false"' in html and 'id=t-ifizbox' in html and 'id=ifzb data-app="com.ryha.ifizbox" data-m="https://x.test/m/com.ryha.ifizbox.plist?e=' in html
assert "Your certificate, already in it" in html and "10 sources" in html
# F25: Home's iFizBox card: no "Why iFizBox" footer, the "Recommended" line, a green INSTALL that opens the page and starts the install once
card = html[html.index("<h3 class=hdr>iFizBox</h3>"):html.index("<h3 class=hdr>Apps</h3>")]
assert "Why" not in card and "class=ftr" not in card and '<small class=rec>Recommended: get update alerts and install more apps</small>' in card
assert '<a class="get go" data-app="com.ryha.ifizbox" aria-label="Install com.ryha.ifizbox" href=#ifizbox onclick="return ifzGo(this)">INSTALL</a>' in card
assert ".get.go{min-width:76px" in html and ".get:before{" in html and "background:var(--greenbtn)" in html, "the green is the INSTALL state's --greenbtn"
# B3: in dark themes every armed INSTALL keeps white text and the green border: .dark .get.go (0,3,0) outranks .dark .get, which sits after .get.go
assert ".dark .get.go{color:#fff;border-color:#2f7a17}" in html and ".dark .get.go.is-pressed{border-color:#255e12}" in html
assert html.index(".dark .get{") < html.index(".dark .get.go.is-pressed{"), "the pressed border comes after the ifzr rule and .dark .get"
# B5: plain blue buttons outside forms (Copy Link) take the blue pressed look at one class of weight; dark grey buttons hold with --barpress
# (iFizBox's --dk-btn-pressed), a rule that outranks .dark button.grey; a held mouse presses too, not through :active
assert ":where(button:not(.grey,.act,.gbtn,.get,.tile,.bar,.ok,.mkc,.confin)).is-pressed{border-color:#1f3b67;background:linear-gradient(#5c7cb3," in html
assert ".dark button.grey.is-pressed{color:var(--text);border-color:var(--barpe);background:var(--barpress);" in html and ".dark button.grey{" in html
assert 'addEventListener("pointerdown",e=>{if(e.pointerType!=="mouse"||e.button)return;' in html and 'addEventListener("pointerup",e=>{if(e.pointerType==="mouse")unpress()})' in html
assert 'addEventListener("hashchange",()=>{if(ifzAuto&&cur=="ifizbox"){ifzAuto=0;ifzRun()}});' in html, "the page runs the install once, off the flag"
assert 'function ifzGo(c){ifzAuto=1;go("ifizbox");ifzAuto=0;' in html, "the flag is set only for the card's tap"
c.post("/installed", data={"name": "com.ryha.ifizbox"})
card = (h := c.get("/").data.decode())[h.index("<h3 class=hdr>iFizBox</h3>"):h.index("<h3 class=hdr>Apps</h3>")]
assert 'class="get done"' in card and ">INSTALLED</a>" in card and " go" not in card, "current: the grey INSTALLED"
# F27: the card's hold sheet marks it too (Mark as Not Installed: the green INSTALL again; Mark as Installed: INSTALLED)
f27 = lambda do: c.post("/installed/mark", data={"name": "com.ryha.ifizbox", "do": do, "csrf": A.mark_csrf(A.token_udid(c.get_cookie("device").value))}).status_code
assert f27("forget") == 204 and '<a class="get go" data-app="com.ryha.ifizbox"' in (h := c.get("/").data.decode()) and ">INSTALL</a>" in h
assert f27("installed") == 204 and '<a class="get done" data-app="com.ryha.ifizbox"' in c.get("/").data.decode()
# tabs: Apps, iFizBox, Settings (no Feather, no More, no Changes, and no Files tab while there are no files: F14)
assert re.findall(r"<a href=#(\w+)><svg", html) == ["apps", "ifizbox", "settings"] and "t-feather" not in html and "id=t-files" not in html and "t-changes" not in html
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

# Manage opens as a page pushed in place; pressed looks come from JS (.is-pressed), never :active, which iOS leaves stuck
html = c.get("/").data.decode()
assert 'closest("a[data-push]")' in html and ":active{" not in html and ":active," not in html
# the inline scripts parse (a syntax error kills every button on the page)
import shutil, subprocess
if shutil.which("node"):
    for js in re.findall(r"<script>(.*?)</script>", html, re.S):
        (tmp / "inline.js").write_text(js)
        r = subprocess.Popen(["node", "--check", str(tmp / "inline.js")], stderr=subprocess.PIPE, text=True)  # subprocess.run is stubbed above
        assert r.wait() == 0, r.stderr.read()

# F18 themes: the nine palettes in iFizBox's order, each a CSS block on the page with every token its tone's default sets, and (F20) a row
# in its tone's Settings > Theme checklist
assert A.THEMES == {"light": ["classic", "sepia", "solarized"], "dark": ["oled", "gunmetal", "midnight", "linen", "nord", "dracula"]}
toks = lambda css: set(re.findall(r"--([a-z]+):", css))
theme_lists = {t: c.get(f"/theme/{t}", base_url="https://localhost").data.decode() for t in ("light", "dark")}
for n, (tone, label, color, css) in A.PALETTES.items():
    assert f"html[data-theme={tone}][data-palette={n}]{{" in html and f"data-v={n} " in theme_lists[tone] and f"<div>{label}</div>" in theme_lists[tone], n
    assert f"data-v={n} " not in theme_lists["dark" if tone == "light" else "light"], n
    assert toks(A.PALETTES[A.THEMES[tone][0]][3]) <= toks(css), (n, toks(A.PALETTES[A.THEMES[tone][0]][3]) - toks(css))
    assert f"html[data-palette={n}]{{--seg:" in html and n in A.SWATCH, n  # F20: its segmented control's colours and its swatch
# B4: themeMarks is defined only by Settings > Theme's script, so the main page calls it only behind a guard
assert "function themeMarks(" not in html and html.count("themeMarks()") == html.count("if(window.themeMarks)themeMarks()"), "an unguarded themeMarks() on the main page"
assert "darkSw" not in html and "data-tk=" not in html and "Display" not in html  # F20: the theme lists left the Settings tab for Settings > Theme

# F20 Settings > Theme, as iFizBox's: a Theme row (its tile) in Settings pushes it; Mode is a segmented control, Themes' Light and Dark rows
# push their checklists (the tone's default ticked until themeMarks reads the stored choice) with a preview under them
settings_tab = html[html.index("id=t-settings"):]; settings_tab = settings_tab[:settings_tab.index("</section>")]
ico = lambda name: str(A.row_icon(name))  # str: Markup + str would escape the str
assert '<a class="row mrow" href=/theme data-push>' + ico("theme") + "<div>Theme</div><span class=val id=themeV>Classic</span></a>" in settings_tab
assert ico("notifications") + "<div>Update Alerts</div>" in settings_tab
# F26, the user's concept: the groups in order (This iPhone; Theme + Update Alerts; Add to Home Screen; Help), each footer under its group,
# then Sign Out and the version line; no iFizBox row (the tab bar has it), no About, no 'iPhones used' (Manage > iPhones has it)
assert re.findall(r'<div class="g[^"]*" id=(s\w+)>', settings_tab) == ["sThis", "sTheme", "sHome", "sHelp"]
assert ico("status") + "<div>Status</div><span class=val>Registered</span>" in settings_tab
for gone in (">iFizBox<", "#ifizbox", "About", "iPhones used", ico("slots"), "Stolen Device", "<details", "class=tile", "class=pair", "g split"):
    assert gone not in settings_tab, gone
# F29: no 'This iPhone' title; a user has no Admin Settings or Share row; Theme sits under Preferences; Settings doesn't rubber-band
assert "This iPhone</h3>" not in settings_tab and "Admin Settings" not in settings_tab and "id=shareRow" not in settings_tab and "<div>Share</div>" not in settings_tab
assert re.findall(r"<h3 class=hdr>([^<]+)</h3>", settings_tab) == ["Preferences"] and settings_tab.index("Preferences</h3>") < settings_tab.index("<div>Theme</div>")
assert "#scr:has(>#t-settings:not([hidden])){overscroll-behavior-y:none} #t-settings{min-height:0}" in html
order = [settings_tab.index(s) for s in ("<div>Status</div>", "Every app on the Apps tab can install on this iPhone.</p>",
                                         "<div>Theme</div>", "<div>Update Alerts</div>", "Tells you when an app you installed has a new version.</p>",
                                         '<a class="row mrow" href=/home-screen data-push>' + ico("homeScreen") + "<div>Add to Home Screen</div></a>",
                                         "Open SideDrop from your Home Screen like an app.</p>",
                                         '<a class="row mrow" href=/help data-push id=helpRow>' + ico("help") + "<div>Help</div></a>",
                                         '<a class="b grey out" href=/logout>Sign Out</a>', "class=ver")]
assert order == sorted(order), order
assert '"classic": "Classic"' in settings_tab and "function themeVal()" in settings_tab  # the Theme row's detail follows the theme showing
# Help (pushed, back Settings): Problems (Register iPhone Didn't Work with the SDP steps, An App Won't Install, Developer Mode as today), then
# Getting Started (Add to Home Screen, Notifications in Apps, More Apps with iFizBox); Stolen Device Protection is only under the first
r = c.get("/help", base_url="https://localhost"); hp = r.data.decode()
assert r.status_code == 200 and "<h1>Help</h1>" in hp and '<a class="bar back" href="/#settings"' in hp and ">Settings</a>" in hp
assert re.findall(r"<h3 class=hdr>([^<]+)</h3>", hp) == ["Problems", "Getting Started"]
assert re.findall(r"<details id=(\w+)><summary>.*?<span>([^<]+)</span>", hp) == [
    ("register", "Register iPhone Didn't Work"), ("install", "An App Won't Install"), ("dev", "Turn on Developer Mode"),
    ("a2hs", "Add to Home Screen"), ("notify", "Notifications in Apps"), ("more", "More Apps with iFizBox")], re.findall(r"<details id=(\w+)><summary>.*?<span>([^<]+)</span>", hp)
reg = hp[hp.index("<details id=register>"):hp.index("<details id=install>")]
assert "Tap <b>Register iPhone</b> again, then <b>Allow</b>" in reg and "<b>Profile Downloaded</b>" in reg and "<b>Install</b>" in reg
ins = hp[hp.index("<details id=install>"):hp.index("<details id=dev>")]  # F33: Install only shows once registered, so no registration step
assert "Registered" not in ins and "egister" not in ins and re.findall(r"<li>(.*?)</li>", ins) == [
    "An app stuck half-installed (a grey icon): delete it from the Home Screen, then tap GET again.", "Installed but it won't open? Turn on Developer Mode, below."]
assert "wait timer" in reg and "/static/sdp1.jpg" in reg and "at home" in reg and hp.count("/static/sdp1.jpg") == 1
assert f"<span>Turn on Developer Mode</span></summary><p>{A.DEV_WHY}</p>" in hp  # F23: Help says why too
assert "/static/dev3.jpg" in hp[hp.index("<details id=dev>"):] and "class=shot" in hp and ".shot{" in hp  # its own copy of the steps' look
assert c.get("/home-screen", base_url="https://localhost").status_code == 200 and "<h1>Add to Home Screen</h1>" in c.get("/home-screen", base_url="https://localhost").data.decode()
assert A.app.test_client().get("/help").status_code == 302 and A.app.test_client().get("/home-screen").status_code == 302  # signed out: the sign-in page
assert "function helpOpen(id)" in html and 'function devDone(show){devAsk.hidden=true;if(show)helpOpen("dev")' in html  # Show Me opens Help at Developer Mode
assert A.ROW_ICONS["theme"][0] == "#4650b4"  # rowicons.js ROW_ICONS.theme: indigo "contrast"
r = c.get("/theme", base_url="https://localhost"); tp = r.data.decode()
assert r.status_code == 200 and "<h1>Theme</h1>" in tp and '<a class="bar back" href="/#settings"' in tp and ">Settings</a>" in tp
seg = re.search(r'<div class="seg" role=radiogroup aria-label="Mode" data-tk=mode>(.*?)</div>', tp).group(1)
assert re.findall(r"data-v=(\w+) aria-checked=(\w+)[^>]*>(\w+)<", seg) == [("auto", "true", "Automatic"), ("light", "false", "Light"), ("dark", "false", "Dark")]
assert "onclick=\"themeSet('mode',this.dataset.v)\"" in seg and "<h3 class=hdr>Mode</h3>" in tp and "<h3 class=hdr>Themes</h3>" in tp
assert '<a class="row mrow" href=/theme/light data-push><div>Light</div><span class=val data-tv=lightTheme>Classic</span></a>' in tp
assert '<a class="row mrow" href=/theme/dark data-push><div>Dark</div><span class=val data-tv=darkTheme>OLED Black</span></a>' in tp
assert "Automatic switches between your Light and Dark themes" in tp and 'themePreview("' not in tp
assert c.get("/display", base_url="https://localhost").data.decode() == tp  # Display's old address still opens Theme
for tone, first in (("light", "classic"), ("dark", "oled")):
    tl = theme_lists[tone]
    assert f"<h1>{tone.title()}</h1>" in tl and '<a class="bar back" href="/theme"' in tl and f'themePreview("{tone}");' in tl
    ticks = re.findall(r'class="row ck" role=radio data-v=(\w+) aria-checked=(\w+)', tl)
    assert ticks == [(n, str(n == first).lower()) for n in A.THEMES[tone]], ticks
    assert f"data-tk={tone}Theme" in tl and A.THEME_FOOTERS[tone] in tl and "<div class=tpv aria-hidden=true inert>" in tl
assert c.get("/theme/blue", base_url="https://localhost").status_code == 404
assert A.app.test_client().get("/theme").status_code == 302 and A.app.test_client().get("/theme/dark").status_code == 302  # signed out: home
if shutil.which("node"):  # the Theme pages' scripts: they parse, and in node (boot script first, fake storage and <html>) preview and pick
    import json
    for page_html in (tp, *theme_lists.values()):
        for js in re.findall(r"<script>(.*?)</script>", page_html, re.S):
            (tmp / "inline.js").write_text(js)
            r = subprocess.Popen(["node", "--check", str(tmp / "inline.js")], stderr=subprocess.PIPE, text=True)
            assert r.wait() == 0, r.stderr.read()
    (tmp / "theme-run.js").write_text("""const vm=require("vm"),fs=require("fs"),[boot,pg]=[2,3].map(i=>fs.readFileSync(process.argv[i],"utf8"));
const out=JSON.parse(process.argv[4]).map(([store,steps])=>{let at={},meta={content:""},ls=Object.assign(Object.create({removeItem(k){delete this[k]}}),store);
 let ctx={localStorage:ls,window:{},matchMedia:()=>({matches:false,addEventListener(){}}),addEventListener(){},
  document:{querySelector:()=>meta,querySelectorAll:()=>[],currentScript:null,documentElement:{setAttribute:(k,v)=>at[k]=v,classList:{toggle(){}}}}};
 vm.createContext(ctx);vm.runInContext(boot,ctx);vm.runInContext(pg,ctx);let seen=[at["data-theme"]];
 for(const s of steps){vm.runInContext(s,ctx);seen.push(at["data-theme"])}return [seen,{...ls}]});console.log(JSON.stringify(out))""")
    (tmp / "boot.js").write_text(re.search(r"<script>(/\* F18 themes.*?)</script>", tp, re.S).group(1))
    for page_html, cases in [
        (theme_lists["dark"], [  # (stored, calls) -> (data-theme after load and after each call, stored after)
            ({"mode": "light"}, ["themeSet('darkTheme','nord')", "themeTone=null;theme()"], ["dark", "dark", "dark"], {"mode": "dark", "darkTheme": "nord"}),
            ({"mode": "dark", "darkTheme": "linen"}, ["themeSet('darkTheme','oled')"], ["dark", "dark"], {"mode": "dark", "darkTheme": "oled"})]),
        (theme_lists["light"], [  # the light list previews light on a dark Mode; picking there switches Mode, and the old key goes
            ({"mode": "dark", "dark": "1"}, ["themeSet('lightTheme','sepia')"], ["light", "light"], {"mode": "light", "lightTheme": "sepia"})]),
        (tp, [  # Theme itself previews nothing; Mode's segments store it and drop the pre-F18 key
            ({"dark": "1"}, ["themeSet('mode','auto')", "themeSet('mode','dark')"], ["dark", "light", "dark"], {"mode": "dark"})])]:
        (tmp / "page.js").write_text(re.search(r"<script>(/\* F20 Settings > Theme.*?)</script>", page_html, re.S).group(1))
        tproc = subprocess.Popen(["node", str(tmp / "theme-run.js"), str(tmp / "boot.js"), str(tmp / "page.js"), json.dumps([c_[:2] for c_ in cases])],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        tout, terr = tproc.communicate()
        assert tproc.returncode == 0, terr
        for (t_store, t_calls, t_seen, t_stored), t_got in zip(cases, json.loads(tout)):  # (names of their own: k, s and p are used further down)
            assert t_got == [t_seen, t_stored], (t_store, t_calls, t_got)
assert html.index("data-palette") < html.index("<style>"), "the boot script runs before the CSS, so the first paint has the theme"
assert ":root,html[data-theme=light][data-palette=classic]{" in html and "html.dark,html[data-theme=dark][data-palette=gunmetal]{" in html
assert "base64," in A.PALETTES["sepia"][3] and "#c4a77d" in __import__("base64").b64decode(A.PALETTES["sepia"][3].split("base64,")[1].split('"')[0]).decode()
if shutil.which("node"):  # the boot script itself, in node with a fake localStorage, phone appearance, <html> and theme-color meta
    (tmp / "boot.js").write_text(re.search(r"<script>(/\* F18 themes.*?)</script>", html, re.S).group(1))
    (tmp / "boot-run.js").write_text("""const vm=require("vm"),boot=require("fs").readFileSync(process.argv[2],"utf8");
console.log(JSON.stringify(JSON.parse(process.argv[3]).map(([store,dark])=>{let at={},cls=new Set(),meta={content:""};
 vm.runInNewContext(boot,{localStorage:store,window:{},matchMedia:()=>({matches:dark,addEventListener(){}}),document:{querySelector:()=>meta,
  documentElement:{setAttribute:(k,v)=>at[k]=v,classList:{toggle:(c,on)=>(on?cls.add(c):cls.delete(c),on)}}}});
 return [at["data-theme"],at["data-palette"],cls.has("dark"),meta.content]})))""")
    cases = [  # (localStorage, phone dark) -> (data-theme, data-palette, .dark, theme-color)
        ({}, False, "light", "classic", "#4f698b"),  # nothing stored: Automatic, each tone's first theme
        ({}, True, "dark", "oled", "#000"),
        ({"dark": "1"}, False, "dark", "oled", "#000"),  # the old Dark Mode switch on: Mode Dark
        ({"dark": "0"}, True, "light", "classic", "#4f698b"),  # and off: Mode Light, even on a dark phone
        ({"mode": "dark", "darkTheme": "nord"}, False, "dark", "nord", "#2e3440"),
        ({"mode": "light", "lightTheme": "sepia", "dark": "1"}, True, "light", "sepia", "#7a5c36"),  # a picked Mode wins over the old key
        ({"mode": "auto", "lightTheme": "solarized", "darkTheme": "gunmetal"}, True, "dark", "gunmetal", "#5f656f"),
        ({"mode": "auto", "lightTheme": "solarized", "darkTheme": "gunmetal"}, False, "light", "solarized", "#2a74a8"),
        ({"mode": "bogus", "darkTheme": "bogus", "dark": "1"}, False, "dark", "oled", "#000"),  # unknown values fall back
        ({"mode": "light", "lightTheme": "nord"}, False, "light", "classic", "#4f698b"),  # a dark theme's name isn't a light theme
    ] + [({"mode": t, f"{t}Theme": n}, False, t, n, A.PALETTES[n][2]) for t, ns in A.THEMES.items() for n in ns]
    import json
    p = subprocess.Popen(["node", str(tmp / "boot-run.js"), str(tmp / "boot.js"), json.dumps([[s, d] for s, d, *_ in cases])], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    assert p.returncode == 0, err
    for (s, d, tone, pal, color), got in zip(cases, json.loads(out)):
        assert got == [tone, pal, tone == "dark", color], (s, d, got)

# F22: signing your own IPA is gone: no route, and its old storage (signed/custom/) is cleared at start
import io
assert c.post("/sign", data={"url": "https://gh/t.ipa"}).status_code in (404, 405)
(tmp / "signed" / "custom").mkdir(); (tmp / "signed" / "custom" / "0123abcd.ipa").write_bytes(b"x")
A.drop_old_custom_signs(); assert not (tmp / "signed" / "custom").exists()
# F22: Home's update rows. Installs are recorded per phone; a newer signed version then turns that app's row into an update
# (UPDATE in place of GET, "Update available" beside the version) and the Apps tab's badge counts them
def apps_tab(h): return re.search(r"<section class=page id=t-apps .*?</section>", h, re.S).group(0)
def badge(h): return re.search(r"<span class=badge id=badge( hidden)?>(\d+)</span>", h).groups()
html = c.get("/").data.decode()
assert "Update available" not in html and 'class="row up"' not in html and badge(html) == (" hidden", "0")
assert re.search(r'href=#apps><svg[^>]*>.*?</svg>Apps<span class=badge id=badge hidden>0</span></a>', html), "the badge sits on the Apps tab"
assert A.app.test_client().post("/installed", data={"name": "Demo"}).status_code == 403
assert c.post("/installed", data={"name": "../x"}).status_code == 403
assert c.post("/installed", data={"name": "Demo"}).status_code == 204 and "Update available" not in c.get("/").data.decode()
html = c.get("/").data.decode()
assert 'class="get done" data-app="Demo" aria-expanded=false onclick="steps(this)">INSTALLED<' in html and badge(html) == (" hidden", "0")
with zipfile.ZipFile(tmp / "apps" / "Demo.ipa", "w") as z:
    z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.me.demo", "CFBundleVersion": "8", "CFBundleShortVersionString": "1.3", "CFBundleName": "Demo"}))
os.utime(tmp / "apps" / "Demo.ipa", (time.time() + 5, time.time() + 5))
html = c.get("/").data.decode()
t_apps = apps_tab(html)
assert re.search(r'<div class="row up">.*?Demo<small>Version 1\.3<span class=upn> · Update available</span>', t_apps, re.S), "the row says so, with the new version"
assert 'data-app="Demo" aria-expanded=false onclick="steps(this)">UPDATE<' in t_apps, "UPDATE in place of GET"
assert t_apps.count('class="row up"') == 1 and badge(html) == (None, "1"), "the Apps tab's badge counts it"
assert "Update available" not in A.app.test_client().get("/?password=hunter2-but-longer", follow_redirects=True).data.decode(), "another phone, which never installed Demo, has no update"
assert c.post("/installed", data={"name": "Demo"}).status_code == 204
html = c.get("/").data.decode()
assert "Update available" not in html and badge(html) == (" hidden", "0") and ">INSTALLED<" in apps_tab(html), "installed: the update is gone"
# an update to an app that doesn't bring files: its row's link says UPDATE, and arming it still installs (data-arm keeps UPDATE)
def signed_plain(short, build):  # written as signed (the stubbed zsign always outputs Demo)
    with zipfile.ZipFile(tmp / "signed" / "Plain.ipa", "w") as z:
        z.writestr("Payload/Plain.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "com.me.plain", "CFBundleVersion": build, "CFBundleShortVersionString": short, "CFBundleName": "Plain"}))
signed_plain("1.0", "1"); assert c.post("/installed", data={"name": "Plain"}).status_code == 204
signed_plain("1.1", "2")
html = c.get("/").data.decode()
assert re.search(r'<a class="get upd" data-arm=UPDATE data-app="Plain" aria-label="Install Plain" href="itms-services://[^"]+" onclick="return arm\(this\)">UPDATE</a>', html)
assert "Plain<small>Version 1.1<span class=upn> · Update available</span>" in html and badge(html) == (None, "1")
# F24: the update row stands out: the red badge on its icon and the blue UPDATE button; an up-to-date row has neither
def app_row(h, name): return re.search(r'<div class="row[^"]*">(?:(?!<div class="row).)*?data-app="' + name + '".*?</div>', h, re.S).group(0)
up_row = app_row(apps_tab(html), "Plain")
assert up_row.startswith('<div class="row up">') and '<i class="badge ub" aria-hidden=true></i>' in up_row and 'class="get upd"' in up_row
assert apps_tab(html).count('class="badge ub"') == 1 and apps_tab(html).count(' upd"') == 1, "only the update row"
ok_row = app_row(apps_tab(html), "Demo")
assert "badge" not in ok_row and "upd" not in ok_row and 'class="get done"' in ok_row
assert ".get.upd:not(.go):not(.done):not([aria-expanded=true]){color:#fff" in html and "linear-gradient(#79a1f3,#3b71e1 49%,#215fdd 51%,#2361dd);background-origin:border-box" in html
assert ".get.upd:not(.go):not(.done):not([aria-expanded=true]).is-pressed{background:linear-gradient(#5f86d6," in html, "held, a darker blue"
assert '.querySelectorAll(".upn,.ub")' in html and 'x.classList.remove("upd")' in html, "an install tap takes the badge and the blue off"
(tmp / "signed" / "Plain.ipa").unlink()
# the page's script: the badge counts Home's update rows, and an install tap takes its row off the count
assert "querySelectorAll(\"#t-apps .row.up\").length" in html and 'r.classList.remove("up")' in html
# F27: hold an Apps row for an action sheet. Each mark lands in installed.json for this iPhone and changes the page: Plain has an update,
# Demo is installed
import json as _json
me = A.token_udid(c.get_cookie("device").value)
mk = re.search(r'<div class=mks id=mkSheet hidden data-csrf="(\w{32})"', html).group(1)
assert mk == A.mark_csrf(me) and '<p id=mkH></p><div id=mkB></div><button type=button class=mkc onclick="mkClose()">Cancel</button>' in html
mark = lambda cl, name, do, csrf=mk: cl.post("/installed/mark", data={"name": name, "do": do, "csrf": csrf}).status_code
mine_now = lambda: _json.loads(A.INSTALLED.read_text()).get(me, {})
signed_plain("1.1", "2"); assert badge(c.get("/").data.decode()) == (None, "1")
assert mark(c, "Plain", "installed") == 204 and mine_now()["Plain"] == "1.1/2", "Mark as Updated records the current version"
html = c.get("/").data.decode()
assert badge(html) == (" hidden", "0") and "Update available" not in html and 'class="badge ub"' not in apps_tab(html)
assert re.search(r'<a class="get done" data-arm=INSTALLED data-app="Plain"[^>]*>INSTALLED</a>', html), "the blue UPDATE is the grey INSTALLED"
assert mark(c, "Plain", "forget") == 204 and "Plain" not in mine_now(), "Mark as Not Installed forgets it"
html = c.get("/").data.decode()
assert re.search(r'<a class="get" data-arm=GET data-app="Plain"[^>]*>GET</a>', html) and badge(html) == (" hidden", "0")
assert mark(c, "Plain", "installed") == 204 and mine_now()["Plain"] == "1.1/2", "Mark as Installed records the current version"
assert re.search(r'<a class="get done" data-arm=INSTALLED data-app="Plain"[^>]*>INSTALLED</a>', c.get("/").data.decode())
signed_plain("1.2", "3"); html = c.get("/").data.decode()
assert badge(html) == (None, "1") and 'data-arm=UPDATE data-app="Plain"' in html, "a newer build: an update again"
assert mark(c, "Plain", "forget") == 204 and badge(c.get("/").data.decode()) == (" hidden", "0"), "forgetting an update takes it off the tab's count"
before = A.INSTALLED.read_text()
# refused: no session, no device, a bad csrf, another iPhone's csrf, an unregistered iPhone, a bad action or app
assert mark(A.app.test_client(), "Plain", "installed") == 403
guest = A.app.test_client(); guest.get("/?password=hunter2-but-longer")
assert mark(guest, "Plain", "installed") == 403, "signed in, no registered iPhone"
assert mark(c, "Plain", "installed", csrf="x" * 32) == 403 and mark(c, "Plain", "installed", csrf="") == 403
other = A.app.test_client(); other.get("/?password=hunter2-but-longer"); other.set_cookie("device", A.device_token("00008130-BBBB"))
assert mark(other, "Plain", "installed", csrf=A.mark_csrf("00008130-BBBB")) == 403, "not in the profile"
real_udids = A.profile_udids
A.profile_udids = lambda: real_udids() | {"00008130-BBBB"}
try:
    assert mark(other, "Plain", "installed") == 403, "this iPhone's csrf with another iPhone's token"
    assert mark(c, "Plain", "installed", csrf=A.mark_csrf("00008130-BBBB")) == 403, "another iPhone's csrf with this one's token"
    assert A.INSTALLED.read_text() == before
    assert mark(other, "Plain", "installed", csrf=A.mark_csrf("00008130-BBBB")) == 204 and "Plain" not in mine_now(), "the other phone marks only its own"
    other_html = other.get("/").data.decode()
    assert re.search(r'id=mkSheet hidden data-csrf="' + A.mark_csrf("00008130-BBBB") + '"', other_html)
finally:
    A.profile_udids = real_udids
before = A.INSTALLED.read_text()
assert mark(c, "Plain", "delete") == 403 and mark(c, "../x", "installed") == 403 and mark(c, "Nope", "forget") == 403 and A.INSTALLED.read_text() == before
assert "id=mkSheet" not in guest.get("/").data.decode(), "no sheet for an unregistered iPhone"
(tmp / "signed" / "Plain.ipa").unlink()
# the page's hold: half a second still, the row held (cell selection), the ending click eaten, the sheet's items by state, and a mark refreshes the lists
assert "mkTm=setTimeout(()=>{mkTm=null;mkEat=1;r.classList.add(\"held\")" in html and "},500)},true)" in html
assert "Math.hypot(e.clientX-mkXY[0],e.clientY-mkXY[1])>10)mkCancel()" in html and 'addEventListener("scroll",()=>{if(mkTm)mkCancel()}' in html
assert 'addEventListener("click",e=>{if(mkEat){mkEat=0;e.preventDefault();e.stopImmediatePropagation()}},true)' in html
assert "#t-apps .g .row.held,.dark #t-apps .g .row.held{background:var(--select)" in html and 'closest("#t-apps .g:not(.locked) .row")' in html
assert 'fetch("/installed/mark",{method:"POST",body:new URLSearchParams({name:n,do:d,csrf:mkSheet.dataset.csrf})}).then(r=>{if(!r.ok)throw 0;return refreshIn()})' in html
if shutil.which("node"):  # the sheet's items and the GET button's arming (F27 Also), in node with fake buttons
    js = "\n".join(re.search(r"^function " + f + r"\(.*$", html, re.M).group(0) for f in ("morph", "disarm", "arm", "mkState", "mkItems"))
    (tmp / "f27.js").write_text(js + """
const marked=[];function mark(b){marked.push(b.dataset.app)}function setTimeout(){}
function btn(arm,cls){let c=new Set(cls||[]);return {dataset:{arm,app:arm+"App"},textContent:arm,offsetWidth:40,style:{},classList:{contains:x=>c.has(x),add:x=>c.add(x),remove:x=>c.delete(x)}}}
const document={querySelectorAll:()=>[]};const out={};
for(const a of ["GET","INSTALLED","UPDATE"]){let b=btn(a,a=="INSTALLED"?["done"]:a=="UPDATE"?["upd"]:[]);let n=marked.length,r1=arm(b),l1=b.textContent,g1=b.classList.contains("go"),m1=marked.length-n;
 let r2=r1?null:arm(b);out[a]=[r1,l1,g1,m1,r2,marked.length-n]}
const row=(up,done)=>({classList:{contains:x=>x=="up"&&up},querySelector:s=>s==".get.done"&&done?{}:null});
out.items=[mkItems(mkState(row(true,false))),mkItems(mkState(row(false,true))),mkItems(mkState(row(false,false)))];
console.log(JSON.stringify(out))""")
    p = subprocess.Popen(["node", str(tmp / "f27.js")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # subprocess.run is zsign's stub
    out, err = p.communicate()
    assert p.returncode == 0, err
    got = _json.loads(out)
    assert got["GET"] == [False, "INSTALL", True, 0, True, 1], "GET arms as a green INSTALL, the second tap installs"
    assert got["INSTALLED"] == [False, "REINSTALL", True, 0, True, 1], "an installed app arms as a green REINSTALL"
    assert got["UPDATE"] == [True, "UPDATE", False, 1, None, 1], "UPDATE installs on its first tap, no confirm"
    assert got["items"] == [[["Mark as Updated", "installed"], ["Mark as Not Installed", "forget"]], [["Mark as Not Installed", "forget"]], [["Mark as Installed", "installed"]]]
# admin: separate password, CSRF, lockout; lists devices and disables one
plain = A.app.test_client()
assert plain.get("/admin").status_code == 302 and plain.post("/admin/device").status_code == 403
assert b"Admin password" in c.get("/admin").data and c.post("/admin/device", data={"id": "D1", "status": "DISABLED"}).status_code == 403
assert b"Wrong admin password" in c.post("/admin", data={"password": "nope"}).data
patched, devs = [], [{"id": "D1", "attributes": {"name": "Sam <b>", "udid": "00008130-AAAA", "status": "ENABLED", "addedDate": "2026-11-03T10:00:00.000+0000", "model": "iPhone 15"}}]
A.asc = lambda m, path, **kw: (patched.append((m, path, kw)), {"data": devs if m == "GET" and path == "/devices" and "filter[udid]" not in kw.get("params", {}) else []})[1]
recorder = A.asc
assert c.post("/admin", data={"password": "admin-pass-also-long"}).status_code == 302
# F10: Manage is a menu that asks Apple nothing, so it opens at once with Apple hanging or down; each row pushes its page
hang = threading.Event()
def slow_asc(*a, **k):
    hang.wait(5); raise RuntimeError("App Store Connect GET /devices: timed out")
down = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("App Store Connect GET /devices: 500"))
A.asc = slow_asc
t0 = time.monotonic(); html = c.get("/admin").data.decode()
assert time.monotonic() - t0 < 1, "Manage waited on Apple"
for p in ("iphones", "signing", "passwords", "invites", "files", "sources", "ifizbox"):
    assert f"href=/admin/{p} data-push" in html, p
assert html.count("<img class=rico src=\"data:image/svg+xml,%3Csvg") == 8 and "Files for Friends" in html and "App Sources" in html
# F26 Manage: Friends (iPhones N of 100, Invite Friends, Passwords), Signing (Certificate, Profile), Apps (App Sources, Files for Friends,
# iFizBox), each with its footer; the rows push the same pages as before
assert re.findall(r"<h3 class=hdr>(\w+)</h3>", html) == ["Friends", "Signing", "Apps"] and re.findall(r'class="g mg2" id=(m\w+)>', html) == ["mFriends", "mSigning", "mApps"]
grp = lambda g: html[html.index(f"id={g}>"):].split("<p class=ftr>")[0]
assert re.findall(r"<div>(\w[\w ]*)", grp("mFriends")) == ["iPhones", "Invite Friends", "Passwords"] and "<div>iPhones</div><span class=val>1 of 100</span>" in grp("mFriends")
assert re.findall(r"<div>(\w[\w ]*)", grp("mSigning")) == ["Certificate", "Profile"] and "<small>Ad Hoc" in grp("mSigning") and "capabilit" in grp("mSigning")
assert "<span class=val>1 iPhone</span>" in grp("mSigning") and grp("mSigning").count("href=/admin/signing data-push") == 2
assert re.findall(r"<div>(\w[\w ]*)", grp("mApps")) == ["App Sources", "Files for Friends", "iFizBox"] and "<span class=val>0</span>" in grp("mApps")
for ftr in ("Who can sign in, and the links that let a friend register one iPhone.", "Made again by itself when an iPhone registers. Apps keep their own bundle IDs and notifications.",
            "The apps on the Apps tab come from these sources, signed for every registered iPhone."):
    assert f"<p class=ftr>{ftr}</p>" in html, ftr
st = (h := c.get("/").data.decode())[h.index("id=t-settings"):]; st = st[:st.index("</section>")]  # the admin's Settings: the Manage row, second
assert re.findall(r'<div class="g[^"]*" id=(s\w+)>', st) == ["sThis", "sManage", "sTheme", "sHome", "sHelp"]
assert '<a class="row mrow" href=/admin data-push>' + str(A.row_icon("manage")) + "<div>Manage</div><span class=val>1 iPhone</span></a>" in st
assert "Only you see this" not in st and A.ROW_ICONS["manage"][0] == "#f08b1d"  # F29: no hint under the admin's group
# F29: the admin's group is titled Admin Settings (Manage, then Share pushing Invite Friends' links); Theme's group is Preferences
assert re.findall(r"<h3 class=hdr>([^<]+)</h3>", st) == ["Admin Settings", "Preferences"] and "This iPhone</h3>" not in st
assert re.findall(r"<div>(\w[\w ]*)</div>", st[st.index("id=sManage"):st.index("id=sTheme")]) == ["Manage", "Share"]
assert '<a class="row mrow" href=/admin/invites data-push id=shareRow>' + str(A.row_icon("share")) + "<div>Share</div></a>" in st
assert st.index("Admin Settings") < st.index("id=sManage") < st.index("Preferences") < st.index("id=sTheme")
assert A.tile_svg("general").startswith('<svg xmlns="http://www.w3.org/2000/svg" width="29" height="29"') and 'fill="#8c9097"' in A.tile_svg("general")
t0 = time.monotonic(); html = c.get("/admin/iphones").data.decode()  # nothing saved yet: the loading row, and the refresh's script
assert time.monotonic() - t0 < 1 and "Loading from Apple…" in html and "/admin/devices.json" in html and "No iPhones" not in html
hang.set()
A.asc = down
assert c.get("/admin").status_code == 200
j = c.get("/admin/devices.json").get_json()
assert not j["ok"] and "didn't answer" in j["html"] and "500" in j["error"]
A.asc = recorder
j = c.get("/admin/devices.json").get_json()
assert j["ok"] and j["devices"][0]["name"] == "Sam <b>" and j["devices"][0]["added"] == "2026-11-03"
assert "Sam &lt;b&gt;" in j["html"] and "this iPhone" in j["html"] and "1 of 100 slots used. Disabled iPhones still count" in j["html"]
assert "Loading from Apple" not in j["html"] and "Delete" not in j["html"] and A.load_json(A.DEVICES)["data"] == devs  # saved for next time
A.asc = down  # the saved list shows at once, Apple down or not, under a loading row that the refresh replaces
html = c.get("/admin/iphones").data.decode()
assert "Sam &lt;b&gt;" in html and "Loading from Apple…" in html and 'data-id="D1"' in html and " checked " in html
assert "<div>iPhones</div><span class=val>1 of 100</span>" in c.get("/admin").data.decode()  # the menu's count is the saved list's
html = c.get("/admin/iphone/D1").data.decode()
assert "iPhone 15" in html and "Nov 3, 2026" in html and "Last Used</div><span class=val>Today · this iPhone" in html and "00008130-AAAA" in html and "this iPhone" in html
assert "Rename" in html and b"isn't in the saved list" in c.get("/admin/iphone/NOPE").data
csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
A.asc = recorder
assert c.post("/admin/device", data={"id": "D1", "status": "DISABLED", "csrf": "x"}).status_code == 403
assert c.post("/admin/device", data={"id": "../x", "status": "DISABLED", "csrf": csrf}).status_code == 400
resign_all_real, dev_resigns = A.resign_all, []
A.resign_all = lambda: dev_resigns.append(1)
j = c.post("/admin/device", data={"id": "D1", "status": "DISABLED", "csrf": csrf, "json": "1"}).get_json()
assert j["ok"] and "Disabled</h3>" not in j["html"] and 'class="row drow off"' in j["html"] and 'data-id="D1"' in j["html"] and " checked " not in j["html"]
# F11: one list, newest first; a turned-off iPhone keeps its place, greyed with its switch off, under the same slots footer
with A.app.test_request_context():
    mix = [{"id": i, "attributes": {"name": i, "status": s, "addedDate": f"2026-11-0{n}T10:00:00.000+0000"}}
           for i, s, n in (("OLD", "ENABLED", 1), ("NEW", "ENABLED", 3), ("MID", "DISABLED", 2))]
    h = A.device_list_html(A.device_rows(mix))
assert h.count("<div class=g>") == 1 and "Disabled</h3>" not in h and "3 of 100 slots used" in h
assert h.index('data-id="NEW"') < h.index('data-id="MID"') < h.index('data-id="OLD"')
assert h.count('class="row drow off"') == 1 and h.index('class="row drow off"') < h.index('data-id="MID"') < h.index('class="row drow"><a class=dl href="/admin/iphone/OLD"')
assert ("PATCH", "/devices/D1") in [(m, p) for m, p, _ in patched] and A.load_json(A.DEVICES)["data"][0]["attributes"]["status"] == "DISABLED"
deadline = time.monotonic() + 5
while not dev_resigns and time.monotonic() < deadline: threading.Event().wait(.01)
assert dev_resigns, "turning an iPhone off makes a new profile and signs again, in the background"
assert c.post("/admin/device", data={"id": "D1", "status": "ENABLED", "csrf": csrf}).location == "/admin/iphones"  # without JS
A.asc = down
r = c.post("/admin/device", data={"id": "D1", "status": "DISABLED", "csrf": csrf, "json": "1"})
assert r.status_code == 502 and "500" in r.get_json()["error"] and A.load_json(A.DEVICES)["data"][0]["attributes"]["status"] == "ENABLED"
assert b"didn&#39;t rename" in c.post("/admin/iphone/D1", data={"csrf": csrf, "name": "x"}).data
A.asc = recorder
assert b"1 to 50 characters" in c.post("/admin/iphone/D1", data={"csrf": csrf, "name": "  "}).data
assert c.post("/admin/iphone/D1", data={"csrf": "x", "name": "y"}).status_code == 403
r = c.post("/admin/iphone/D1", data={"csrf": csrf, "name": "  Sam's   phone "})
assert r.location == "/admin/iphone/D1?done=renamed"
assert ("PATCH", "/devices/D1", {"data": {"type": "devices", "id": "D1", "attributes": {"name": "Sam's phone"}}}) in [(m, p, kw.get("json")) for m, p, kw in patched]
html = c.get(r.location).data.decode()
assert "Renamed." in html and "Sam&#39;s phone" in html and A.load_json(A.DEVICES)["data"][0]["attributes"]["name"] == "Sam's phone"
A.resign_all = resign_all_real
for p in ("/admin/iphones", "/admin/iphone/D1", "/admin/signing", "/admin/passwords", "/admin/files", "/admin/sources", "/admin/ifizbox"):
    assert plain.get(p).location == "/" and A.app.test_client().get(p).status_code == 302
assert plain.get("/admin/devices.json").status_code == 403
# passwords set in .env are changed here only after the page's confirm (F12, tested in full at the end)
assert b"Set in .env" in c.get("/admin/passwords").data and b"Confirm replacing" in c.post("/admin/passwords", data={"csrf": csrf, "password": "x" * 9}).data
assert A.password_ok("hunter2-but-longer") and not A.password_ok("x" * 9)
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
assert "push(a.href,{},a,!!L)" in html and 'L.querySelectorAll(".page script")' in html  # Manage's rows push over Manage; their scripts run
html = boss.get("/admin").data.decode()
assert "Files for Friends" in html and "Admin password" not in html
assert "iFizBox&#39;s starting sources" in boss.get("/admin/ifizbox").data.decode() and "Sources" in boss.get("/admin/sources").data.decode()
html = boss.get("/admin/signing").data.decode()
assert "Choose Signing Files" in html and "Upload cert.p12 Instead" in html and "Make New Certificate" in html and "Choose API Key" in html
csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
synced = []
A.sync_sources = lambda: synced.append(list(A.SOURCES))
repo_mirror = (Path(A.__file__).parent / "mirror-sources.txt").read_text()
r = boss.post("/admin/config", data={"csrf": csrf, "name": "mirror-sources.txt", "text": "https://src.test/a.json com.a.b\r\n"})
assert r.location == "/admin/sources?done=sources" and (tmp / "config" / "mirror-sources.txt").read_text() == "https://src.test/a.json com.a.b\n"
assert A.SOURCES == [("https://src.test/a.json", ["com.a.b"], False)] + [s for s in A.SOURCES if s[2]]
assert (Path(A.__file__).parent / "mirror-sources.txt").read_text() == repo_mirror  # the repo file is untouched
assert "src.test/a.json" in boss.get("/admin/sources").data.decode() and "Use Default" in boss.get("/admin/sources").data.decode()
assert f"<span class=val>{1 + len(A.read_sources('third-party-sources.txt'))}</span>" in boss.get("/admin").data.decode().split("App Sources")[1][:40]  # the menu counts the sources
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
assert r.location == "/admin/sources?done=default" and not (tmp / "config" / "mirror-sources.txt").exists()
assert [u for u, _, t in A.SOURCES if not t] == [u for u, _ in A.read_sources("mirror-sources.txt")]
r = boss.post("/admin/files", data={"csrf": csrf, "files": [(io.BytesIO(b"hello friends"), "notes v2.txt"), (io.BytesIO(b"x"), "../.hidden")]},
              content_type="multipart/form-data")
assert r.location == "/admin/files?done=files" and "notes v2.txt" in boss.get(r.location).data.decode() and (tmp / "files" / "notes v2.txt").read_bytes() == b"hello friends"
assert sorted(p.name for p in (tmp / "files").iterdir()) == ["hidden", "notes v2.txt"]  # no paths, no dotfiles
# F13: the page's background upload (json=1) answers JSON with the file's row; picking files is enough (no Upload button)
r = boss.post("/admin/files", data={"csrf": csrf, "json": "1", "files": [(io.BytesIO(b"big" * 1000), "disc.iso")]}, content_type="multipart/form-data")
assert r.status_code == 200 and r.json["name"] == "disc.iso" and r.json["size"] == 3000, r.data
assert 'data-file="disc.iso"' in r.json["html"] and "3.0 kB" in r.json["html"] and "DELETE" in r.json["html"] and csrf in r.json["html"]
assert (tmp / "files" / "disc.iso").read_bytes() == b"big" * 1000 and not (tmp / "files" / ".disc.iso.part").exists()
r = boss.post("/admin/files", data={"csrf": csrf, "json": "1"}, content_type="multipart/form-data")
assert r.status_code == 400 and r.json["error"], r.data
html = boss.get("/admin/files").data.decode()
assert "upAdd(this)" in html and "window.upQ" in html and "upload.onprogress" in html and 'textContent="CANCEL"' in html and "j.x.abort()" in html and "<noscript><button>Upload</button></noscript>" in html
(tmp / "files" / "disc.iso").unlink()
friend = A.app.test_client(); friend.get("/?password=hunter2-but-longer")
html = friend.get("/").data.decode()
assert "notes v2.txt" in html and "href=/admin" not in html, "a friend sees the file and not Manage"
# F14: a file brings the Files tab back (before Settings), with the file's row there and not on the Apps tab
assert re.findall(r"<a href=#(\w+)><svg", html) == ["apps", "ifizbox", "files", "settings"]
t_apps, t_files = (re.search(rf"<section class=page id=t-{t} .*?</section>", html, re.S).group(0) for t in ("apps", "files"))
assert "notes v2.txt" in t_files and "notes v2.txt" not in t_apps and "Files</h3>" not in t_apps
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
assert boss.post("/admin/files/delete", data={"csrf": csrf, "name": "hidden"}).location == "/admin/files?done=deleted" and not (tmp / "files" / "hidden").exists()
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
if A.cert_bg.get("t"): A.cert_bg["t"].join(5)  # an earlier page's background check, against the old certificate
t0 = time.monotonic(); html = boss.get("/admin").data.decode()  # Manage's banner: the local checks at once, Apple's in the background
assert time.monotonic() - t0 < 1 and "expires in 10 days" in html and '<a class="cw" href=/admin/signing data-push>' in html, html
A.cert_bg["t"].join(5)  # Apple answered: the next page has its findings too
html = boss.get("/admin").data.decode()  # the banner: the first error, and how many more Signing lists
assert '<a class="cw bad" href=/admin/signing data-push><div><p>cert.p12 isn&#39;t in your developer account' in html and "And 2 more on Signing." in html, html
html = boss.get("/admin/signing").data.decode()
assert "expires in 10 days" in html and "isn&#39;t in your developer account" in html and "The App ID com.me.* isn&#39;t" in html, html
assert html.index("isn&#39;t in your developer account") < html.index("expires in 10 days")  # errors first
assert "Apple Distribution" in html and "Sam Test (TEAM123456)" in html and "com.me.*" in html
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
# F26: no problems, so Manage's banner is the green one: the certificate's kind, the App ID, and Push when the profile has it
csc = A.cert_status_cached; A.cert_status_cached = lambda: []
A.PROFILE.write_bytes(plistlib.dumps({"DeveloperCertificates": [mine.public_bytes(S.Encoding.DER)], "ProvisionedDevices": ["a", "b"],
                                      "Entitlements": {"application-identifier": "TEAM.com.me.app", "aps-environment": "production", "com.apple.security.application-groups": []}}))
html = boss.get("/admin").data.decode()
assert '<a class="cw ok" href=/admin/signing data-push><div><p>Signing works: Apple Distribution, App ID com.me.app with Push</p>' in html, html[:3000]
assert "<small>Ad Hoc · Push · 2 capabilities</small>" in html and "<span class=val>2 iPhones</span>" in html and "<small>Apple Distribution: Sam Test (TEAM123456)</small>" in html
A.PROFILE.write_bytes(plistlib.dumps({"DeveloperCertificates": [mine.public_bytes(S.Encoding.DER)]}))
assert "Signing works: Apple Distribution, App ID com.me.app</p>" in boss.get("/admin").data.decode()  # no Push in the profile, none claimed
A.cert_status_cached = csc
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
assert r.location == "/admin/signing?done=signing" and A.P12.read_bytes() == p12_new and A.P12_PASSWORD == "new-p12-pw" and resigns == [1]
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
mf = c.get("/manifest.webmanifest").json; assert (mf["name"], mf["short_name"]) == ("SideDrop", "SideDrop") and "sideload apps" in mf["description"]
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
assert sent == [("https://push.example/1", {"title": "Update Available", "body": "Demo 1.4 is available.", "url": "/#apps"})], sent  # an Update Alert opens Home's Apps tab
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
html = fa.get("/admin/signing").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert "App ID (BUNDLE_ID)" in html and b"doesn&#39;t look right" in fa.post("/admin/signing", data={"csrf": csrf, "bundle_id": "com.me.* x"}).data
assert fa.post("/admin/signing", data={"csrf": csrf, "bundle_id": "com.me.sideload"}).status_code == 302 and F.BUNDLE_ID == "com.me.sideload"
assert "pbkdf2_sha256$" in (first / "setup.json").read_text()  # Manage's save keeps the saved passwords
# Manage → Passwords changes the saved ones (hashed), both or one
html = fa.get("/admin/passwords").data.decode()
assert "Friends' Password" in html and "Admin Password" in html and "set in .env" not in html
pw_post = lambda **f: fa.post("/admin/passwords", data=dict(f, csrf=csrf))
assert b"Type a new password" in pw_post().data and b"at least 8" in pw_post(password="short").data
assert b"different ones" in pw_post(password="admin-pass-x").data and b"different ones" in pw_post(password="same-pass-x", admin_password="same-pass-x").data
assert b"different ones" in pw_post(admin_password="sidedrop").data and fa.post("/admin/passwords", data={"password": "friends-new-pass"}).status_code == 403
assert pw_post(password="friends-new-pass").location == "/admin/passwords?done=passwords"
assert F.password_ok("friends-new-pass") and not F.password_ok("friends-pass") and F.password_ok("admin-pass-x", admin=True)
assert pw_post(password="friends-pass", admin_password="admin-new-pass").location == "/admin/passwords?done=passwords"
assert F.password_ok("friends-pass") and F.password_ok("admin-new-pass", admin=True) and not F.password_ok("admin-pass-x", admin=True)
assert "admin-new-pass" not in (first / "setup.json").read_text() and b"Saved." in fa.get("/admin/passwords?done=passwords").data
assert pw_post(admin_password="admin-pass-x").status_code == 302  # back, for the restarts below
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
        s.settings, s.refuse = {}, set()  # capabilityType: the settings it was turned on with; capabilities Apple refuses
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
            d = kw["json"]["data"]; cap = d["attributes"]["capabilityType"]
            if cap in s.refuse:
                raise RuntimeError(f'App Store Connect POST /bundleIdCapabilities: 409 {{"errors":[{{"detail":"no {cap}"}}]}}')
            s.caps.append((d["relationships"]["bundleId"]["data"]["id"], cap)); s.settings[cap] = d["attributes"].get("settings"); return {"data": d}
        if method == "GET" and path.endswith("/bundleIdCapabilities"):
            if kw.get("params"):  # Apple answers a limit here with a 400
                raise RuntimeError(f"App Store Connect GET {path}: 400 PARAMETER_ERROR.INVALID limit")
            return {"data": [{"attributes": {"capabilityType": c}} for b, c in s.caps if b == path.split("/")[2]]}
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
assert "Choose API Key" in html and "Manual setup" in html and "openssl req -new" in html and "Choose Signing Files" in html
key_only = lambda **f: g.post("/setup", data=dict({"password": "friends-pass", "admin_password": "admin-pass-x", "bundle_id": "com.me.sideload",
    "asc_issuer_id": "69a6de7e-1111-47e3-e053-5b8c7c11a4d1"}, **f, files=[(io.BytesIO(p8), "AuthKey_KEYID12345.p8")]), content_type="multipart/form-data")
apple.forbid = True  # an App Manager key: Apple refuses the certificate, and the error says which role it needs
r = key_only()
assert b"Admin role" in r.data and not (tmp / "apikey" / "cert.p12").exists() and G.needs_setup()
assert [b["attributes"] for b in apple.bundles.values()] == [{"identifier": "com.me.sideload", "name": "SideDrop", "platform": "IOS"}]
ALL_CAPS = ["PUSH_NOTIFICATIONS", "APP_GROUPS", "ASSOCIATED_DOMAINS", "ICLOUD", "GAME_CENTER", "HEALTHKIT", "HOMEKIT", "SIRIKIT",
            "NETWORK_EXTENSIONS", "PERSONAL_VPN", "MULTIPATH", "HOT_SPOT", "NFC_TAG_READING", "CLASSKIT", "AUTOFILL_CREDENTIAL_PROVIDER",
            "ACCESS_WIFI_INFORMATION", "COREMEDIA_HLS_LOW_LATENCY", "APPLE_ID_AUTH", "WALLET", "IN_APP_PURCHASE", "INTER_APP_AUDIO",
            "WIRELESS_ACCESSORY_CONFIGURATION", "DATA_PROTECTION", "MAPS", "APPLE_PAY"]  # the 25 Apple's API took on a real team
assert apple.caps == [("B0", c) for c in ALL_CAPS], apple.caps
assert apple.settings["ICLOUD"] == [{"key": "ICLOUD_VERSION", "options": [{"key": "XCODE_6", "enabled": True}]}]
assert apple.settings["APPLE_ID_AUTH"] == [{"key": "APPLE_ID_AUTH_APP_CONSENT", "options": [{"key": "PRIMARY_APP_CONSENT", "enabled": True}]}]
assert apple.settings["DATA_PROTECTION"] == [{"key": "DATA_PROTECTION_PERMISSION_LEVEL", "options": [{"key": "COMPLETE_PROTECTION", "enabled": True}]}]
assert apple.settings["PUSH_NOTIFICATIONS"] is None
apple.forbid = False
r = key_only()
assert r.location == "/" and not G.needs_setup(), re.findall(rb"class=err>[^<]*", r.data)
made_p12 = (tmp / "apikey" / "cert.p12").read_bytes()
assert G.cert_problems(made_p12, G.P12_PASSWORD) == [] and len(G.P12_PASSWORD) >= 20  # signs: our key, Apple's Distribution cert
assert G.load_json(G.SETUP)["p12_password"] == G.P12_PASSWORD and os.environ["ASC_KEY_ID"] == "KEYID12345"
assert len(apple.bundles) == 1 and len(apple.caps) == 25 and len(apple.certs) == 1  # the App ID made once, not again on the retry
assert [m for m, p, _ in apple.calls].count("DELETE") == 0
assert G.ensure_app_id("com.me.*") and len(apple.caps) == 25 and not G.ensure_app_id("com.me.*")  # a wildcard gets no capabilities
# an App ID that already exists (made by hand, with Push and App Groups) gets the ones it lacks; one Apple refuses is skipped
apple.bundles["BX"] = {"type": "bundleIds", "id": "BX", "attributes": {"identifier": "com.me.hand"}}
apple.caps += [("BX", "PUSH_NOTIFICATIONS"), ("BX", "APP_GROUPS")]
apple.refuse = {"HEALTHKIT"}
assert G.ensure_app_id("com.me.hand") and [c for b, c in apple.caps if b == "BX"] == ["PUSH_NOTIFICATIONS", "APP_GROUPS"] + [
    c for c in ALL_CAPS if c not in ("PUSH_NOTIFICATIONS", "APP_GROUPS", "HEALTHKIT")]
n = len(apple.caps); apple.refuse = set()
assert G.ensure_app_id("com.me.hand") and apple.caps[n:] == [("BX", "HEALTHKIT")]  # tried again next time
assert not G.ensure_app_id("com.me.hand") and len(apple.caps) == n + 1  # nothing missing: the profile needn't change
apple.bundles["BY"] = {"type": "bundleIds", "id": "BY", "attributes": {"identifier": "com.me.nopush"}}
apple.refuse = {"PUSH_NOTIFICATIONS"}
try:
    G.ensure_app_id("com.me.nopush"); raise AssertionError("Push refused, yet no error")
except RuntimeError as e:
    assert "PUSH_NOTIFICATIONS" in str(e)
apple.refuse = set(); del apple.bundles["BX"], apple.bundles["BY"]
# at start: a profile made for another certificate or App ID, or an App ID that just got capabilities, is made again and every
# app signed again; a profile that fits is left alone
regens, resign_all0, gprof0 = [], G.resign_all, G.PROFILE.read_bytes() if G.PROFILE.exists() else None
G.resign_all = lambda: regens.append(1)
_, gcert, _ = P12x.load_key_and_certificates(made_p12, G.P12_PASSWORD.encode())
gprof = lambda der, appid: G.PROFILE.write_bytes(b"\x30junk" + plistlib.dumps({"DeveloperCertificates": [der], "Entitlements": {
    "application-identifier": appid, "com.apple.developer.team-identifier": "TEAM"}}) + b"\x00")
gprof(gcert.public_bytes(S.Encoding.DER), "TEAM.com.me.sideload")
assert G.BUNDLE_ID == "com.me.sideload" and G.profile_stale() is None
G.heal_signing(); assert regens == []
gprof(dcrt.public_bytes(S.Encoding.DER), "TEAM.com.me.sideload")
assert "another certificate" in G.profile_stale(); G.heal_signing(); assert regens == [1]
gprof(gcert.public_bytes(S.Encoding.DER), "TEAM.com.me.*")
assert "com.me.*" in G.profile_stale(); G.heal_signing(); assert regens == [1, 1]
gprof(gcert.public_bytes(S.Encoding.DER), "TEAM.com.me.sideload")
apple.caps.remove(("B0", "MAPS"))  # a capability added to the list since the profile was made
G.heal_signing(); assert regens == [1, 1, 1] and ("B0", "MAPS") in apple.caps
G.heal_signing(); assert regens == [1, 1, 1]
G.PROFILE.unlink(); G.heal_signing(); assert regens == [1, 1, 1]  # no profile yet: the first registration makes it
G.resign_all = resign_all0
if gprof0 is not None: G.PROFILE.write_bytes(gprof0)
# Manage: Make New Certificate with the account full lists the certificates and revokes nothing; the pick is revoked, then a new one made
apple.add_cert(dist_cert("Apple Distribution: Old Mac (TEAM123456)"), "Old Mac"); apple.add_cert(dist_cert(days=40), "Elsewhere")
ga = G.app.test_client(); assert ga.get("/?password=admin-pass-x").location == "/"
html = ga.get("/admin/signing").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert "Make New Certificate" in html and "Choose API Key" in html and "Upload cert.p12 Instead" in html and "AuthKey_KEYID12345.p8" in html
assert re.search(r"Role</div><span class=val>Admin<", html), "the key made a certificate at setup: Admin"
r = ga.post("/admin/signing", data={"csrf": csrf, "make": "1"}).data.decode()
assert "as many Apple Distribution certificates" in r and "stop opening" in r and r.count('name=revoke value=') == 3
assert "Old Mac" in r and "Elsewhere" in r and r.count("SideDrop's certificate") == 1 and "expires" in r and "made " in r
assert [m for m, p, _ in apple.calls].count("DELETE") == 0 and (tmp / "apikey" / "cert.p12").read_bytes() == made_p12
assert "isn&#39;t in your account" in ga.post("/admin/signing", data={"csrf": csrf, "make": "1", "revoke": "nope"}).data.decode()
old = next(i for i, c in apple.certs.items() if c["attributes"]["name"] == "Old Mac")
r = ga.post("/admin/signing", data={"csrf": csrf, "make": "1", "revoke": old})
assert r.location == "/admin/signing?done=signing" and [p for m, p, _ in apple.calls if m == "DELETE"] == [f"/certificates/{old}"]
assert old not in apple.certs and len(apple.certs) == 3 and (tmp / "apikey" / "cert.p12").read_bytes() != made_p12
assert G.cert_problems((tmp / "apikey" / "cert.p12").read_bytes(), G.P12_PASSWORD) == [] and len(apple.bundles) == 2  # App ID kept
# the manual path still takes an uploaded cert.p12 on Manage, and asks Apple for nothing
before = len(apple.calls)
r = ga.post("/admin/signing", data={"csrf": csrf, "p12_password": "p12-secret", "files": [(io.BytesIO(p12), "cert.p12")]}, content_type="multipart/form-data")
assert r.location == "/admin/signing?done=signing" and (tmp / "apikey" / "cert.p12").read_bytes() == p12 and G.P12_PASSWORD == "p12-secret"
assert all(m == "GET" for m, _, _ in apple.calls[before:])
assert ga.post("/admin/signing", data={"csrf": csrf, "bundle_id": "com.me.other"}).location == "/admin/signing?done=signing"  # a new App ID is made
assert [b["attributes"]["identifier"] for b in apple.bundles.values()] == ["com.me.sideload", "com.me.*", "com.me.other"]

# F12: Manage changes a password .env sets: an override in setup.json that signs out the old password's sessions (not the admin
# making it), that .env wins over again once .env holds a different value, and that 'Use .env Password' drops
envd = tmp / "f12"; envd.mkdir()
ENV12 = dict(PASSWORD="env-friends-pass", ADMIN_PASSWORD="env-admin-pass", SECRET_KEY="f" * 32)
J = boot(envd, **ENV12)
friend, boss, other = J.app.test_client(), J.app.test_client(), J.app.test_client()
assert friend.post("/login", data={"password": "env-friends-pass"}).location == "/" and b"Register iPhone" in friend.get("/").data
assert boss.get("/?password=env-admin-pass").location == "/" and other.get("/?password=env-admin-pass").location == "/"
html = boss.get("/admin/passwords").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert html.count("Set in .env") == 2 and "name=password " in html and "name=admin_password " in html and "data-env=1" in html
assert "Change the Password?" in html and "This replaces the password from .env" in html and "Use .env Password" not in html
assert "Sign Out Everyone" in html and "Keep Signed In" in html and "window.confirm" not in html and "activeElement.blur()" in html  # keyboard down first
p12post = lambda cl, **f: cl.post("/admin/passwords", data=dict(f, csrf=csrf))
assert b"Confirm replacing" in p12post(boss, password="new-friends-pass").data and J.password_ok("env-friends-pass")  # no confirm: nothing changes
assert b"different ones" in p12post(boss, password="env-admin-pass", replace_env="1").data
assert p12post(boss, password="new-friends-pass", replace_env="1", signout="1").location == "/admin/passwords?done=passwords"
saved = (envd / "setup.json").read_text()
assert "new-friends-pass" not in saved and "env-friends-pass" not in saved and "password_override" in saved
assert "err=1" in J.app.test_client().post("/login", data={"password": "env-friends-pass"}).location  # old one refused
assert "err=1" in J.app.test_client().get("/?password=env-friends-pass").location  # and old links
assert J.app.test_client().post("/login", data={"password": "new-friends-pass"}).location == "/"  # new one works
assert b"Register iPhone" not in friend.get("/").data and friend.post("/check").status_code == 403  # the friend signed in with the old one is out
assert b"Changed here, over the one in .env" in boss.get("/admin/passwords").data  # the admin stays in
html = boss.get("/admin/passwords").data.decode()
assert html.count("Use .env Password") == 1 and "Use the .env Password?" in html
# the admin password too: other admin iPhones are signed out, the one making the change stays
assert p12post(boss, admin_password="new-admin-pass", replace_env="1", signout="1").location == "/admin/passwords?done=passwords"
assert boss.get("/admin/passwords").status_code == 200 and other.get("/admin/passwords").location == "/"
assert J.password_ok("new-admin-pass", admin=True) and not J.password_ok("env-admin-pass", admin=True)
# a restart with the same .env keeps the overrides
J2 = boot(envd, **ENV12)
assert J2.password_ok("new-friends-pass") and not J2.password_ok("env-friends-pass") and J2.password_ok("new-admin-pass", admin=True)
# 'Use .env Password' drops the friends' override: .env's works again, sessions made with the override are signed out
friend = J2.app.test_client(); boss = J2.app.test_client()
assert friend.post("/login", data={"password": "new-friends-pass"}).location == "/" and boss.get("/?password=new-admin-pass").location == "/"
html = boss.get("/admin/passwords").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert boss.post("/admin/passwords", data={"csrf": csrf, "use_env": "PASSWORD", "signout": "1"}).location == "/admin/passwords?done=env"
assert J2.password_ok("env-friends-pass") and not J2.password_ok("new-friends-pass") and J2.password_ok("new-admin-pass", admin=True)
assert b"Register iPhone" not in friend.get("/").data and b"works again" in boss.get("/admin/passwords?done=env").data
# .env edited to a different admin password: .env wins and the override is dropped
J3 = boot(envd, PASSWORD="env-friends-pass", ADMIN_PASSWORD="edited-admin-pass", SECRET_KEY="f" * 32)
assert J3.password_ok("edited-admin-pass", admin=True) and not J3.password_ok("new-admin-pass", admin=True)
assert "password_override" not in (envd / "setup.json").read_text() and J3.password_ok("env-friends-pass")
# Keep Signed In: the password changes, but iPhones signed in with the old one stay signed in (as before F12)
friend, boss = J3.app.test_client(), J3.app.test_client()
assert friend.post("/login", data={"password": "env-friends-pass"}).location == "/" and boss.get("/?password=edited-admin-pass").location == "/"
html = boss.get("/admin/passwords").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert boss.post("/admin/passwords", data={"csrf": csrf, "password": "kept-friends-pass", "replace_env": "1", "signout": "0"}).location == "/admin/passwords?done=passwords"
assert J3.password_ok("kept-friends-pass") and not J3.password_ok("env-friends-pass")
assert b"Register iPhone" in friend.get("/").data, "Keep Signed In kept the friend signed in"
assert "err=1" in J3.app.test_client().post("/login", data={"password": "env-friends-pass"}).location  # but the old one no longer signs in
# the iPhones page loads in the bottom reload bar, not a row that pushes the list down
html = boss.get("/admin/iphones").data.decode()
assert 'getElementById("rbarT")' in html and 'class="row load"' not in html
# an upload the server can't write shows an error on the page, not a 500
fd = envd / "files"; fd.mkdir(exist_ok=True); fd.chmod(0o500)
r = boss.post("/admin/files", data={"csrf": csrf, "files": [(io.BytesIO(b"x"), "a.txt")]}, content_type="multipart/form-data")
rj = boss.post("/admin/files", data={"csrf": csrf, "json": "1", "files": [(io.BytesIO(b"x"), "a.txt")]}, content_type="multipart/form-data")
fd.chmod(0o700)
assert r.status_code == 200 and b"can&#39;t write to the data folder" in r.data, r.status_code
assert rj.status_code == 500 and "can't write to the data folder" in rj.json["error"], rj.data  # F13: the upload row shows it, with Retry
# the manual certificate steps are on the page, not a link out
html = boss.get("/admin/signing").data.decode()
assert "openssl pkcs12 -export" in html and "Apple Distribution" in html and "docs/developer-account.md" not in html

# F16 invite links: 'Anyone with the link' signs in like the friends' password; 'One iPhone' invites register exactly one iPhone
idir = tmp / "invites"; (idir / "apps").mkdir(parents=True)
I = boot(idir, PASSWORD="friends-pass-16", ADMIN_PASSWORD="admin-pass-16", SECRET_KEY="i" * 32)
iudids = []
I.asc = lambda m, path, **kw: (m == "POST" and iudids.append(kw["json"]["data"]["attributes"]["udid"]), {"data": []})[1]
I.regen_profile = lambda: I.PROFILE.write_bytes(plistlib.dumps({"ProvisionedDevices": iudids}))
boss = I.app.test_client(); assert boss.get("/?password=admin-pass-16").location == "/"
assert "href=/admin/invites" in boss.get("/admin").data.decode()
html = boss.get("/admin/invites").data.decode(); csrf = re.search(r'name=csrf value="([^"]+)"', html).group(1)
assert "friends-pass-16" not in html and "Copy Link" in html and "navigator.clipboard.writeText" in html and "navigator.share" in html
join_link = lambda: re.search(r'data-link="https://x.test(/join/[0-9a-f]{32})"', boss.get("/admin/invites").data.decode()).group(1)
inv = lambda **f: boss.post("/admin/invites", data=dict(f, csrf=csrf))
signed_in = lambda cl: (lambda r: r.status_code == 200 and b"action=/login" not in r.data)(cl.get("/"))
# the anyone link signs in as a friend; a made-up one refuses
anyone, j = I.app.test_client(), join_link()
assert anyone.get(j).location == "/?go=setup" and b"Register iPhone" in anyone.get("/").data
assert I.app.test_client().get("/join/" + "0" * 32).status_code == 403 and I.app.test_client().get("/join/x").status_code == 403
# Make New Link: the old link stops, sessions made with it stay; the new one works
assert inv(do="rotate").location == "/admin/invites?done=newlink"
assert I.app.test_client().get(j).status_code == 403 and signed_in(anyone)
j = join_link(); assert I.app.test_client().get(j).location == "/?go=setup"
# changing the friends' password with Sign Out Everyone kills the link too
assert boss.post("/admin/passwords", data={"csrf": csrf, "password": "friends-pass-17", "replace_env": "1", "signout": "1"}).location == "/admin/passwords?done=passwords"
assert I.app.test_client().get(j).status_code == 403 and not signed_in(anyone)
assert I.app.test_client().get(join_link()).location == "/?go=setup"
# a one-iPhone invite: the guest it signs in can register; Manage is 403 to them
tok = re.search(r"new=([\w-]+)$", inv(do="new", name="Sam <x>").location).group(1)
html = boss.get(f"/admin/invites?new={tok}").data.decode()
assert f'data-link="https://x.test/invite/{tok}"' in html and "New link for Sam x" in html and "Not used" in html
guest, early = I.app.test_client(), I.app.test_client()
assert guest.get(f"/invite/{tok}").location == "/?go=setup" and b"Register iPhone" in guest.get("/").data
assert b'placeholder="Your name"' not in guest.get("/").data  # a named invite skips the name step
# F31: the link is a guest's access: no password field anywhere on their pages, and no Sign Out (nothing to sign back in with)
gh = guest.get("/").data
assert b"type=password" not in gh and b"action=/login" not in gh and b"href=/logout>Sign Out" not in gh
fr = I.app.test_client(); fr.get(join_link()); assert b"href=/logout>Sign Out" in fr.get("/").data  # friends keep Sign Out
assert b"href=/logout>Sign Out" in boss.get("/").data
gp = enroll(guest, name="Someone Else")
assert b"/udid/Sam%20x/g/" in gp and b"Someone" not in gp, "registered under the invite's name, not the form's"
assert early.get(f"/invite/{tok}").location == "/?go=setup" and signed_in(early)  # someone else opening the shared link before it's used
for p in ("/admin", "/admin/invites", "/admin/passwords", "/admin/iphones", "/admin/devices.json", "/admin/files"):
    assert guest.get(p).status_code == 403, p
assert guest.post("/admin/invites", data={"do": "new"}).status_code == 403 and guest.post("/admin", data={"password": "admin-pass-16"}).status_code == 403
assert boss.get(f"/invite/{tok}").location == "/?go=setup" and boss.get("/admin/invites").status_code == 200  # the admin trying it stays admin
# the first UDID through it uses it up; a second UDID is refused, the same one again is fine
iurl = plistlib.loads(enroll(guest, name=""))["PayloadContent"]["URL"]
assert "/udid/Sam%20x/g/" + tok + "/" in iurl, iurl
ipost = lambda udid: I.app.test_client().post(path_qs(iurl), data=b"\x30\x80" + plistlib.dumps({"UDID": udid, "PRODUCT": "iPhone14,2"}) + b"\x00")
r = ipost("GUEST-1"); assert r.status_code == 301 and r.location.endswith("/?enrolled=" + I.device_token("GUEST-1")) and iudids == ["GUEST-1"]
r = ipost("GUEST-2"); assert r.status_code == 301 and r.location == f"https://x.test/invite/{tok}" and iudids == ["GUEST-1"]
try:
    I.register("GUEST-3", "x", invite=(tok, "")); raise AssertionError("second UDID registered")
except I.InviteRefused as e:
    assert str(e) == I.INVITE_USED == "This invite already registered an iPhone. Ask for a new one."
assert ipost("GUEST-1").status_code == 301 and I.profile_udids() == {"GUEST-1"}
assert "Used by Sam x iPhone14,2 on" in boss.get("/admin/invites").data.decode()
# after use: the session that registered stays in (the Home Screen app copies its cookies), other sessions are out, the link
# opens again only with that iPhone's device cookie
assert signed_in(guest) and not signed_in(early)
r = I.app.test_client().get(f"/invite/{tok}"); assert r.status_code == 403 and I.INVITE_USED.encode() in r.data
hs = I.app.test_client(); hs.set_cookie("device", I.device_token("GUEST-1"))
assert hs.get(f"/invite/{tok}").location == "/?go=setup" and signed_in(hs)
other = I.app.test_client(); other.set_cookie("device", I.device_token("GUEST-2"))
assert other.get(f"/invite/{tok}").status_code == 403
# F31: the registered iPhone with no session (a Home Screen app that lost it) is signed back in by its device cookie, no password;
# a stale guest session (someone else's, after the link was used) is told why, not shown a password form
lost = I.app.test_client(); lost.set_cookie("device", I.device_token("GUEST-1"))
assert lost.get("/").location == "/" and signed_in(lost) and b"type=password" not in lost.get("/").data
r = early.get("/"); assert r.status_code == 403 and I.INVITE_USED.encode() in r.data and b"type=password" not in r.data and b"href=/logout" in r.data
assert b"action=/login" in early.get("/logout", follow_redirects=True).data  # its way to the password form, if it has one
assert not signed_in(other) and b"action=/login" in other.get("/").data  # an iPhone no invite registered: the password form as before
assert b"open it again: it signs you in with no password" in other.get("/").data
# expired: refused, sessions from it out, its profile can't register
etok = re.search(r"new=([\w-]+)$", inv(do="new").location).group(1)
eg = I.app.test_client(); assert eg.get(f"/invite/{etok}").location == "/?go=setup"
eurl = plistlib.loads(enroll(eg))["PayloadContent"]["URL"]
invs = I.load_invites(); invs[etok]["exp"] = time.time() - 1; I.save_json(I.INVITES, invs)
assert not signed_in(eg) and b"expired" in I.app.test_client().get(f"/invite/{etok}").data and I.app.test_client().get(f"/invite/{etok}").status_code == 403
assert I.app.test_client().post(path_qs(eurl), data=plistlib.dumps({"UDID": "GUEST-E"})).location == f"https://x.test/invite/{etok}" and "GUEST-E" not in iudids
assert "Expired" in boss.get("/admin/invites").data.decode()
# revoked: refused and its guest signed out; revoking the used one leaves its iPhone registered
rtok = re.search(r"new=([\w-]+)$", inv(do="new", name="Kim").location).group(1)
rg = I.app.test_client(); assert rg.get(f"/invite/{rtok}").location == "/?go=setup"
assert inv(do="revoke", tok=rtok).location == "/admin/invites?done=revoked"
assert not signed_in(rg) and I.app.test_client().get(f"/invite/{rtok}").status_code == 403 and "Kim" not in boss.get("/admin/invites").data.decode()
inv(do="revoke", tok=tok)
assert not signed_in(guest) and not signed_in(hs) and I.profile_udids() == {"GUEST-1"}
gone = I.app.test_client(); gone.set_cookie("device", I.device_token("GUEST-1"))
assert not signed_in(gone)  # F31: a revoked invite's device cookie signs nobody in
# F30: every setup or invite link, opened in a fresh browser, lands on the setup steps unfolded at step 1 (Stolen Device Protection),
# not on Home with them folded; plain / keeps them folded, a registered iPhone has none, the admin's own ?password= link stays on /
setup_open = lambda h: '<div id=setup>' in h and 'id=setupT aria-expanded=true' in h and h.index('id=sdp open') < h.index('id=reg>')
ftok = re.search(r"new=([\w-]+)$", inv(do="new", name="Lee").location).group(1)
for link in (join_link(), f"/invite/{ftok}", "/?password=friends-pass-17"):
    fresh = I.app.test_client(); r = fresh.get(link, follow_redirects=True)
    assert r.status_code == 200 and r.request.path == "/" and r.request.args.get("go") == "setup" and setup_open(r.data.decode()), link
    assert not setup_open(fresh.get("/").data.decode()) and "<div id=setup hidden>" in fresh.get("/").data.decode(), link
    assert 'history.replaceState(history.state,"","/"+location.hash)' in r.data.decode()  # the page drops ?go=setup from the address bar
assert I.app.test_client().get("/?password=admin-pass-16").location == "/"
reg1 = I.app.test_client(); reg1.set_cookie("device", I.device_token("GUEST-1")); reg1.get("/?password=friends-pass-17")
h = reg1.get("/?go=setup").data.decode(); assert "id=setup" not in h and "Registered" in h  # already registered: nothing to set up
# B1: a cert.p12 with an RC2-40 certificate bag (Keychain exports) opens in Python but not in the image's zsign: it's saved again as
# 3DES with the same key, certificate and password, the original kept as cert.p12.bak; on upload and at start
import shutil, subprocess as SP
real_run = lambda cmd: SP.Popen(cmd, stdout=SP.DEVNULL, stderr=SP.DEVNULL).wait()  # subprocess.run is zsign's stub here
RC2_OID, TDES_OID = bytes.fromhex("060a2a864886f70d010c0106"), bytes.fromhex("060a2a864886f70d010c0103")
rc2dir = tmp / "rc2src"; rc2dir.mkdir()
if shutil.which("openssl"):
    (rc2dir / "key.pem").write_bytes(k.private_bytes(S.Encoding.PEM, S.PrivateFormat.PKCS8, S.NoEncryption()))
    (rc2dir / "cert.pem").write_bytes(dcrt.public_bytes(S.Encoding.PEM))
    assert real_run(["openssl", "pkcs12", "-export", "-legacy", "-certpbe", "PBE-SHA1-RC2-40", "-inkey", str(rc2dir / "key.pem"), "-in",
                     str(rc2dir / "cert.pem"), "-passout", "pass:rc2-secret", "-out", str(rc2dir / "cert.p12")]) == 0
    rc2_pw = "rc2-secret"
else:  # fixtures/rc2-legacy.p12: the same openssl command, its own key and an "Apple Distribution" certificate to 2126
    shutil.copy(Path(__file__).with_name("fixtures") / "rc2-legacy.p12", rc2dir / "cert.p12"); rc2_pw = "fixture-pw"
rc2 = (rc2dir / "cert.p12").read_bytes()
assert RC2_OID in rc2 and A.p12_opens(rc2, rc2_pw) and A.p12_repacked(p12_of(dcrt), "pw") is None  # AES (cryptography's) is left alone
def repacked_ok(path, pw):
    blob = path.read_bytes()
    assert RC2_OID not in blob and TDES_OID in blob and (path.parent / "cert.p12.bak").read_bytes() == rc2
    (k1, c1, _), (k2, c2, _) = (P12x.load_key_and_certificates(b, pw.encode()) for b in (rc2, blob))
    assert c1 == c2 and k1.private_numbers() == k2.private_numbers()
    if shutil.which("openssl"):  # what zsign's OpenSSL does: no legacy provider, so RC2 fails and 3DES opens
        no_legacy = lambda p: real_run(["openssl", "pkcs12", "-in", str(p), "-noout", "-passin", f"pass:{pw}"])
        assert no_legacy(path) == 0 and no_legacy(path.parent / "cert.p12.bak") != 0
rc2up = tmp / "rc2up"
R = boot(rc2up)
rw = R.app.test_client(); rw.post("/login", data={"password": "sidedrop"})
rw.post("/setup", data={"p12_password": rc2_pw, "files": [(io.BytesIO(rc2), "cert.p12")]}, content_type="multipart/form-data")
assert R.P12_PASSWORD == rc2_pw; repacked_ok(rc2up / "cert.p12", rc2_pw)
rc2start = tmp / "rc2start"; rc2start.mkdir(); (rc2start / "cert.p12").write_bytes(rc2)  # saved before B1, or copied in by hand
R2 = boot(rc2start, P12_PASSWORD=rc2_pw)
R2.heal_signing(); repacked_ok(rc2start / "cert.p12", rc2_pw)
again = (rc2start / "cert.p12").read_bytes(); R2.heal_signing(); assert (rc2start / "cert.p12").read_bytes() == again  # once only
os.environ.pop("P12_PASSWORD")
print("ok")
