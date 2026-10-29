"""Run: python test_app.py  (no network; App Store Connect and zsign are stubbed)."""
import os, plistlib, re, tempfile, zipfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

tmp = Path(tempfile.mkdtemp())
os.environ.update(DATA=str(tmp), PASSWORD="hunter2-but-longer", PUBLIC_URL="https://x.test", SECRET_KEY="k" * 32,
                  BUNDLE_ID="com.me.*")
import app as A

(tmp / "apps").mkdir(); (tmp / "files").mkdir()
(tmp / "files" / "big.bin").write_bytes(b"0123456789")
with zipfile.ZipFile(tmp / "apps" / "Demo.ipa", "w") as z:
    z.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(
        {"CFBundleIdentifier": "com.me.demo", "CFBundleVersion": "7", "CFBundleName": "Demo"}, fmt=plistlib.FMT_BINARY))

calls = []
def fake_regen():
    # real profiles are CMS-wrapped plists; junk bytes around it exercise embedded_plist
    A.PROFILE.write_bytes(b"\x30\x82junk" + plistlib.dumps({"ProvisionedDevices": [u for u, _ in calls]}) + b"\x00tail")
def fake_asc(method, path, **kw):
    return {"data": []}
def fake_run(cmd, **kw):
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
assert r.status_code == 301 and r.location.endswith("/?enrolled=1")
assert calls == [("00008130-AAAA", "Sam script iPhone16,1")]
# landing back in Safari marks this browser as registered and hides the form behind <details>
assert b"Register this iPhone" in c.get("/").data
html = c.get("/?enrolled=1").data
assert b"This iPhone is registered" in html and b"<details>" in html and b"This iPhone is registered" in c.get("/").data
assert A.profile_udids() == {"00008130-AAAA"} and (tmp / "signed" / "Demo.ipa").exists()

# tampered / expired signatures are refused
assert A.app.test_client().post(path_qs(url).replace("Sam", "Eve"), data=body).status_code == 403
assert A.app.test_client().get("/f/big.bin?e=1&s=x").status_code == 403

# install page -> manifest -> ipa, all cookie-less
html = c.get("/").data.decode()
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
        return Resp({"apps": [{"bundleIdentifier": "io.x.tennis", "versions": [{"version": "1.5", "downloadURL": "https://gh/t.ipa"}]}]})
    return Resp((tmp / "apps" / "Demo.ipa").read_bytes())
A.requests.get, A.SOURCES = fake_get, ["https://src/source.json"]
A.sync_sources(); A.sync_sources()
assert (tmp / "apps" / "io.x.tennis.ipa").read_bytes() == (tmp / "apps" / "Demo.ipa").read_bytes()
assert gets.count("https://gh/t.ipa") == 1
# page loads check the source, throttled to once a minute
n = gets.count("https://src/source.json"); A.last_sync[0] = 0
c.get("/"); c.get("/")
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
print("ok")
