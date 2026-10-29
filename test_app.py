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

# enrollment profile points at a signed /udid URL
prof = plistlib.loads(c.post("/enroll", data={"name": "Sam <script>"}).data)
url = prof["PayloadContent"]["URL"]
assert "/udid/Sam%20script?" in url, url

# iOS posts a CMS-signed plist; we register + regen + sign, then 301 back
body = b"\x30\x80" + plistlib.dumps({"UDID": "00008130-AAAA", "PRODUCT": "iPhone16,1"}) + b"\x00sig"
r = A.app.test_client().post(path_qs(url), data=body)  # no cookie, like iOS
assert r.status_code == 301 and r.location.endswith("/?enrolled=1")
assert calls == [("00008130-AAAA", "Sam script iPhone16,1")]
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
print("ok")
