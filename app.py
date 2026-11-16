"""sidedrop: password-gated UDID enrollment, ad hoc OTA installs and private file downloads."""
import base64, hashlib, hmac, os, plistlib, re, subprocess, threading, time, uuid, zipfile, zlib
from pathlib import Path
from urllib.parse import quote

import jwt, requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from flask import Flask, abort, make_response, redirect, render_template_string, request, send_from_directory, session, url_for

DATA = Path(os.environ.get("DATA", "/data"))
APPS, SIGNED, FILES = DATA / "apps", DATA / "signed", DATA / "files"
APP_FILES = DATA / "appfiles"  # appfiles/<ipa name>/* are listed under that app's Install button, not in Files
CUSTOM = SIGNED / "custom"  # one-off IPAs friends upload or link on the page
HERE = Path(__file__).parent  # config files edited on GitHub; the NAS pulls and rebuilds (deploy.sh)
read_urls = lambda f: [u for u in (HERE / f).read_text().split() if u.startswith(("https://", "http://"))] if (HERE / f).exists() else []
FEATHER_REPO = "https://github.com/claration/Feather"
PROFILE = DATA / "adhoc.mobileprovision"
P12, ASC_KEY = DATA / "cert.p12", DATA / "asc.p8"
PASSWORD = os.environ["PASSWORD"]
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")  # must be https with a real cert, iOS refuses otherwise
SECRET = os.environ["SECRET_KEY"].encode()
P12_PASSWORD = os.environ.get("P12_PASSWORD", "")
BUNDLE_ID = os.environ.get("BUNDLE_ID", "")  # wildcard like com.you.*; apps outside it get re-IDed to fit
PROFILE_NAME = os.environ.get("PROFILE_NAME", "sidedrop adhoc")
LINK_TTL = int(os.environ.get("LINK_TTL", 7 * 86400))
# AltStore sources to mirror into apps/: one per line, a URL then optionally the bundle IDs to take (else all its apps);
# third-party-sources.txt's apps are listed under "Third-party apps"
read_sources = lambda f: [(l.split()[0], l.split()[1:]) for l in (HERE / f).read_text().splitlines()
                          if l.startswith(("https://", "http://"))] if (HERE / f).exists() else []
SOURCES = [(u, ids, False) for u, ids in read_sources("mirror-sources.txt")] + \
          [(u, ids, True) for u, ids in read_sources("third-party-sources.txt")]
SYNC_TOKEN = os.environ.get("SYNC_TOKEN", "")  # lets CI hit POST /sync after a release
PROFILE_CERT_DIR = os.environ.get("PROFILE_CERT_DIR", "")  # dir with fullchain.pem + privkey.pem; iOS then shows "Verified"

app = Flask(__name__)
app.jinja_env.filters["hue"] = lambda s: zlib.crc32(s.encode()) % 360  # stable icon color per app
app.secret_key = SECRET
app.config.update(SESSION_COOKIE_SECURE=PUBLIC_URL.startswith("https"), SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=30 * 86400)
lock = threading.Lock()  # ponytail: one global lock for ASC + signing, fine for a handful of friends


# --- signed links: iOS installd and wget fetch without cookies, so links carry their own auth ---

def sig(path, exp):
    return hmac.new(SECRET, f"{path}:{exp}".encode(), hashlib.sha256).hexdigest()[:32]


def signed_url(path, ttl=LINK_TTL):
    exp = int(time.time()) + ttl
    return f"{PUBLIC_URL}{quote(path)}?e={exp}&s={sig(path, exp)}"


def check_sig():
    e, s = request.args.get("e", ""), request.args.get("s", "")
    if not (e.isdigit() and int(e) > time.time() and hmac.compare_digest(s, sig(request.path, int(e)))):
        abort(403)


def logged_in():
    return session.get("ok") is True


# --- Apple bits ---

def embedded_plist(blob):
    """Pull the XML plist out of a CMS-signed blob (profile-service POST body or .mobileprovision)."""
    # ponytail: skips verifying the CMS signature; the signed URL already authenticates the POST
    m = re.search(rb"<\?xml.*?</plist>", blob, re.S)
    if not m:
        raise ValueError("no plist in payload")
    return plistlib.loads(m.group(0))


def asc(method, path, **kw):
    now = int(time.time())
    token = jwt.encode({"iss": os.environ["ASC_ISSUER_ID"], "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
                       ASC_KEY.read_text(), algorithm="ES256", headers={"kid": os.environ["ASC_KEY_ID"]})
    r = requests.request(method, f"https://api.appstoreconnect.apple.com/v1{path}",
                         headers={"Authorization": f"Bearer {token}"}, timeout=30, **kw)
    if r.status_code >= 400:
        raise RuntimeError(f"App Store Connect {method} {path}: {r.status_code} {r.text[:300]}")
    return r.json() if r.content else {}


def device_token(udid):
    """Signed UDID kept in a long-lived cookie, so the page knows this phone is in the profile."""
    return f"{udid}.{hmac.new(SECRET, b'device:' + udid.encode(), 'sha256').hexdigest()[:32]}"


def token_udid(tok):
    udid = tok.partition(".")[0]
    return udid if udid and hmac.compare_digest(tok, device_token(udid)) else None


def profile_udids():
    return set(embedded_plist(PROFILE.read_bytes()).get("ProvisionedDevices", [])) if PROFILE.exists() else set()


def cert_id():
    _, cert, _ = pkcs12.load_key_and_certificates(P12.read_bytes(), P12_PASSWORD.encode() or None)
    serial = f"{cert.serial_number:X}".lstrip("0")
    for c in asc("GET", "/certificates", params={"limit": 200})["data"]:
        if c["attributes"]["serialNumber"].upper().lstrip("0") == serial:
            return c["id"]
    raise RuntimeError("cert.p12 not found in your developer account")


def regen_profile():
    bundle = asc("GET", "/bundleIds", params={"filter[identifier]": BUNDLE_ID})["data"]
    bundle = next(b for b in bundle if b["attributes"]["identifier"] == BUNDLE_ID)  # filter is a prefix match
    devices = asc("GET", "/devices", params={"filter[platform]": "IOS", "filter[status]": "ENABLED", "limit": 200})["data"]
    for p in asc("GET", "/profiles", params={"filter[name]": PROFILE_NAME})["data"]:
        asc("DELETE", f"/profiles/{p['id']}")
    rel = lambda t, ids: {"data": [{"type": t, "id": i} for i in ids]}
    created = asc("POST", "/profiles", json={"data": {
        "type": "profiles",
        "attributes": {"name": PROFILE_NAME, "profileType": "IOS_APP_ADHOC"},
        "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bundle["id"]}},
                          "certificates": rel("certificates", [cert_id()]),
                          "devices": rel("devices", [d["id"] for d in devices])}}})
    PROFILE.write_bytes(base64.b64decode(created["data"]["attributes"]["profileContent"]))


def register(udid, name):
    with lock:
        if udid in profile_udids():
            return
        if not asc("GET", "/devices", params={"filter[udid]": udid})["data"]:
            asc("POST", "/devices", json={"data": {"type": "devices", "attributes": {
                "name": name[:50], "udid": udid, "platform": "IOS"}}})
        regen_profile()
        resign(force=True)


def ipa_info(path):
    with zipfile.ZipFile(path) as z:
        name = next(n for n in z.namelist() if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n))
        info = plistlib.loads(z.read(name))
    return {"id": info["CFBundleIdentifier"], "version": info.get("CFBundleVersion", "1"),
            "short": info.get("CFBundleShortVersionString") or info.get("CFBundleVersion", "1"),
            "title": info.get("CFBundleDisplayName") or info.get("CFBundleName") or path.stem}


def fit_bundle_id(bid):
    """Bundle ID the app must be signed as so a wildcard profile like io.x.* covers it, or None if it already fits."""
    prefix = BUNDLE_ID[:-1]  # "io.x." for "io.x.*"
    if not BUNDLE_ID.endswith("*") or bid.startswith(prefix):
        return None
    return prefix + bid.rsplit(".", 1)[-1]  # ponytail: two apps sharing a last component would collide


def retarget(src, dst, old_id, new_id):
    """Copy an IPA, swapping the old bundle ID prefix for the new one in the app's and its extensions' Info.plists."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        for item in zin.infolist():
            data = zin.read(item)
            if item.filename.endswith("Info.plist") and ".lproj/" not in item.filename:
                info = plistlib.loads(data)
                bid = info.get("CFBundleIdentifier", "")
                if bid == old_id or bid.startswith(old_id + "."):
                    info["CFBundleIdentifier"] = new_id + bid[len(old_id):]
                    data = plistlib.dumps(info)
            zout.writestr(item, data)


def app_entitlements(bid):
    """The profile's entitlements with the wildcard narrowed to this app, the way Xcode signs.

    zsign copies TEAM.com.you.* verbatim, and iOS can then match the app to a development
    profile on the phone and demand Developer Mode."""
    ents = embedded_plist(PROFILE.read_bytes())["Entitlements"]
    team = ents["com.apple.developer.team-identifier"]
    ents["application-identifier"] = f"{team}.{bid}"
    ents["keychain-access-groups"] = [f"{team}.{bid}"]
    ents["get-task-allow"] = False
    return ents


def sign_ipa(src, out):
    old_id = ipa_info(src)["id"]
    new_id = fit_bundle_id(old_id)
    tmp = out.with_name(f".{out.name}.in") if new_id else src
    if new_id:  # rewrite ourselves: zsign 1.1.2's -b can't find Info.plist
        retarget(src, tmp, old_id, new_id)
    ents = out.with_name(f".{out.name}.entitlements.plist")
    ents.write_bytes(plistlib.dumps(app_entitlements(new_id or old_id)))
    try:
        subprocess.run(["zsign", "-q", "-t", out.parent, "-k", P12, "-p", P12_PASSWORD, "-m", PROFILE,
                        "-e", ents, "-o", out, tmp], check=True, timeout=600)
    finally:
        ents.unlink(missing_ok=True)
        if new_id:
            tmp.unlink(missing_ok=True)


def resign(force=False):
    """Sign every apps/*.ipa whose signed copy is missing or older than the IPA or profile."""
    if not PROFILE.exists():
        return
    SIGNED.mkdir(exist_ok=True)
    for src in sorted(APPS.glob("*.ipa")):
        out = SIGNED / src.name
        if force or not out.exists() or out.stat().st_mtime < max(src.stat().st_mtime, PROFILE.stat().st_mtime):
            sign_ipa(src, out)


def sync_sources():
    """Download the newest IPA of each app in SOURCES when its version changes."""
    for url, ids, third in SOURCES:
        seen = set()  # a source can list variants under one bundle ID (iOS 15 builds, …): the first is the main one
        for a in requests.get(url, timeout=30).json().get("apps", []):
            if (ids and a["bundleIdentifier"] not in ids) or a["bundleIdentifier"] in seen:
                continue
            seen.add(a["bundleIdentifier"])
            v = (a.get("versions") or [a])[0]  # newer sources nest versions, older ones are flat
            slug = re.sub(r"[^\w.-]", "", a["bundleIdentifier"])
            # the source's name for it (YouMod, not the IPA's own "YouTube"), shown on its Install button
            (APPS / f".{slug}.third").write_text(a.get("name", "")) if third else (APPS / f".{slug}.third").unlink(missing_ok=True)
            (APPS / f".{slug}.icon").write_text(a.get("iconURL", ""))  # ponytail: hotlinked, cache locally if a host goes flaky
            marker = APPS / f".{slug}.version"
            if not v.get("downloadURL") or (marker.exists() and marker.read_text() == v["version"]):
                continue
            tmp = APPS / f".{slug}.part"
            with requests.get(v["downloadURL"], stream=True, timeout=60) as r:
                r.raise_for_status()
                with tmp.open("wb") as f:
                    for chunk in r.iter_content(1 << 20):
                        f.write(chunk)
            tmp.replace(APPS / f"{slug}.ipa")
            marker.write_text(v["version"])


sync_lock, last_sync = threading.Lock(), [0.0]


def sync_if_stale(max_age):
    """Sync unless one ran within max_age seconds or another is already running."""
    if time.time() - last_sync[0] < max_age or not sync_lock.acquire(blocking=False):
        return
    try:
        last_sync[0] = time.time()  # set before trying so a GitHub outage doesn't stall every page load
        sync_sources()
    except Exception as e:
        print("source sync failed:", e, flush=True)
    finally:
        sync_lock.release()


def sync_loop():
    while True:
        sync_if_stale(0)
        time.sleep(3600)


if SOURCES:  # ponytail: runs once per worker; gunicorn here has one worker
    threading.Thread(target=sync_loop, daemon=True).start()


def sign_profile(data):
    """CMS-sign a .mobileconfig with the site's TLS cert. Read per request so cert renewals just work."""
    if not PROFILE_CERT_DIR:
        return data
    d = Path(PROFILE_CERT_DIR)
    chain = x509.load_pem_x509_certificates((d / "fullchain.pem").read_bytes())
    key = serialization.load_pem_private_key((d / "privkey.pem").read_bytes(), None)
    b = pkcs7.PKCS7SignatureBuilder().set_data(data).add_signer(chain[0], key, hashes.SHA256())
    for c in chain[1:]:
        b = b.add_certificate(c)
    return b.sign(serialization.Encoding.DER, [])


# --- pages ---

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>sidedrop</title><link rel=apple-touch-icon href=/apple-touch-icon.png><meta name=theme-color content="#b0bccd"><meta name=apple-mobile-web-app-title content=sidedrop>
<style>
:root{color-scheme:light;--bg:#f2f2f7;--cell:#fff;--fg:#000;--mute:#8a8a8e;--sep:rgba(60,60,67,.18);--acc:#007aff;--ok:#34c759;--fill:rgba(118,118,128,.12)}
body{font:17px/1.35 -apple-system,BlinkMacSystemFont,system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:30rem;margin:0 auto;
 padding:12px max(16px,env(safe-area-inset-right)) 48px max(16px,env(safe-area-inset-left));-webkit-font-smoothing:antialiased}
h1{font-size:34px;margin:8px 0 2px} h2{font-size:22px;margin:0;text-wrap:balance}
h3.hdr{font-size:13px;font-weight:400;color:var(--mute);text-transform:uppercase;letter-spacing:.02em;margin:22px 16px 6px}
.c,.g{background:var(--cell);border-radius:12px;padding:1rem 1.1rem;margin:0 0 1rem;overflow:hidden}
.g{padding:0;margin:0} .ftr{font-size:13px;color:var(--mute);margin:6px 16px 0}
.hero{border-radius:16px;padding:20px 18px;display:flex;flex-direction:column;gap:12px} .hero p{margin:0}
a.b,button{display:inline-block;background:var(--acc);color:#fff;border:0;border-radius:12px;padding:.75rem 1rem;font-family:inherit;font-size:17px;font-weight:600;line-height:1.2;text-decoration:none;cursor:pointer;text-align:center}
input{font:inherit;padding:12px 14px;border-radius:10px;border:0;width:100%;box-sizing:border-box;background:var(--fill);color:inherit}
label.drop{display:block;border:2px dashed var(--sep);border-radius:12px;padding:1.2rem;text-align:center;color:var(--mute)}
button:disabled{opacity:.4;cursor:default} small,.m{color:var(--mute)} small{font-size:13px} .err{color:#ff3b30} a{color:var(--acc);text-decoration:none}
.row{display:flex;align-items:center;gap:12px;padding:10px 16px;min-height:44px;position:relative}
.row+.row:before,details.row+details.row:before{content:"";position:absolute;top:0;right:0;left:76px;border-top:.5px solid var(--sep)}
.row>div:not(.ico){flex:1;min-width:0} .row small{display:block}
.ico{width:48px;height:48px;border-radius:11px;object-fit:cover;box-shadow:0 0 0 .5px var(--sep);flex:none;display:grid;place-items:center;color:#fff;font-weight:700;font-size:20px}
a.get{background:var(--fill);color:var(--acc);border-radius:99px;padding:6px 18px;font-family:inherit;font-size:15px;font-weight:700;flex:none;text-decoration:none}
.locked .ico{filter:grayscale(.7);opacity:.55} .locked a.get{color:var(--mute)}
details.row{display:block;padding:0} details.row:before{left:16px!important} details.row>summary{list-style:none;padding:12px 16px;cursor:pointer;display:flex;justify-content:space-between}
details.row>summary::-webkit-details-marker{display:none} details.row>summary:after{content:"›";color:var(--mute);font-size:20px;line-height:1;transition:transform .2s}
details[open].row>summary:after{transform:rotate(90deg)} details.row>:not(summary){margin:0 16px 12px}
ol{padding-left:1.3rem} li{margin:.35rem 0} .ok-badge{width:40px;height:40px;border-radius:50%;background:var(--ok);color:#fff;display:grid;place-items:center;font-size:22px;flex:none}
.nudge{animation:nudge .45s} @keyframes nudge{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
.nav{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:8px 0 2px}
.nav h1{margin:0;display:flex;align-items:center;gap:10px} .nav img{width:34px;height:34px;border-radius:8px}
.mini{box-shadow:0 0 0 .5px var(--sep);border-radius:10px;margin:0 0 12px}
.sw{position:relative;flex:none;width:51px;height:31px}
.sw input{position:absolute;inset:0;width:100%;height:100%;margin:0;padding:0;opacity:0;cursor:pointer;z-index:2}
.sw i{position:absolute;inset:0;border-radius:16px;background:var(--fill);transition:background .2s}
.sw .k{position:absolute;top:2px;left:2px;width:27px;height:27px;border-radius:50%;background:#fff;box-shadow:0 2px 4px rgba(0,0,0,.25);transition:transform .2s;pointer-events:none}
.sw input:checked~i{background:var(--ok)} .sw input:checked~.k{transform:translateX(20px)}
.sw input:focus-visible~i{outline:3px solid var(--acc);outline-offset:2px}
/* the 2012 look, layered over the base rules above. Single light look by design. */
:root{color-scheme:light;--cell:#fff;--fg:#000;--mute:#6d7480;--sep:#e0e0e0;--acc:#385487;--ok:#3c9a1d;--fill:#e6e9ec;
 --gloss:linear-gradient(rgba(255,255,255,.55),rgba(255,255,255,.12) 50%,rgba(255,255,255,0) 51%);
 --navbg:linear-gradient(#b0bccd,#889bb3 50%,#7d92ae 51%,#6d84a2);--barbtn:linear-gradient(#8fa1b9,#6a83a6 50%,#5877a2 51%,#4e6d99);
 --bluebtn:linear-gradient(#7aa5ef,#3b72d4 50%,#2861c9 51%,#3a73da);--greenbtn:linear-gradient(#8fd96b,#4caa2b 50%,#3c9a1d 51%,#4cae2a);
 --emboss:0 1px 0 rgba(255,255,255,.75);background:repeating-linear-gradient(90deg,#c5ccd4 0 5px,#cbd2d8 5px 7px);background-color:#c8cfd6}
body{font-family:"Helvetica Neue",Helvetica,Arial,sans-serif;background:none;padding-top:0}
.nav{position:sticky;top:0;z-index:5;height:44px;margin:0 calc(50% - 50vw) 14px;padding:env(safe-area-inset-top) max(8px,env(safe-area-inset-right)) 0 max(8px,env(safe-area-inset-left));
 box-sizing:content-box;justify-content:center;background:var(--navbg);box-shadow:inset 0 1px 0 #cdd5df,0 1px 0 #2d3642,0 2px 4px rgba(0,0,0,.25)}
.nav h1{font-size:20px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45)} .nav img{width:26px;height:26px;border-radius:6px;box-shadow:0 1px 1px rgba(0,0,0,.4)}
.nav button{position:absolute;right:max(8px,env(safe-area-inset-right));bottom:7px;font:700 12px/1.2 sans-serif;font-family:inherit;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45);
 background:var(--barbtn);border:1px solid #375073;border-radius:5px;padding:6px 10px;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 1px 0 rgba(255,255,255,.25)}
h2{font-size:19px} a{color:var(--acc)}
h3.hdr{font-size:17px;font-weight:700;color:#4c566c;text-transform:none;letter-spacing:0;margin:20px 10px 7px;text-shadow:var(--emboss)}
.ftr{font-size:14px;color:#4c566c;text-align:center;text-shadow:var(--emboss);margin:7px 12px 0}
.c,.g{border:1px solid #abb2bc;border-radius:10px;box-shadow:0 1px 0 rgba(255,255,255,.8)}
.g .g,.mini{box-shadow:none}
.row+.row:before,details.row+details.row:before{left:0!important;border-top:1px solid var(--sep)}
a.b,button{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.4);font-weight:700;border:1px solid #2b4f8a;border-radius:9px;background:var(--bluebtn);
 box-shadow:inset 0 1px 0 rgba(255,255,255,.45),0 1px 2px rgba(0,0,0,.3)}
input{background:#fff;border:1px solid #9aa3ae;border-radius:6px;box-shadow:inset 0 1px 2px rgba(0,0,0,.2)}
label.drop{border:1px solid #9aa3ae;border-radius:8px;color:#6b7684;font-weight:700;text-shadow:var(--emboss);
 background:repeating-linear-gradient(90deg,#d5dae0 0 5px,#dadfe4 5px 7px);box-shadow:inset 0 2px 5px rgba(0,0,0,.3),0 1px 0 #fff}
label.drop input{border:0;box-shadow:none;background:none}
textarea{border:1px solid #b7bec8!important;background:linear-gradient(#eef0f3,#fff 12px)!important;box-shadow:inset 0 1px 2px rgba(0,0,0,.15)}
.ico{box-shadow:0 1px 3px rgba(0,0,0,.45);position:relative} div.ico:after{content:"";position:absolute;inset:0;border-radius:inherit;background:var(--gloss)}
.ok-badge{background:var(--gloss),var(--greenbtn);border:1px solid #2f7a17;text-shadow:0 -1px 0 rgba(0,0,0,.35);box-shadow:0 1px 2px rgba(0,0,0,.3)}
/* App Store, 2012: one tap on the green INSTALL starts the install */
a.get{font-size:12px;letter-spacing:.02em;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);border-radius:4px;padding:5px 10px;border:1px solid #2f7a17;
 background:var(--greenbtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.4),0 1px 1px rgba(0,0,0,.15)}
a.get:active{background:linear-gradient(#3c9a1d,#5bb83a)}
.locked a.get{color:#5b6573;text-shadow:var(--emboss);border-color:#9aa3ae;background:linear-gradient(#fdfdfd,#e3e6ea);box-shadow:inset 0 1px 0 #fff}
details.row>summary{font-weight:700} details.row>summary:after{content:"";width:8px;height:8px;margin:6px 4px 0 0;border:solid #7f8a99;border-width:3px 3px 0 0;transform:rotate(45deg)}
details[open].row>summary:after{transform:rotate(135deg)}
.sw{width:79px;height:27px}
.sw i{border:1px solid #a7a7a7;border-radius:14px;overflow:hidden;background:linear-gradient(#e6e6e6,#fefefe);box-shadow:inset 0 2px 3px rgba(0,0,0,.3);font:700 16px/25px sans-serif;font-family:inherit}
.sw i:before{content:"ON";position:absolute;inset:0 auto 0 0;width:79px;padding-left:12px;box-sizing:border-box;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);
 background:linear-gradient(#1b68d8,#3f8cf3 55%,#5da1f6);transform:translateX(-79px);transition:transform .2s}
.sw i:after{content:"OFF";position:absolute;right:12px;color:#808080}
.sw .k{top:-1px;left:-1px;width:29px;height:29px;background:linear-gradient(#cfcfcf,#fcfcfc);border:1px solid #a3a3a3;box-sizing:border-box;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.sw input:checked~i{background:linear-gradient(#e6e6e6,#fefefe)} .sw input:checked~i:before{transform:none} .sw input:checked~i:after{opacity:0}
.sw input:checked~.k{transform:translateX(52px)}
.scrim[hidden]{display:none} .scrim{position:fixed;inset:0;z-index:20;display:grid;place-items:center;padding:16px;background:radial-gradient(rgba(0,0,0,.2),rgba(0,0,0,.6))}
.alert{width:min(284px,100%);box-sizing:border-box;border-radius:10px;border:2px solid rgba(255,255,255,.85);padding:16px 14px 14px;text-align:center;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.5);
 background:linear-gradient(rgba(255,255,255,.25),rgba(255,255,255,.06) 40px,transparent 41px),rgba(4,20,70,.88);box-shadow:0 4px 18px rgba(0,0,0,.6),inset 0 0 0 1px #000;animation:pop .3s ease-out}
@keyframes pop{0%{transform:scale(.6);opacity:0}60%{transform:scale(1.07);opacity:1}100%{transform:scale(1)}}
.alert h3{margin:0 0 6px;font-size:17px} .alert p{margin:0 0 12px;font-size:15px}
.abtns{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.alert .abtns button{height:43px;padding:0;font-size:16px;border:1px solid #0b1a3e;border-radius:6px;box-shadow:inset 0 1px 0 rgba(255,255,255,.3);
 background:linear-gradient(rgba(255,255,255,.35),rgba(255,255,255,.1) 50%,rgba(255,255,255,.05) 51%,rgba(255,255,255,.15))}
.alert .abtns .ok{background:linear-gradient(rgba(255,255,255,.5),rgba(255,255,255,.2) 50%,rgba(255,255,255,.12) 51%,rgba(255,255,255,.25))}
/* pull to refresh, Cydia/Tweetie style: sits behind the sticky nav, shows when iOS Safari rubber-bands the page down */
#ptr{position:absolute;left:0;right:0;top:calc(44px + env(safe-area-inset-top) - 400px);height:400px;z-index:1;display:flex;align-items:flex-end;justify-content:center;
 gap:14px;padding-bottom:12px;box-sizing:border-box;color:#576c89;text-shadow:var(--emboss);background:repeating-linear-gradient(90deg,#c5ccd4 0 5px,#cbd2d8 5px 7px);
 box-shadow:inset 0 -1px 0 #9aa3ae;pointer-events:none}
#ptr svg{width:22px;height:40px;transition:transform .18s} #ptr.armed svg.arrow{transform:rotate(180deg)}
#ptr .spin{display:none;width:20px;height:20px;margin:10px 1px;animation:spin .9s steps(12) infinite} #ptr.loading .spin{display:block} #ptr.loading .arrow{display:none}
#ptr b{display:block;font-size:13px} #ptr small{display:block;font-size:12px;color:#576c89}
@keyframes spin{to{transform:rotate(360deg)}}
.welcome{display:flex;gap:14px;align-items:center;margin-top:4px} .welcome img{width:72px;height:72px;flex:none;border-radius:14px;box-shadow:0 2px 4px rgba(0,0,0,.45)}
.welcome h2{font-size:21px} .welcome p{margin:3px 0 0;font-size:14px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}</style>
<div id=ptr aria-hidden=true><svg class=arrow viewBox="0 0 22 40"><path d="M7 0h8v26h7L11 40 0 26h7z" fill="#6f87a8" stroke="#4d6585"/></svg>
<svg class=spin viewBox="0 0 20 20"><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.08" transform="rotate(0 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.17" transform="rotate(30 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.25" transform="rotate(60 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.33" transform="rotate(90 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.42" transform="rotate(120 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.50" transform="rotate(150 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.58" transform="rotate(180 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.67" transform="rotate(210 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.75" transform="rotate(240 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.83" transform="rotate(270 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="0.92" transform="rotate(300 10 10)"/><rect x="9" y="1" width="2" height="5" rx="1" fill="#576c89" opacity="1.00" transform="rotate(330 10 10)"/></svg>
<div><b id=ptrT>Pull down to refresh…</b><small id=ptrU></small></div></div>
<script>(()=>{const d=new Date(),P=document.getElementById("ptr"),T=document.getElementById("ptrT");let busy=0;
document.getElementById("ptrU").textContent="Last Updated: "+d.toLocaleString("en-US",{month:"numeric",day:"numeric",year:"2-digit",hour:"numeric",minute:"2-digit"}).replace(",","");
addEventListener("scroll",()=>{if(busy)return;const a=scrollY<-65;P.classList.toggle("armed",a);T.textContent=a?"Release to refresh…":"Pull down to refresh…"},{passive:true});
addEventListener("touchend",()=>{if(busy||scrollY>=-65)return;busy=1;P.classList.add("loading");T.textContent="Loading…";document.body.style.paddingTop="64px";location.reload()})})()</script>
<header class=nav><h1><img src=/apple-touch-icon.png alt="">sidedrop</h1><button type=button onclick="about.hidden=false;about.querySelector('.ok').focus()">About</button></header>
<div class=scrim id=about hidden onclick="if(event.target==this)this.hidden=true"><div class=alert role=alertdialog aria-modal=true aria-labelledby=aboutT>
<h3 id=aboutT>About sidedrop</h3><p>Apps shared between friends, signed for each registered iPhone. Register once in Safari, then tap INSTALL.</p>
{% if stats %}<p>{{ stats[0] }} of 100 iPhones registered.{% if stats[1] %} Apps keep working until {{ stats[1].strftime('%B %-d, %Y') }}.{% endif %}</p>{% endif %}
<div class=abtns><button type=button onclick="about.hidden=true;let d=document.getElementById('dev');if(d){d.open=true;d.scrollIntoView()}">Help</button><button type=button class=ok onclick="about.hidden=true">OK</button></div></div></div>
<script>addEventListener("keydown",e=>{if(e.key=="Escape")about.hidden=true})</script>
{{ body|safe }}"""


def page(body, **ctx):
    stats = None
    if logged_in() and PROFILE.exists():  # for the About alert: devices used, and when the profile (so every app) expires
        prof = embedded_plist(PROFILE.read_bytes())
        stats = (len(prof.get("ProvisionedDevices", [])), prof.get("ExpirationDate"))
    return render_template_string(PAGE, body=render_template_string(body, **ctx), stats=stats)


@app.get("/")
def home():
    if "password" in request.args:  # shareable ?password= link; redirect drops it from the address bar
        return login()
    if not logged_in():
        return page("""<form class=c method=post action=/login>
<label>Password<input type=password name=password autofocus required></label>
{% if err %}<p class=err>Wrong password.</p>{% endif %}<button>Sign in</button></form>""", err=request.args.get("err"))
    tok = request.args.get("enrolled") or request.cookies.get("device", "")  # ?enrolled= is the 301 after the profile install
    enrolled = token_udid(tok) in profile_udids()
    error = None
    sync_if_stale(60)  # ponytail: a new release makes this one page load wait for the download
    try:
        with lock:
            resign()  # ponytail: signs stale IPAs on page load; first visit after an upload waits for it
    except Exception as e:
        error = str(e)
    apps = [dict(ipa_info(p), name=p.stem, files=sorted(f for f in (APP_FILES / p.stem).glob("*") if f.is_file()))
            for p in sorted(SIGNED.glob("*.ipa"))] if SIGNED.exists() else []
    feather = [a for a in apps if "feather" in a["name"].lower()]  # mirrored via SOURCES, shown in its own menu
    third = [a for a in apps if a not in feather and (APPS / f".{a['name']}.third").exists()]
    for a in third:
        a["title"] = (APPS / f".{a['name']}.third").read_text().strip() or a["title"]
    for a in apps:
        a["icon"] = (APPS / f".{a['name']}.icon").read_text().strip() if (APPS / f".{a['name']}.icon").exists() else ""
    apps = [a for a in apps if a not in feather and a not in third]
    files = sorted(p for p in FILES.rglob("*") if p.is_file()) if FILES.exists() else []
    resp = make_response(page("""
{% if error %}<p class="c err">{{ error }}</p>{% endif %}
<div class="c welcome"><img src=/apple-touch-icon.png alt=""><div><h2>Welcome to sidedrop</h2>
<p class=m>{% if enrolled %}Apps from friends, signed for this iPhone. Tap INSTALL on any app below.{% else %}Apps from friends, signed for your iPhone. Register it below to get started.{% endif %}</p></div></div>
{% set enroll_form %}<form method=post action=/enroll style="display:flex;flex-direction:column;gap:10px"
 onsubmit="document.getElementById('next').hidden=false;this.querySelector('button').textContent='Check the popup…'">
<input name=name required maxlength=30 placeholder="Your name" aria-label="Your name" autocomplete=given-name
 oninput="this.form.querySelector('button').disabled=!this.value.trim()"><button disabled>Register iPhone</button></form>
<ol id=next hidden><li>Tap <b>Allow</b>, then <b>Close</b>.</li><li>Open the <b>Settings</b> app.</li>
<li>Tap <b>Profile Downloaded</b> near the top.</li><li>Tap <b>Install</b>, enter your passcode, tap <b>Install</b> again.</li>
<li>You'll land back here automatically, registered.</li></ol>{% endset %}
<script>addEventListener("pageshow",()=>document.querySelectorAll("input[name=name]").forEach(i=>i.oninput()))</script>
{% if not enrolled %}<div class="c hero" id=reg><h2>First, register this iPhone</h2>
<p class=m>Apps only install on registered phones. Do this in Safari on the iPhone. It takes about a minute, once per phone.</p>
{{ enroll_form }}<small>Registered before but the apps are locked? Register again, it's instant.</small></div>{% endif %}
{% macro install_list(apps) %}<div class="g{{ '' if enrolled else ' locked' }}">{% for a in apps %}
<div class=row>{% if a.icon %}<img class=ico src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=ico style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}
<div>{{ a.title }}<small>Version {{ a.short }}</small>{% for f in a.files %}<small><a href="{{ adl(f) }}">↓ {{ f.name }}</a>
· {{ '%.1f'|format(f.stat().st_size/1e6) }} MB</small>{% endfor %}</div>
{% if enrolled %}<a class=get aria-label="Install {{ a.title }}" href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">INSTALL</a>
{% else %}<a class=get aria-label="Register first" href=#reg onclick="let r=document.getElementById('reg');r.classList.remove('nudge');void r.offsetWidth;r.classList.add('nudge');r.querySelector('input').focus()">🔒</a>{% endif %}</div>
{% endfor %}</div>{% endmacro %}
<h3 class=hdr>Apps</h3>{% if apps %}{{ install_list(apps) }}
<p class=ftr>{% if enrolled %}Tap Install, then Install in the popup, and check your home screen.{% else %}Register above to unlock these.{% endif %}</p>
{% else %}<p class="c m">No apps yet.</p>{% endif %}
{% if third %}<h3 class=hdr>Third-party apps</h3>{{ install_list(third) }}<p class=ftr>Made by other people, mirrored from their sources.</p>{% endif %}
<h3 class=hdr>If an app won't open</h3><div class=g><details class=row id=dev><summary>Turn on Developer Mode</summary>
<p class=m>Needed once per iPhone for apps not from the App Store.</p>
<ol><li>Install an app above first. The switch only shows up after that.</li>
<li>Open Settings → Privacy &amp; Security → <b>Developer Mode</b> (near the bottom) → turn it on → <b>Restart</b>.</li>
<li>After the restart, tap <b>Turn On</b> and enter your passcode. The apps open normally from then on.</li></ol>
<div class="g mini"><div class=row><div>Developer Mode</div><label class=sw><input type=checkbox checked aria-label="Developer Mode (example of the switch)"><i></i><span class=k></span></label></div></div></details></div>
{% if enrolled %}<h3 class=hdr>This iPhone</h3><div class="c hero"><div style="display:flex;gap:12px;align-items:center"><div class=ok-badge>✓</div>
<div><h2>This iPhone is registered</h2><small>It can install every app above.</small></div></div>
<details><summary class=m>Register a different iPhone</summary>{{ enroll_form }}</details></div>{% endif %}
<h3 class=hdr>More</h3><div class=g>
<details class=row><summary><span>Feather <small style="display:inline">on-device signer</small></span></summary>
<p class=m>Feather installs and re-signs IPAs right on the iPhone. It needs your own Apple certificate to sign;
the "Sign your own IPA" box below works without one.</p>
{% for a in feather %}<p>{% if enrolled %}<a class=b href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">Install Feather</a>
{% else %}<a class=b href=#reg>Register to install Feather</a>{% endif %} <small style="display:inline">v{{ a.short }}</small></p>{% endfor %}
{% if sources %}<p class=m>Sources to add in Feather:</p>
<textarea id=src readonly rows={{ sources|length }} wrap=off style="width:calc(100% - 32px);box-sizing:border-box;font:13px ui-monospace,monospace;background:var(--fill);color:inherit;border:0;border-radius:10px;padding:8px">{{ sources|join('\n') }}</textarea>
<p><button type=button onclick="navigator.clipboard.writeText(src.value).then(()=>this.textContent='Copied ✓')">Copy sources</button></p>{% endif %}
<p><a href="{{ FEATHER_REPO }}">Feather on GitHub</a> · <a href="{{ FEATHER_REPO }}/releases/latest">latest release</a></p></details>
<details class=row><summary>Sign your own IPA</summary>
<form method=post action=/sign enctype=multipart/form-data style="display:flex;flex-direction:column;gap:10px" onsubmit="this.querySelector('button').textContent='Signing…'">
<label class=drop>Drop an .ipa here or tap to browse<input type=file name=ipa accept=.ipa style="background:none"></label>
<input type=url name=url placeholder="…or paste a link to an .ipa" aria-label="Link to an .ipa">
<button>Sign</button></form><p><small>Signed for registered iPhones. The install link lasts 7 days.</small></p></details></div>
{% if files %}<h3 class=hdr>Files</h3><div class=g>{% for f in files %}
<div class=row style="padding-left:16px"><div><a href="{{ dl(f) }}">{{ f.relative_to(FILES) }}</a><small>{{ '%.1f'|format(f.stat().st_size/1e6) }} MB · link works without login for 7 days</small></div></div>
{% endfor %}</div>{% endif %}
<p style="text-align:center;margin-top:28px"><a href=/logout>Sign out</a></p>""", error=error, enrolled=enrolled, apps=apps, third=third, files=files, FILES=FILES, feather=feather, FEATHER_REPO=FEATHER_REPO,
        sources=read_urls("feather-sources.txt"),
        manifest=lambda n: quote(signed_url(f"/m/{n}.plist"), safe=""),
        dl=lambda f: signed_url(f"/f/{f.relative_to(FILES)}"), adl=lambda f: signed_url(f"/af/{f.relative_to(APP_FILES)}")))
    if enrolled and request.args.get("enrolled"):  # survives sign-out; re-checked against the profile on every load
        resp.set_cookie("device", tok, max_age=10 * 365 * 86400, secure=True, httponly=True, samesite="Lax")
    return resp


@app.get("/apple-touch-icon.png")
def touch_icon():
    return send_from_directory(HERE, "icon.png", max_age=86400)  # source: icon.svg (rsvg-convert -w 180 icon.svg -o icon.png)


@app.post("/login")
def login():
    if not hmac.compare_digest(request.values.get("password", "").encode(), PASSWORD.encode()):
        time.sleep(2)  # ponytail: slows guessing per request, add per-IP lockout if this ever gets hammered
        return redirect("/?err=1")
    session.permanent, session["ok"] = True, True
    return redirect("/")


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.post("/enroll")
def enroll():
    if not logged_in():
        abort(403)
    name = re.sub(r"[^\w .'-]", "", request.form.get("name", ""))[:30] or "friend"
    url = signed_url(f"/udid/{name}", ttl=1800)
    profile = plistlib.dumps({
        "PayloadContent": {"URL": url, "DeviceAttributes": ["UDID", "PRODUCT"]},
        "PayloadOrganization": "sidedrop", "PayloadDisplayName": "sidedrop device registration",
        "PayloadDescription": "Shares this iPhone's device ID so apps can be signed for it.",
        "PayloadIdentifier": "sidedrop.udid", "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadType": "Profile Service", "PayloadVersion": 1})
    return sign_profile(profile), 200, {"Content-Type": "application/x-apple-aspen-config",
                          "Content-Disposition": 'attachment; filename="sidedrop.mobileconfig"'}


@app.post("/udid/<name>")
def udid(name):
    check_sig()
    attrs = embedded_plist(request.get_data())
    register(attrs["UDID"], f"{name} {attrs.get('PRODUCT', '')}".strip())
    return redirect(f"{PUBLIC_URL}/?enrolled={device_token(attrs['UDID'])}", 301)  # iOS requires a 301 here, then opens it in Safari


@app.post("/sign")
def sign_custom():
    """Sign one IPA from an upload or URL and hand back an install link."""
    if not logged_in():
        abort(403)
    if not PROFILE.exists():
        return page("<p class='c err'>No iPhones are registered yet.</p><p><a href=/>Back</a></p>")
    CUSTOM.mkdir(parents=True, exist_ok=True)
    for old in CUSTOM.glob("*.ipa"):  # ponytail: cleanup piggybacks on new signs; links die with LINK_TTL anyway
        if old.stat().st_mtime < time.time() - LINK_TTL:
            old.unlink(missing_ok=True)
    name = uuid.uuid4().hex[:16]
    src, out = CUSTOM / f".{name}.part", CUSTOM / f"{name}.ipa"
    up, url = request.files.get("ipa"), request.form.get("url", "").strip()
    try:
        if up and up.filename:
            up.save(src)
        elif url.startswith(("https://", "http://")):
            # ponytail: no SSRF guard; only logged-in friends reach this
            with requests.get(url, stream=True, timeout=60) as r:
                r.raise_for_status()
                with src.open("wb") as f:
                    for chunk in r.iter_content(1 << 20):
                        f.write(chunk)
        else:
            return page("<p class='c err'>Pick an .ipa or paste an http(s) link.</p><p><a href=/>Back</a></p>")
        with lock:
            sign_ipa(src, out)
        info = ipa_info(out)
    except Exception as e:
        out.unlink(missing_ok=True)
        return page("<p class='c err'>Couldn't sign that: {{ e }}</p><p><a href=/>Back</a></p>", e=e)
    finally:
        src.unlink(missing_ok=True)
    return page("""<div class=c><h3>{{ i.title }} <small>v{{ i.short }}</small></h3>
<p><a class=b href="itms-services://?action=download-manifest&url={{ m }}">Install {{ i.title }}</a></p>
<small>Link works for 7 days. Developer Mode must be on.</small></div><p><a href=/>Back</a></p>""",
                i=info, m=quote(signed_url(f"/m/custom/{name}.plist"), safe=""))


@app.post("/sync")
def sync_now():
    if not SYNC_TOKEN or not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {SYNC_TOKEN}"):
        abort(403)

    def run():
        sync_if_stale(0)
        try:
            with lock:
                resign()
        except Exception as e:
            print("resign failed:", e, flush=True)
    threading.Thread(target=run, daemon=True).start()  # return right away; CI shouldn't wait on downloads
    return "", 202


@app.get("/m/<path:name>.plist")
def manifest(name):
    check_sig()
    ipa = SIGNED / f"{name}.ipa"
    if not ipa.exists():
        abort(404)
    info = ipa_info(ipa)
    icon = (APPS / f".{name}.icon").read_text().strip() if (APPS / f".{name}.icon").exists() else ""
    return plistlib.dumps({"items": [{
        "assets": [{"kind": "software-package", "url": signed_url(f"/i/{name}.ipa", ttl=3600)}]
                  + [{"kind": k, "url": icon} for k in ("display-image", "full-size-image") if icon],
        "metadata": {"bundle-identifier": info["id"], "bundle-version": info["version"],
                     "kind": "software", "title": info["title"]}}]}), 200, {"Content-Type": "text/xml"}


@app.get("/i/<path:name>.ipa")
def ipa(name):
    check_sig()
    return send_from_directory(SIGNED, f"{name}.ipa", mimetype="application/octet-stream")


@app.get("/f/<path:rel>")
def file(rel):
    check_sig()
    return send_from_directory(FILES, rel, as_attachment=True)  # handles Range, so downloads resume


@app.get("/af/<path:rel>")
def app_file(rel):
    check_sig()
    return send_from_directory(APP_FILES, rel, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
