"""sidedrop: password-gated UDID enrollment, ad hoc OTA installs and private file downloads."""
import base64, datetime, hashlib, hmac, itertools, json, os, plistlib, re, subprocess, threading, time, uuid, zipfile, zlib
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
INSTALLED, installed_lock = DATA / "installed.json", threading.Lock()  # {udid: {app: "short/build"}} from INSTALL taps, for Changes


def installed():
    try:
        return json.loads(INSTALLED.read_text())
    except (OSError, ValueError):
        return {}


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
        src = requests.get(url, timeout=30).json()
        for a in src.get("apps", []):
            if (ids and a["bundleIdentifier"] not in ids) or a["bundleIdentifier"] in seen:
                continue
            seen.add(a["bundleIdentifier"])
            v = (a.get("versions") or [a])[0]  # newer sources nest versions, older ones are flat
            slug = re.sub(r"[^\w.-]", "", a["bundleIdentifier"])
            # the source's name for it (YouMod, not the IPA's own "YouTube"), shown on its Install button
            (APPS / f".{slug}.third").write_text(a.get("name", "")) if third else (APPS / f".{slug}.third").unlink(missing_ok=True)
            (APPS / f".{slug}.icon").write_text(a.get("iconURL", ""))  # ponytail: hotlinked, cache locally if a host goes flaky
            desc = (v.get("localizedDescription") or a.get("subtitle") or a.get("localizedDescription") or "").strip()
            for k, val in {"source": src.get("name", ""), "date": v.get("date", ""), "desc": desc.splitlines()[0] if desc else ""}.items():
                (APPS / f".{slug}.{k}").write_text(val)  # shown on the Changes tab
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
<title>sidedrop</title><link rel=apple-touch-icon href=/apple-touch-icon.png><meta name=theme-color content="#b0bccd"><meta name=apple-mobile-web-app-status-bar-style content=black><meta name=apple-mobile-web-app-title content=sidedrop>
<script>/* Dark Mode follows the phone's theme until the More switch picks one (localStorage.dark = "1"/"0") */
function theme(){let d=null;try{d=localStorage.dark}catch(e){}let on=document.documentElement.classList.toggle("dark",d?d=="1":matchMedia("(prefers-color-scheme: dark)").matches);
 document.querySelector("meta[name=theme-color]").content=on?"#5f656f":"#b0bccd"}  /* Safari's top bar matches the nav */
theme();matchMedia("(prefers-color-scheme: dark)").addEventListener("change",theme)</script>
<style>
/* 2012 iOS look (pinstripes, glossy bars, App Store buttons), with a gunmetal Dark Mode below. */
:root{color-scheme:light;--mute:#6d7480;--sep:#e0e0e0;--line:#abb2bc;--acc:#385487;--head:#4c566c;
 --pin:repeating-linear-gradient(90deg,#c5ccd4 0 5px,#cbd2d8 5px 7px);--gloss:linear-gradient(rgba(255,255,255,.55),rgba(255,255,255,.12) 50%,rgba(255,255,255,0) 51%);
 --navbg:linear-gradient(#b0bccd,#889bb3 50%,#7d92ae 51%,#6d84a2);--barbtn:linear-gradient(#8fa1b9,#6a83a6 50%,#5877a2 51%,#4e6d99);
 --bluebtn:linear-gradient(#7aa5ef,#3b72d4 50%,#2861c9 51%,#3a73da);--greenbtn:linear-gradient(#8fd96b,#4caa2b 50%,#3c9a1d 51%,#4cae2a);
 --greybtn:linear-gradient(#fdfdfd,#e3e6ea);--emboss:0 1px 0 rgba(255,255,255,.75);background:#c8cfd6}
/* fixed backdrop: stays put while iOS rubber-bands the page, so the bounce shows pinstripes instead of a flat color */
body::before{content:"";position:fixed;inset:0;z-index:-1;background:var(--pin)}
/* body scrolls, not the page: iOS 26 blurs the top edge of a scrolling page in the home-screen app, washing out the nav, and has no switch to turn that off */
html{height:100%;overflow:hidden}
body{height:100%;box-sizing:border-box;overflow-y:auto;overscroll-behavior:contain;margin:0;font:17px/1.35 "Helvetica Neue",Helvetica,Arial,sans-serif;color:#000;-webkit-font-smoothing:antialiased;
 padding:calc(56px + env(safe-area-inset-top)) max(10px,env(safe-area-inset-right),(100% - 30rem)/2) calc(72px + env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left),(100% - 30rem)/2)}
a{color:var(--acc);text-decoration:none} small,.m{color:var(--mute)} small{font-size:13px} .err{color:#d70015} h2{font-size:19px;margin:0}
button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #f5c542;outline-offset:2px}
.nav{position:fixed;top:0;left:0;right:0;z-index:5;height:44px;padding:env(safe-area-inset-top) max(7px,env(safe-area-inset-right)) 0 max(7px,env(safe-area-inset-left));
 display:grid;grid-template-columns:1fr auto 1fr;align-items:center;background:var(--navbg);box-shadow:inset 0 1px 0 #cdd5df,0 1px 0 #2d3642,0 2px 4px rgba(0,0,0,.25)}
.nav h1{margin:0;font-size:20px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45)}
.nav .bar{justify-self:start;width:auto;font-size:12px;font-weight:700;line-height:1.2;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45);background:var(--barbtn);border:1px solid #375073;
 border-radius:5px;padding:6px 10px;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 1px 0 rgba(255,255,255,.25)} .nav .bar.r{justify-self:end}
h3.hdr{font-size:17px;font-weight:700;color:var(--head);margin:20px 10px 7px;text-shadow:var(--emboss)}
.ftr{font-size:14px;color:var(--head);text-align:center;text-shadow:var(--emboss);margin:7px 12px 0}
.c,.g{background:#fff;border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 0 rgba(255,255,255,.8);overflow:hidden}
.c{padding:14px;margin:0 0 12px;display:flex;flex-direction:column;gap:10px} .c p{margin:0}
a.b,button{display:block;box-sizing:border-box;width:100%;font:inherit;font-weight:700;line-height:1.2;text-align:center;cursor:pointer;padding:11px;color:#fff;
 text-shadow:0 -1px 0 rgba(0,0,0,.4);border:1px solid #2b4f8a;border-radius:9px;background:var(--bluebtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.45),0 1px 2px rgba(0,0,0,.3)}
a.b.grey,button.grey{color:#38404b;text-shadow:var(--emboss);border-color:#8d97a5;background:linear-gradient(#fff,#e9ebee 50%,#dde0e5 51%,#eceef1)}
button:disabled{opacity:.5;cursor:default}
input{font:inherit;width:100%;box-sizing:border-box;padding:10px 12px;background:#fff;border:1px solid #9aa3ae;border-radius:6px;box-shadow:inset 0 1px 2px rgba(0,0,0,.2);color:var(--acc)}
label.drop{display:block;padding:18px 12px;text-align:center;border:1px solid #9aa3ae;border-radius:8px;color:#6b7684;font-weight:700;text-shadow:var(--emboss);
 background:repeating-linear-gradient(90deg,#d5dae0 0 5px,#dadfe4 5px 7px);box-shadow:inset 0 2px 5px rgba(0,0,0,.3),0 1px 0 #fff}
label.drop input{border:0;box-shadow:none;background:none;padding:8px 0 0;font-size:13px}
textarea{width:100%;box-sizing:border-box;font:12px/1.5 ui-monospace,Menlo,monospace;border:1px solid #b7bec8;border-radius:6px;padding:8px;color:#333;resize:none;
 background:linear-gradient(#eef0f3,#fff 12px);box-shadow:inset 0 1px 2px rgba(0,0,0,.15);white-space:pre;overflow-x:auto}
ol{margin:0;padding-left:1.3rem} li{margin:.35rem 0}
.row{display:flex;align-items:center;gap:10px;min-height:44px;padding:9px 10px;border-top:1px solid var(--sep)}
.g>:first-child{border-top:0!important} .row>div:not(.ico){flex:1;min-width:0} .row small{display:block}
.ico{position:relative;width:50px;height:50px;flex:none;border-radius:10px;object-fit:cover;display:grid;place-items:center;color:#fff;font-weight:700;font-size:21px;
 text-shadow:0 -1px 0 rgba(0,0,0,.3);box-shadow:0 1px 3px rgba(0,0,0,.45)} div.ico:after{content:"";position:absolute;inset:0;border-radius:inherit;background:var(--gloss)}
.locked .ico{filter:grayscale(.8);opacity:.6}
details{border-top:1px solid var(--sep)} details>summary{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:10px;min-height:44px;
 padding:0 10px;font-weight:700} details>summary::-webkit-details-marker{display:none}
details>summary:after{content:"";flex:none;width:8px;height:8px;margin-right:4px;border:solid #7f8a99;border-width:3px 3px 0 0;transform:rotate(45deg);transition:transform .2s}
details[open]>summary:after{transform:rotate(135deg)} details>:not(summary){margin:0 10px 12px}
.scrim[hidden]{display:none} .scrim{position:fixed;inset:0;z-index:20;display:grid;place-items:center;padding:16px;background:radial-gradient(rgba(0,0,0,.2),rgba(0,0,0,.6))}
.alert{width:min(284px,100%);box-sizing:border-box;border-radius:10px;border:2px solid rgba(255,255,255,.85);padding:16px 14px 14px;text-align:center;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.5);
 background:linear-gradient(rgba(255,255,255,.25),rgba(255,255,255,.06) 40px,transparent 41px),rgba(4,20,70,.88);box-shadow:0 4px 18px rgba(0,0,0,.6),inset 0 0 0 1px #000;animation:pop .3s ease-out}
@keyframes pop{0%{transform:scale(.6);opacity:0}60%{transform:scale(1.07);opacity:1}100%{transform:scale(1)}}
.alert h3{margin:0 0 6px;font-size:17px} .alert p{margin:0 0 12px;font-size:15px}
.abtns{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.alert .abtns button{height:43px;padding:0;font-size:16px;border:1px solid #0b1a3e;border-radius:6px;box-shadow:inset 0 1px 0 rgba(255,255,255,.3);
 background:linear-gradient(rgba(255,255,255,.35),rgba(255,255,255,.1) 50%,rgba(255,255,255,.05) 51%,rgba(255,255,255,.15))}
.alert .abtns .ok{background:linear-gradient(rgba(255,255,255,.5),rgba(255,255,255,.2) 50%,rgba(255,255,255,.12) 51%,rgba(255,255,255,.25))}
/* Dark Mode (follows the phone, or the More tab switch): gunmetal bars, dark pinstripes, inverted emboss */
html.dark{color-scheme:dark;--mute:#8b9099;--sep:#17191c;--line:#0d0e10;--acc:#6fa8ff;--head:#8b9099;--emboss:0 -1px 0 #000;
 --pin:repeating-linear-gradient(90deg,#1b1d21 0 5px,#202227 5px 7px);--navbg:linear-gradient(#5f656f,#3b4048 50%,#30343b 51%,#23262b);
 --barbtn:linear-gradient(#4a4f58,#24272c);--greybtn:linear-gradient(#4a4f58,#2c2f34);background:#1d1f23}
.dark body{color:#e6e8eb} .dark .nav{box-shadow:inset 0 1px 0 #7a808a,0 1px 0 #0b0c0e,0 2px 4px rgba(0,0,0,.5)} .dark .nav .bar{border-color:#111}
.dark .c,.dark .g{background:#2c2f34;border-color:#0d0e10;box-shadow:0 1px 0 rgba(255,255,255,.06)}
.dark .row,.dark details>summary{background:linear-gradient(#34373d,#2a2d32);box-shadow:inset 0 1px 0 rgba(255,255,255,.07)}
.dark input{background:#1f2125;border-color:#0d0e10;color:#e6e8eb;box-shadow:inset 0 1px 3px #000} .dark textarea{background:#1f2125;border-color:#0d0e10;color:#ccc}
.dark label.drop{background:repeating-linear-gradient(90deg,#16181b 0 5px,#1a1c1f 5px 7px);border-color:#0d0e10;color:#8b9099;box-shadow:inset 0 2px 5px #000,0 1px 0 rgba(255,255,255,.06)}
.dark a.b.grey,.dark button.grey{color:#e6e8eb;border-color:#111;background:linear-gradient(#4a4f58,#2c2f34 50%,#24272c 51%,#2c2f34);box-shadow:inset 0 1px 0 rgba(255,255,255,.15)}
/* Cydia-style "Reloading Data" HUD while Reload syncs sources and re-signs */
.hud{width:min(276px,100%);box-sizing:border-box;padding:34px 10px 26px;border-radius:14px;background:rgba(20,20,20,.82);color:#fff;text-align:center;font-weight:700;font-size:30px;line-height:1.1;letter-spacing:-.3px;
 display:grid;justify-items:center;gap:16px} /* Cydia's HUD: big bold label, grey spinner, no border */
.spin{width:37px;height:37px;animation:spin 1s steps(12) infinite} @keyframes spin{to{transform:rotate(360deg)}}
.scrim.clear{background:none}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}</style>
<header class=nav><button type=button class=bar onclick="about.hidden=false;about.querySelector('.ok').focus()">About</button><h1 id=navT>sidedrop</h1>
<button type=button class="bar r" onclick="reloadData()">Reload</button></header>
<div class="scrim clear" id=reloading hidden><div class=hud role=status><svg class=spin viewBox="0 0 24 24" aria-hidden=true><g stroke="#d0d0d0" stroke-width="2.2" stroke-linecap="round">
<line x1=12 y1=2.5 x2=12 y2=7 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(30 12 12)" opacity=.92 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(60 12 12)" opacity=.84 />
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(90 12 12)" opacity=.76 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(120 12 12)" opacity=.68 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(150 12 12)" opacity=.6 />
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(180 12 12)" opacity=.52 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(210 12 12)" opacity=.44 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(240 12 12)" opacity=.36 />
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(270 12 12)" opacity=.3 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(300 12 12)" opacity=.25 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(330 12 12)" opacity=.2 /></g></svg>
Reloading Data</div></div>
<div class=scrim id=about hidden onclick="if(event.target==this)this.hidden=true"><div class=alert role=alertdialog aria-modal=true aria-labelledby=aboutT>
<h3 id=aboutT>About sidedrop</h3><p>Apps shared between friends, signed for each registered iPhone. Register once in Safari, then tap GET.</p>
{% if stats %}<p>{{ stats[0] }} of 100 iPhones registered.{% if stats[1] %} Apps keep working until {{ stats[1].strftime('%B %-d, %Y') }}.{% endif %}</p>{% endif %}
<div class=abtns><button type=button onclick="about.hidden=true;let d=document.getElementById('dev');if(d){location.hash='more';d.open=true;setTimeout(()=>d.scrollIntoView(),50)}">Help</button><button type=button class=ok onclick="about.hidden=true">OK</button></div></div></div>
<script>addEventListener("keydown",e=>{if(e.key=="Escape")about.hidden=true})
function reloadData(){reloading.hidden=false;fetch("/refresh",{method:"POST"}).catch(()=>{}).finally(()=>location.replace("/"+location.hash))}</script>
{{ body|safe }}"""


def file_labels(folder):
    """appfiles/<app>/labels.txt: one "file name = label" line per file, e.g. "GMPE01.iso = the game disc"."""
    f = folder / "labels.txt"
    return {k.strip(): v.strip() for k, _, v in (l.partition("=") for l in f.read_text().splitlines() if "=" in l)} if f.exists() else {}


def page(body, **ctx):
    stats = None
    if logged_in() and PROFILE.exists():  # for the About alert: devices used, and when the profile (so every app) expires
        prof = embedded_plist(PROFILE.read_bytes())
        stats = (len(prof.get("ProvisionedDevices", [])), prof.get("ExpirationDate"))
    return render_template_string(PAGE, body=render_template_string(body, stats=stats, **ctx), stats=stats)


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
    apps = [dict(ipa_info(p), name=p.stem, files=sorted(f for f in (APP_FILES / p.stem).glob("*") if f.is_file() and f.name != "labels.txt"))
            for p in sorted(SIGNED.glob("*.ipa"))] if SIGNED.exists() else []
    feather = [a for a in apps if "feather" in a["name"].lower()]  # mirrored via SOURCES, shown in its own menu
    third = [a for a in apps if a not in feather and (APPS / f".{a['name']}.third").exists()]
    for a in third:
        a["title"] = (APPS / f".{a['name']}.third").read_text().strip() or a["title"]
    for a in apps:
        a["icon"] = (APPS / f".{a['name']}.icon").read_text().strip() if (APPS / f".{a['name']}.icon").exists() else ""
    meta = lambda a, k: (APPS / f".{a['name']}.{k}").read_text().strip() if (APPS / f".{a['name']}.{k}").exists() else ""
    for a in apps:
        a["vkey"], a["source"], a["desc"] = f"{a['short']}/{a['version']}", meta(a, "source") or "sidedrop", meta(a, "desc")
        try:
            a["when"] = datetime.date.fromisoformat(meta(a, "date")[:10])
        except ValueError:  # no release date from a source: when the IPA arrived
            src = APPS / f"{a['name']}.ipa"
            a["when"] = datetime.date.fromtimestamp((src if src.exists() else SIGNED / f"{a['name']}.ipa").stat().st_mtime)
    mine = installed().get(token_udid(tok), {}) if enrolled else {}
    updates = [a for a in apps if a["name"] in mine and mine[a["name"]] != a["vkey"]]
    recent = [(d, list(g)) for d, g in itertools.groupby(sorted(apps, key=lambda a: a["when"], reverse=True)[:30], key=lambda a: a["when"])]
    apps = [a for a in apps if a not in feather and a not in third]
    files = sorted(p for p in FILES.rglob("*") if p.is_file()) if FILES.exists() else []
    resp = make_response(page("""<style>
.splash{display:flex;align-items:center;gap:14px;padding:2px 6px 4px} .splash img{width:76px;height:76px;flex:none;border-radius:15px;box-shadow:0 3px 6px rgba(0,0,0,.45)}
.splash h2{font-size:23px;font-weight:400;letter-spacing:-.3px;line-height:1.15;text-shadow:var(--emboss)} .splash p{margin:3px 0 0;font-size:16px;text-shadow:var(--emboss)}
.splash p a{font-weight:700}
/* iOS 5 App Store price button: grey GET, a tap turns it into a green INSTALL, a second tap installs */
.get{flex:none;display:inline-block;width:auto;min-width:62px;box-sizing:border-box;text-align:center;font-size:12px;font-weight:700;letter-spacing:.02em;line-height:1.2;font-family:inherit;padding:5px 10px;
 border-radius:4px;cursor:pointer;white-space:nowrap;color:#4e5866;text-shadow:var(--emboss);border:1px solid #9aa3ae;background:var(--greybtn);box-shadow:inset 0 1px 0 #fff,0 1px 1px rgba(0,0,0,.12)}
.get.go{min-width:76px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);border-color:#2f7a17;background:var(--greenbtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.4)}
.get.blue{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);border-color:#2b4f8a;background:var(--bluebtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.4)}
.get[aria-expanded=true]{color:#7d8794;background:linear-gradient(#c9ced5,#dfe3e8);box-shadow:inset 0 1px 3px rgba(0,0,0,.3)}
.locked .get{min-width:44px}
.steps{background:linear-gradient(#f3f5f8,#fff);max-height:0;overflow:hidden;transition:max-height .28s ease} .steps.open{max-height:40rem;border-top:1px solid var(--sep)}
.step{display:flex;align-items:center;gap:10px;padding:8px 10px 8px 20px} .step+.step{border-top:1px dashed #d4d9df}
.step>div{flex:1;min-width:0} .step b{display:block;font-size:15px} .step small{display:block}
.num{flex:none;width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-size:13px;font-weight:700;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);
 background:var(--gloss),linear-gradient(#7f8a99,#5b6573);border:1px solid #4a525d}
.step.ok .num{background:var(--gloss),var(--greenbtn);border-color:#2f7a17;font-size:0} .step.ok .num:after{content:"✓";font-size:14px}
/* setup step 1: Stolen Device Protection, folds away once ticked (localStorage.sdp) */
details.c>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;font-weight:700} details.c>summary::-webkit-details-marker{display:none}
details.c>summary small{display:block;font-weight:400} details.c>summary>div{flex:1}
details.c>summary:after{content:"";flex:none;width:8px;height:8px;margin-right:4px;border:solid #7f8a99;border-width:3px 3px 0 0;transform:rotate(135deg);transition:transform .2s}
details.c[open]>summary:after{transform:rotate(-45deg)} details.c>summary,.dark details.c>summary{min-height:0;padding:0;background:none;box-shadow:none} details.c>:not(summary){margin:12px 0 0} details.c>.shot+.shot{margin-top:22px} details.c>.warn{margin-top:20px} details.c>small{display:block} /* margins, not gap: Safari ignores gap inside <details> */ details.c:not([open]){padding-block:10px}
.sh{display:flex;align-items:center;gap:10px;font-weight:700} .sh small{display:block;font-weight:400}
.ok>summary .num{background:var(--gloss),var(--greenbtn);border-color:#2f7a17;font-size:0} .ok>summary .num:after{content:"✓";font-size:14px}
.shot{display:flex;flex-direction:column;gap:6px} .shot figcaption{display:flex;gap:8px;align-items:center;font-size:15px} .shot .num{width:20px;height:20px;font-size:11px}
.shot img{display:block;width:100%;height:auto;border-radius:8px;border:1px solid var(--line);box-shadow:0 1px 3px rgba(0,0,0,.3)}
.warn{display:flex;gap:10px;align-items:flex-start;padding:10px;border-radius:8px;background:#fff8e1;border:1px solid #e6cf7a;font-size:14px}
button.gbtn{border-color:#2f7a17;background:var(--greenbtn)} /* not .green: that's the More tab's status panel */
fieldset{border:0;margin:0;padding:0;min-width:0} fieldset:disabled{opacity:.55;filter:grayscale(.6)}
.dark .warn{background:#3a3220;border-color:#6b5a26}
.nudge{animation:nudge .45s} @keyframes nudge{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
/* More tab: Cydia-style rows */
.green{background:#e9f8e4} .kv{display:flex;justify-content:space-between;gap:10px;padding:11px 12px;border-top:1px solid #d6e6cf} .kv span{color:var(--acc);text-align:right}
.split{display:grid;grid-template-columns:1fr 1fr;margin-top:12px} .pair{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.tile{display:flex;align-items:center;gap:9px;min-height:50px;padding:8px 10px;box-sizing:border-box;font-weight:700;color:#000;background:#fff;cursor:pointer;text-align:left;border:0;border-radius:0;box-shadow:none;text-shadow:none;line-height:1.35}
.split .tile+.tile{border-left:1px solid var(--sep)} .pair .tile{border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 0 rgba(255,255,255,.8)}
.tile:after{content:"";margin-left:auto;flex:none;width:8px;height:8px;border:solid #6f7a88;border-width:3px 3px 0 0;transform:rotate(45deg);margin-right:4px}
.tile:active{background:linear-gradient(#058cf5,#015fe6);color:#fff}
.tic{position:relative;flex:none;width:30px;height:30px;border-radius:7px;display:grid;place-items:center;box-shadow:0 1px 2px rgba(0,0,0,.4)}
.tic:after{content:"";position:absolute;inset:0;border-radius:inherit;background:var(--gloss)} .tic svg{width:19px;height:19px}
.out{margin-top:20px}
.sw{position:relative;flex:none;width:79px;height:27px}
.sw input{position:absolute;inset:0;width:100%;height:100%;margin:0;padding:0;opacity:0;cursor:pointer;z-index:2}
.sw i{position:absolute;inset:0;border:1px solid #a7a7a7;border-radius:14px;overflow:hidden;background:linear-gradient(#e6e6e6,#fefefe);box-shadow:inset 0 2px 3px rgba(0,0,0,.3);font-size:16px;font-weight:700;line-height:25px;font-style:normal}
.sw i:before{content:"ON";position:absolute;inset:0 auto 0 0;width:79px;padding-left:12px;box-sizing:border-box;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);
 background:linear-gradient(#1b68d8,#3f8cf3 55%,#5da1f6);transform:translateX(-79px);transition:transform .2s}
.sw i:after{content:"OFF";position:absolute;right:12px;color:#808080}
.sw .k{position:absolute;top:-1px;left:-1px;width:29px;height:29px;border-radius:50%;background:linear-gradient(#cfcfcf,#fcfcfc);border:1px solid #a3a3a3;box-sizing:border-box;
 box-shadow:0 1px 2px rgba(0,0,0,.3);transition:transform .2s;pointer-events:none}
.sw input:checked~i:before{transform:none} .sw input:checked~i:after{opacity:0} .sw input:checked~.k{transform:translateX(52px)}
.mini{border:1px solid var(--line);border-radius:8px;overflow:hidden}
.dark .get{color:#c9ced5;border-color:#111;box-shadow:inset 0 1px 0 rgba(255,255,255,.15)} .dark .get[aria-expanded=true]{color:#8b9099;background:linear-gradient(#1f2125,#2a2d32);box-shadow:inset 0 1px 3px #000}
.dark .steps{background:linear-gradient(#26292d,#2c2f34)} .dark .step+.step{border-top-color:#3a3d42}
.dark .green{background:#24302a} .dark .kv{border-top-color:#1a221d}
.dark .tile{background:linear-gradient(#34373d,#2a2d32);color:#e6e8eb} .dark .pair .tile{border-color:#0d0e10;box-shadow:0 1px 0 rgba(255,255,255,.06)} .dark .split .tile+.tile{border-left-color:#17191c} .dark .tile:after{border-color:#777}
.dark .sw i{border-color:#111;background:linear-gradient(#2b2e33,#3c4047);box-shadow:inset 0 1px 3px rgba(0,0,0,.8)} .dark .sw i:after{color:#9aa0a8}
.dark .sw i:before{background:linear-gradient(#0b4fb0,#3d8cf0)} .dark .sw .k{background:linear-gradient(#6a6f78,#3c4047);border-color:#111}
/* Changes tab: Cydia's plain list with sticky section strips (top is inside body's 56px padding, so -12px lands under the 44px nav) */
.cy{margin:-12px -10px 0;background:#fff;border-bottom:1px solid #d0d4d9}
.cyh{position:sticky;top:-12px;z-index:2;padding:1px 10px;font-size:19px;font-weight:700;color:#fff;text-shadow:0 1px 1px rgba(0,0,0,.5);
 background:linear-gradient(rgba(152,165,177,.92),rgba(184,193,201,.92));border-top:1px solid #8f9aa5;border-bottom:1px solid #a6afb8}
.cyr{display:flex;align-items:flex-start;gap:9px;padding:8px 10px;border-top:1px solid #e0e0e0} .cyh+.cyr{border-top:0}
.cyi{flex:none;width:30px;height:30px;margin-top:3px;border-radius:7px;object-fit:cover;display:grid;place-items:center;color:#fff;font-weight:700;font-size:15px;box-shadow:0 1px 2px rgba(0,0,0,.35)}
.cyt{flex:1;min-width:0} .cyt b{display:block;font-size:19px;line-height:1.2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cyt small{display:block;padding-left:12px;color:#000;font-size:13px} .cyt p{margin:2px 0 0;color:#6d7480;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cyr .get{align-self:center}
.dark .cy{background:#2c2f34;border-color:#0d0e10} .dark .cyr{border-color:#3a3d42} .dark .cyt small{color:#c9ced5}
.dark .cyh{background:linear-gradient(rgba(86,92,102,.94),rgba(58,62,70,.94));border-color:#111}
/* iOS 5 red count badge on the Changes tab */
.badge{position:absolute;top:-2px;left:calc(50% + 4px);min-width:22px;height:22px;padding:0 6px;box-sizing:border-box;border-radius:11px;border:2px solid #fff;color:#fff;
 font:700 13px/18px "Helvetica Neue",Helvetica,sans-serif;text-align:center;background:linear-gradient(#ff7b7b,#e60000 50%,#cc0000 51%,#d40000);box-shadow:0 1px 3px rgba(0,0,0,.6)}
/* Cydia tab bar */
.tabs{position:fixed;left:0;right:0;bottom:0;z-index:5;display:grid;grid-template-columns:repeat(5,1fr);gap:4px;
 padding:2px max(4px,env(safe-area-inset-right)) calc(2px + env(safe-area-inset-bottom)) max(4px,env(safe-area-inset-left));
 background:linear-gradient(#3a3a3a,#1a1a1a 50%,#000 51%,#0a0a0a);border-top:1px solid #000;box-shadow:inset 0 1px 0 rgba(255,255,255,.12)}
.tabs a{position:relative;display:grid;justify-items:center;gap:1px;padding:4px 0 3px;border-radius:3px;color:#999;font-size:10px;font-weight:700}
.tabs svg{width:30px;height:30px;fill:#8d8d8d}
.tabs a[aria-current]{background:rgba(255,255,255,.14);color:#fff;box-shadow:inset 0 1px 0 rgba(255,255,255,.08)}
.tabs a[aria-current] svg{fill:url(#tabglow);filter:drop-shadow(0 0 3px rgba(88,170,255,.7))}
</style>
{% if error %}<p class="c err">{{ error }}</p>{% endif %}
{% set enroll_form %}<form method=post action=/enroll style="display:flex;flex-direction:column;gap:10px"
 onsubmit="document.getElementById('next').hidden=false;this.querySelector('button').textContent='Check the popup…'">
<input name=name required maxlength=30 placeholder="Your name" aria-label="Your name" autocomplete=given-name
 oninput="this.form.querySelector('button').disabled=!this.value.trim()"><button disabled>Register iPhone</button></form>
<ol id=next hidden><li>Tap <b>Allow</b>, then <b>Close</b>.</li><li>Open the <b>Settings</b> app.</li>
<li>Tap <b>Profile Downloaded</b> near the top.</li><li>Tap <b>Install</b>, enter your passcode, tap <b>Install</b> again.</li>
<li>You'll land back here automatically, registered.</li></ol>{% endset %}
{% set sdp_steps %}<figure class=shot><figcaption><span class=num>a</span><span>Settings → <b>Face ID &amp; Passcode</b></span></figcaption>
<img src=/static/sdp1.jpg alt="Settings with Face ID and Passcode circled" width=640 height=277></figure>
<figure class=shot><figcaption><span class=num>b</span><span>Tap <b>Stolen Device Protection</b></span></figcaption>
<img src=/static/sdp2.jpg alt="The Stolen Device Protection row circled" width=640 height=167></figure>
<figure class=shot><figcaption><span class=num>c</span><span>Turn it <b>off</b></span></figcaption>
<img src=/static/sdp3.jpg alt="The Stolen Device Protection switch turned off, circled" width=640 height=291></figure>
<div class=warn><span aria-hidden=true>⏳</span><div>Asked to wait an hour? Do this at home, where there's no wait.</div></div>
{% endset %}
{% macro install(a) %}{% if not enrolled %}<a class=get aria-label="Register first" href=#apps onclick="return nudge()">🔒</a>
{% elif a.files %}<button type=button class=get aria-expanded=false onclick="steps(this)">GET</button>
{% else %}<a class=get data-arm=GET data-app="{{ a.name }}" aria-label="Install {{ a.title }}" href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}" onclick="return arm(this)">GET</a>{% endif %}{% endmacro %}
{% macro install_list(apps) %}<div class="g{{ '' if enrolled else ' locked' }}">{% for a in apps %}
<div class=row>{% if a.icon %}<img class=ico src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=ico style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}
<div>{{ a.title }}<small>Version {{ a.short }}{% if a.files %} · needs {{ a.files|length }} file{{ 's' if a.files|length > 1 }}{% endif %}</small></div>{{ install(a) }}</div>
{% if enrolled and a.files %}{% set labels = file_labels(a.files[0].parent) %}<div class=steps>
<div class=step><span class=num>1</span><div><b>Install the app</b></div><a class="get go" data-app="{{ a.name }}" aria-label="Install {{ a.title }}" onclick="mark(this);this.closest('.step').classList.add('ok')"
 href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">INSTALL</a></div>
{% for f in a.files %}<div class=step><span class=num>{{ loop.index + 1 }}</span><div><b>Download {{ labels.get(f.name, f.name) }}</b>
<small>{% if f.name in labels %}{{ f.name }} · {% endif %}{{ '%.1f'|format(f.stat().st_size/1e6) }} MB · save to Files</small></div>
<a class="get blue" href="{{ adl(f) }}" onclick="this.closest('.step').classList.add('ok')">DOWNLOAD</a></div>{% endfor %}</div>{% endif %}
{% endfor %}</div>{% endmacro %}

<section class=page id=t-apps data-title=sidedrop>
<div class=splash><img src=/apple-touch-icon.png alt=""><div><h2>Welcome to sidedrop</h2><p>by <a href="https://github.com/RyanAHayden">Ryan Hayden</a></p></div></div>
{% if just_enrolled %}<div class=scrim id=welcome onclick="if(event.target==this)welcomeOk()"><div class=alert role=alertdialog aria-modal=true aria-labelledby=welT>
<h3 id=welT>Setup Complete</h3><p>This iPhone is registered. Enjoy!</p><p>Tap GET to install apps.</p>
<div class=abtns style="grid-template-columns:1fr"><button type=button class=ok onclick="welcomeOk()">OK</button></div></div></div>
<script>function welcomeOk(){welcome.hidden=true;history.replaceState(null,"","/")}</script>{% endif %}
{% if not enrolled %}<h3 class=hdr>First, set up this iPhone</h3>
<details class=c id=sdp open><summary><span class=num>1</span><div>Turn off Stolen Device Protection</div></summary>
{{ sdp_steps }}
<button type=button class=gbtn onclick="sdpDone(true)">I turned it off</button></details>
<div class=c id=reg><div class=sh><span class=num>2</span><div>Register this iPhone<small>In Safari on this iPhone</small></div></div>
<fieldset id=regf disabled>{{ enroll_form }}</fieldset><small>Registered before but the apps are locked? Register again, it's instant.</small></div>{% endif %}
<h3 class=hdr>Apps</h3>{% if apps %}{{ install_list(apps) }}{% else %}<p class="c m">No apps yet.</p>{% endif %}
{% if third %}<h3 class=hdr>Third-party apps</h3>{{ install_list(third) }}<p class=ftr>Made by other people, mirrored from their sources.</p>{% endif %}
</section>

{% macro cyrow(a, up) %}<div class="cyr{{ ' up' if up }}">{% if a.icon %}<img class=cyi src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=cyi style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}
<div class=cyt><b>{{ a.title }}</b><small>from {{ a.source }} · {{ a.short }}</small>{% if a.desc %}<p>{{ a.desc }}</p>{% endif %}</div>
{% if up %}<a class=get data-arm=UPDATE data-app="{{ a.name }}" aria-label="Update {{ a.title }}" href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}" onclick="return arm(this)">UPDATE</a>{% endif %}</div>{% endmacro %}
<section class=page id=t-changes data-title=Changes><div class=cy>
{% if updates %}<div class=cyh id=uph>Available Upgrades</div>{% for a in updates %}{{ cyrow(a, True) }}{% endfor %}{% endif %}
{% for day, group in recent %}<div class=cyh>New at {{ day.strftime('%b %-d, %Y') }}</div>{% for a in group %}{{ cyrow(a, False) }}{% endfor %}{% endfor %}</div>
{% if not recent %}<p class="c m">No apps yet.</p>{% endif %}
<p class=ftr>{% if enrolled %}Upgrades show for apps you installed from here on this iPhone.{% else %}Register this iPhone to get upgrades.{% endif %}</p>
<div class=scrim id=upq hidden onclick="if(event.target==this)this.hidden=true"><div class=alert role=alertdialog aria-modal=true aria-labelledby=upqT>
<h3 id=upqT>Upgrade</h3><p id=upqL></p><div class=abtns><button type=button onclick="upq.hidden=true">Cancel</button><button type=button class=ok onclick="upgradeGo()">Confirm</button></div></div></div>
</section>

<section class=page id=t-feather data-title=Feather>
<h3 class=hdr>Feather</h3><div class="g{{ '' if enrolled else ' locked' }}">{% for a in feather %}
<div class=row><div class=ico style="background:linear-gradient(#ffd27a,#e08a12)"><svg viewBox="0 0 24 24" width=28 height=28 fill="#fff"><path d="M20 3c-8 1-13 6-14 14l-2 4 1 1 4-2c8-1 12-6 13-14-2 2-5 3-8 3 2-1 5-3 6-6z"/></svg></div>
<div>Feather<small>On-device signer · Version {{ a.short }}</small></div>{{ install(a) }}</div>{% else %}<div class=row><div class=m>Feather isn't mirrored right now.</div></div>{% endfor %}</div>
<p class=ftr>Installs and re-signs IPAs on the iPhone. It needs your own Apple certificate. <a href="{{ FEATHER_REPO }}">GitHub</a></p>
{% if sources %}<h3 class=hdr>Sources</h3><div class=c>
<textarea id=src readonly rows={{ sources|length }} wrap=off aria-label="Sources to add in Feather">{{ sources|join('\n') }}</textarea>
<button type=button class=grey onclick="navigator.clipboard.writeText(src.value).then(()=>this.textContent='Copied ✓',()=>src.select())">Copy sources</button></div>{% endif %}
</section>

<section class=page id=t-files data-title=Files>
<h3 class=hdr>Files</h3>{% if files %}<div class=g>{% for f in files %}
<div class=row><div>{{ f.relative_to(FILES) }}<small>{{ '%.1f'|format(f.stat().st_size/1e6) }} MB · link works without login for 7 days</small></div><a class="get blue" href="{{ dl(f) }}">DOWNLOAD</a></div>
{% endfor %}</div>{% else %}<p class="c m">No files right now.</p>{% endif %}
<p class=ftr>Game discs are under each app's GET.</p>
</section>

<section class=page id=t-more data-title=More>
<h3 class=hdr>This iPhone</h3><div class="g green">
<div class=kv><b>Status</b><span>{{ 'Registered' if enrolled else 'Not registered' }}</span></div>
{% if stats %}<div class=kv><b>iPhones used</b><span>{{ stats[0] }} of 100</span></div>
{% if stats[1] %}<div class=kv><b>Apps work until</b><span>{{ stats[1].strftime('%b %-d, %Y') }}</span></div>{% endif %}{% endif %}</div>
{% if enrolled %}<p class=ftr>This iPhone is registered and can install every app.</p>{% endif %}
<div class="g split">
{% if enrolled %}<button type=button class=tile onclick="let d=document.getElementById('other');d.open=true;d.scrollIntoView({behavior:'smooth'})">{% else %}<a class=tile href=#apps>{% endif %}
<span class=tic style="background:linear-gradient(#8fd96b,#3c9a1d)"><svg viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2" fill="#fff"/><rect x="8.5" y="5" width="7" height="12" fill="#3c9a1d"/></svg></span>Register{% if enrolled %}</button>{% else %}</a>{% endif %}
<button type=button class=tile onclick="document.getElementById('sign').scrollIntoView({behavior:'smooth'})"><span class=tic style="background:linear-gradient(#b7c0cc,#5d6878)"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"><path d="M4 20c3-1 5-4 7-4s1 3 3 3 3-2 6-3M15 4l5 5-8 8H7v-5z"/></svg></span>Sign IPA</button></div>
<div class=pair>
<button type=button class=tile onclick="let d=document.getElementById('dev');d.open=true;d.scrollIntoView({behavior:'smooth'})"><span class=tic style="background:linear-gradient(#bfc4c9,#5f666e)"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.4" stroke-dasharray="2.4 2"><circle cx="12" cy="12" r="7"/></svg></span>Help</button>
<button type=button class=tile onclick="about.hidden=false;about.querySelector('.ok').focus()"><span class=tic style="background:linear-gradient(#8fc6ff,#2a72d6)"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="#fff"/><path d="M12 10v7M12 6.5v1" stroke="#2a72d6" stroke-width="2.6" stroke-linecap="round"/></svg></span>About</button></div>
<h3 class=hdr>Display</h3><div class=g><div class=row><div>Dark Mode</div><label class=sw><input type=checkbox id=darkSw aria-label="Dark Mode"
 onchange="try{localStorage.dark=this.checked?1:0}catch(e){}theme()"><i></i><span class=k></span></label></div></div>
<h3 class=hdr>Help</h3><div class=g>
<details id=dev><summary>Turn on Developer Mode</summary>
<p class=m>Needed once per iPhone for apps not from the App Store.</p>
<ol><li>Install an app first. The switch only shows up after that.</li>
<li>Open Settings → Privacy &amp; Security → <b>Developer Mode</b> (near the bottom) → turn it on → <b>Restart</b>.</li>
<li>After the restart, tap <b>Turn On</b> and enter your passcode. The apps open normally from then on.</li></ol>
<div class=mini><div class=row><div>Developer Mode</div><label class=sw><input type=checkbox checked aria-label="Developer Mode (example of the switch)"><i></i><span class=k></span></label></div></div></details>
{% if enrolled %}<details><summary>Turn off Stolen Device Protection</summary>{{ sdp_steps }}</details>
<details id=other><summary>Register a different iPhone</summary><p class=m>Turn off Stolen Device Protection on that iPhone first.</p>{{ enroll_form }}</details>{% endif %}</div>
<h3 class=hdr id=sign>Sign your own IPA</h3>
<form class=c method=post action=/sign enctype=multipart/form-data onsubmit="this.querySelector('button').textContent='Signing…'">
<label class=drop>Drop an .ipa here or tap to browse<input type=file name=ipa accept=.ipa></label>
<input type=url name=url placeholder="…or paste a link to an .ipa" aria-label="Link to an .ipa">
<button>Sign</button><small>Signed for registered iPhones. The install link lasts 7 days.</small></form>
<a class="b grey out" href=/logout>Sign out</a>
</section>

<nav class=tabs aria-label=Sections>
<a href=#apps><svg viewBox="0 0 30 30"><path d="M4 4h9v9H4zm13 0h9v9h-9zM4 17h9v9H4zm13 0h9v9h-9z"/></svg>Apps</a>
<a href=#changes><svg viewBox="0 0 30 30"><path fill-rule=evenodd d="M15 3a12 12 0 1 0 0 24a12 12 0 1 0 0-24zm0 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18z"/><path d="M14 8h2.4v6.8l4.8 3.1-1.3 2-5.9-3.8z"/></svg>Changes<span class=badge id=badge{% if not updates %} hidden{% endif %}>{{ updates|length }}</span></a>
<a href=#feather><svg viewBox="0 0 30 30"><path d="M25 4c-10 1-16 8-17 17l-3 5 1 1 5-3c10-1 15-7 16-17-3 2-6 4-10 4 3-1 6-4 8-7z"/></svg>Feather</a>
<a href=#files><svg viewBox="0 0 30 30"><path d="M3 7h10l3 3h11v15H3z"/></svg>Files</a>
<a href=#more><svg viewBox="0 0 30 30"><circle cx="7" cy="15" r="3"/><circle cx="15" cy="15" r="3"/><circle cx="23" cy="15" r="3"/></svg>More</a></nav>
<svg width=0 height=0 style="position:absolute" aria-hidden=true><linearGradient id=tabglow x1=0 y1=0 x2=0 y2=1><stop offset=0 stop-color="#cfe9ff"/><stop offset=.5 stop-color="#5fb4ff"/><stop offset=.51 stop-color="#1d8af2"/><stop offset=1 stop-color="#3fa0ff"/></linearGradient></svg>
<script>
function show(){let t=location.hash.slice(1);if(!document.getElementById("t-"+t))t="apps";
 document.querySelectorAll(".page").forEach(p=>p.hidden=p.id!="t-"+t);
 document.querySelectorAll(".tabs a").forEach(a=>a.getAttribute("href")=="#"+t?a.setAttribute("aria-current","page"):a.removeAttribute("aria-current"));
 navT.textContent=document.getElementById("t-"+t).dataset.title;document.body.scrollTo(0,0);navR()}
/* on Changes the right nav button is Cydia's "Upgrade (n)" */
function navR(){let n=document.querySelectorAll(".cyr.up").length,r=document.querySelector(".nav .bar.r"),c=location.hash=="#changes"&&n;
 r.textContent=c?"Upgrade ("+n+")":"Reload";r.onclick=c?upgradeAll:reloadData;badge.textContent=n;badge.hidden=!n;let h=document.getElementById("uph");if(h)h.hidden=!n}
function mark(b){let n=b.dataset.app;if(!n)return;navigator.sendBeacon("/installed",new URLSearchParams({name:n}));
 setTimeout(()=>{document.querySelectorAll('.cyr.up [data-app="'+n+'"]').forEach(x=>x.closest(".cyr").remove());navR()},500)}  // after the link has followed: a removed link doesn't navigate
function upgradeAll(){let l=[...document.querySelectorAll(".cyr.up b")].map(b=>b.textContent);upqT.textContent="Upgrade "+l.length+(l.length>1?" Apps":" App");upqL.textContent=l.join(", ");upq.hidden=false}
/* ponytail: one install link every 3 s; iOS shows one install prompt per link, re-tap UPDATE on any it drops */
function upgradeGo(){upq.hidden=true;[...document.querySelectorAll(".cyr.up a.get")].map(b=>[b,b.href]).forEach(([b,h],i)=>setTimeout(()=>{mark(b);location.href=h},i*3000))}
addEventListener("hashchange",show);
function disarm(keep){document.querySelectorAll(".get.go[data-arm]").forEach(b=>{if(b!=keep){b.classList.remove("go");b.textContent=b.dataset.arm}})}
function arm(b){if(b.classList.contains("go")){mark(b);setTimeout(()=>disarm(),1500);return true}disarm(b);b.classList.add("go");b.textContent="INSTALL";return false}
addEventListener("click",e=>{if(!e.target.closest("[data-arm]"))disarm()});
function steps(b){let open=b.getAttribute("aria-expanded")!="true";b.setAttribute("aria-expanded",open);b.closest(".row").nextElementSibling.classList.toggle("open",open)}
function sdpDone(save){let d=document.getElementById("sdp");if(!d)return;d.classList.add("ok");d.open=false;regf.disabled=false;
 if(save){try{localStorage.sdp=1}catch(e){}regf.querySelector("input").focus()}}
try{if(localStorage.sdp)sdpDone()}catch(e){}
function nudge(){location.hash="apps";let r=document.querySelector("#sdp:not(.ok)")||document.getElementById("reg");if(r.open===false)r.open=true;r.classList.remove("nudge");void r.offsetWidth;r.classList.add("nudge");if(r.id=="reg")r.querySelector("input").focus();return false}
show();
addEventListener("pageshow",()=>{document.querySelectorAll("input[name=name]").forEach(i=>i.oninput());theme();darkSw.checked=document.documentElement.classList.contains("dark")});
</script>""", error=error, enrolled=enrolled, updates=updates, recent=recent, just_enrolled=enrolled and bool(request.args.get("enrolled")), apps=apps, third=third, files=files, FILES=FILES, feather=feather, FEATHER_REPO=FEATHER_REPO,
        sources=read_urls("feather-sources.txt"),
        manifest=lambda n: quote(signed_url(f"/m/{n}.plist"), safe=""),
        dl=lambda f: signed_url(f"/f/{f.relative_to(FILES)}"), adl=lambda f: signed_url(f"/af/{f.relative_to(APP_FILES)}"),
        file_labels=file_labels))
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


@app.post("/installed")
def mark_installed():
    """INSTALL tapped: remember this phone has the current version, so the Changes tab can offer later ones."""
    udid, p = token_udid(request.cookies.get("device", "")), SIGNED / f"{request.form.get('name', '')}.ipa"
    if not logged_in() or not udid or p.parent != SIGNED or not p.is_file():
        abort(403)
    i = ipa_info(p)
    with installed_lock:
        data = installed()
        data.setdefault(udid, {})[p.stem] = f"{i['short']}/{i['version']}"
        tmp = INSTALLED.with_suffix(".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(INSTALLED)
    return "", 204


@app.post("/refresh")
def refresh():
    """Reload button: pull new releases from the sources and re-sign now, while the "Reloading Data" HUD shows."""
    if not logged_in():
        abort(403)
    with sync_lock:  # waits out a background sync already running, then does a full one, so the HUD stays up until it's done
        last_sync[0] = time.time()
        try:
            sync_sources()
        except Exception as e:
            print("source sync failed:", e, flush=True)
    with lock:
        resign()
    return "", 204


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
