"""sidedrop: password-gated UDID enrollment, ad hoc OTA installs and private file downloads."""
import base64, datetime, gzip, hashlib, hmac, itertools, json, os, plistlib, re, secrets, subprocess, threading, time, uuid, zipfile, zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import jwt, requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from pywebpush import WebPushException, webpush
from flask import Flask, abort, make_response, redirect, render_template_string, request, send_from_directory, session, url_for

DATA = Path(os.environ.get("DATA", "/data"))
APPS, SIGNED = DATA / "apps", DATA / "signed"
APP_FILES = DATA / "appfiles"  # appfiles/<ipa name>/* are listed under that app's Install button
CUSTOM = SIGNED / "custom"  # one-off IPAs friends upload or link on the page
HERE = Path(__file__).parent  # config files edited on GitHub; the NAS pulls and rebuilds (deploy.sh)
read_urls = lambda f: [u for u in (HERE / f).read_text().split() if u.startswith(("https://", "http://"))] if (HERE / f).exists() else []
IFIZBOX_SOURCES = "ifizbox-sources.txt"  # the sources iFizBox starts with (ifizbox_transfer)
IFIZBOX_ID = "com.ryha.ifizbox"  # signed with our certificate and sources inside it (ifizbox_identity, ifizbox_transfer)
INSTALLS = {}  # ponytail: in memory (one gunicorn worker); {token: {"at", "manifest", "started"}}: iOS's requests, for the install page
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
SYNC_TOKEN = os.environ.get("SYNC_TOKEN", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")  # unlocks /admin (disable iPhones); unset = no admin page  # lets CI hit POST /sync after a release
PROFILE_CERT_DIR = os.environ.get("PROFILE_CERT_DIR", "")  # dir with fullchain.pem + privkey.pem; iOS then shows "Verified"

app = Flask(__name__)
app.jinja_env.filters["hue"] = lambda s: zlib.crc32(s.encode()) % 360  # stable icon color per app
app.secret_key = SECRET
app.config.update(SESSION_COOKIE_SECURE=PUBLIC_URL.startswith("https"), SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=10 * 365 * 86400)
lock = threading.Lock()  # ponytail: one global lock for ASC + signing, fine for a handful of friends
INSTALLED, installed_lock = DATA / "installed.json", threading.Lock()  # {udid: {app: "short/build"}} from INSTALL taps, for Changes
PUSH, push_lock = DATA / "push.json", threading.Lock()  # {endpoint: {sub, udid, sent: {app: "short/build"}}} web push subscriptions
VAPID = DATA / "vapid.pem"  # web push signing key, made on first use
SEEN = DATA / "seen.json"  # {udid: unix time} last page load per registered iPhone, for the admin page


def load_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def save_json(path, data):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data))
    tmp.replace(path)


installed = lambda: load_json(INSTALLED)


def touch_seen(udid):
    with installed_lock:
        seen = load_json(SEEN)
        if time.time() - seen.get(udid, 0) > 3600:  # ponytail: hourly granularity keeps this to one write an hour per phone
            seen[udid] = int(time.time())
            save_json(SEEN, seen)


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


def retarget(src, dst, old_id, new_id, extra={}):
    """Copy an IPA, swapping the old bundle ID prefix for the new one in the app's and its extensions' Info.plists,
    and adding extra {file name: bytes} into the .app."""
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
        app_dir = next(n for n in zin.namelist() if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n))[:-len("Info.plist")]
        for name, data in extra.items():
            zout.writestr(app_dir + name, data)
        for item in zin.infolist():
            if item.filename[len(app_dir):] in extra and item.filename.startswith(app_dir):
                continue
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


def ifizbox_identity():
    """iFizBox's sideload build imports this file from its bundle into the Keychain on first launch (its
    BundledIdentity), so friends never pick a certificate: our .p12, its password and the ad hoc profile."""
    return plistlib.dumps({"p12": P12.read_bytes(), "password": P12_PASSWORD, "profile": PROFILE.read_bytes()})


def ifizbox_transfer():
    """iFizBox imports web/transfer.link from its bundle once, on first launch: ifizbox://import?d=<base64url of gzipped JSON>
    (iFizBox's core/transfer.js), here only our sources."""
    payload = {"v": 1, "sources": read_urls(IFIZBOX_SOURCES), "settings": {}, "holds": []}
    return "ifizbox://import?d=" + base64.urlsafe_b64encode(gzip.compress(json.dumps(payload).encode())).decode().rstrip("=")


def sign_ipa(src, out):
    old_id = ipa_info(src)["id"]
    new_id = fit_bundle_id(old_id)
    extra = {"ifizbox-identity.plist": ifizbox_identity(), "web/transfer.link": ifizbox_transfer().encode()} if old_id == IFIZBOX_ID else {}
    rewrite = bool(new_id or extra)
    tmp = out.with_name(f".{out.name}.in") if rewrite else src
    if rewrite:  # rewrite ourselves: zsign 1.1.2's -b can't find Info.plist
        retarget(src, tmp, old_id, new_id or old_id, extra)
    ents = out.with_name(f".{out.name}.entitlements.plist")
    ents.write_bytes(plistlib.dumps(app_entitlements(new_id or old_id)))
    try:
        subprocess.run(["zsign", "-q", "-t", out.parent, "-k", P12, "-p", P12_PASSWORD, "-m", PROFILE,
                        "-e", ents, "-o", out, tmp], check=True, timeout=600)
    finally:
        ents.unlink(missing_ok=True)
        if rewrite:
            tmp.unlink(missing_ok=True)


def resign(force=False):
    """Sign every apps/*.ipa whose signed copy is missing or older than the IPA or profile."""
    if not PROFILE.exists():
        return
    SIGNED.mkdir(exist_ok=True)
    for src in sorted(APPS.glob("*.ipa")):
        out = SIGNED / src.name
        deps = [src, PROFILE] + [p for p in [HERE / IFIZBOX_SOURCES] if src.stem == IFIZBOX_ID and p.exists()]  # its sources are inside it
        if force or not out.exists() or out.stat().st_mtime < max(d.stat().st_mtime for d in deps):
            sign_ipa(src, out)


def sync_sources():
    """Download the newest IPA of each app in SOURCES when its version changes. Sources are fetched in parallel,
    so Reload waits about as long as the slowest one."""
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(lambda s: sync_source(*s), SOURCES))  # list() re-raises the first failure


def sync_source(url, ids, third):
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


def vapid_public():
    """Base64url public key the browser subscribes with; the private half signs each push."""
    if not VAPID.exists():
        VAPID.write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub = serialization.load_pem_private_key(VAPID.read_bytes(), None).public_key()
    return base64.urlsafe_b64encode(pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)).rstrip(b"=").decode()


def pending(udid, vers):
    """Apps this phone installed that now have a newer signed version: {name: vkey}."""
    mine = installed().get(udid, {})
    return {n: vers[n]["vkey"] for n in mine if n in vers and mine[n] != vers[n]["vkey"]}


def signed_versions():
    vers = {p.stem: ipa_info(p) for p in SIGNED.glob("*.ipa")} if SIGNED.exists() else {}
    for n, i in vers.items():
        third = APPS / f".{n}.third"
        i["vkey"], i["title"] = f"{i['short']}/{i['version']}", (third.read_text().strip() if third.exists() else "") or i["title"]
    return vers


def notify_upgrades():
    """One notification per phone for upgrades it hasn't been told about yet; dead subscriptions are dropped."""
    with push_lock:
        subs, vers = load_json(PUSH), signed_versions()
        for ep, s in list(subs.items()):
            new = {n: v for n, v in pending(s["udid"], vers).items() if s["sent"].get(n) != v}
            if not new:
                continue
            names = [vers[n]["title"] for n in new]
            body = f"{names[0]} {vers[next(iter(new))]['short']} is available." if len(new) == 1 else f"New versions of {', '.join(names)}."
            try:
                webpush(s["sub"], json.dumps({"title": "Update Available" if len(new) == 1 else f"{len(new)} Updates Available", "body": body, "url": "/#changes"}),
                        vapid_private_key=str(VAPID), vapid_claims={"sub": PUBLIC_URL}, timeout=10)
            except WebPushException as e:
                if e.response is not None and e.response.status_code in (404, 410):  # unsubscribed or app removed
                    del subs[ep]
                else:
                    print("push failed:", e, flush=True)
                continue
            s["sent"].update(new)
        save_json(PUSH, subs)


def resign_and_notify():
    try:
        with lock:
            resign()
        notify_upgrades()
    except Exception as e:
        print("resign/notify failed:", e, flush=True)


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
        resign_and_notify()  # so phones hear about a release without anyone opening the page first
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

BUILD = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12]  # changes with every deploy of the page's code; an open page that sees a new one reloads

PAGE = """<!doctype html><meta charset=utf-8><meta name=build content=%BUILD%><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<title>sidedrop</title><meta name=description content="Apps shared between friends, signed for your iPhone.">
<meta property=og:title content=sidedrop><meta property=og:description content="Apps shared between friends, signed for your iPhone."><meta property=og:site_name content=sidedrop>
<meta property=og:type content=website><meta property=og:url content="%PUBLIC_URL%/"><meta property=og:image content="%PUBLIC_URL%/static/og.png"><meta property=og:image:width content=1200><meta property=og:image:height content=630>
<meta name=twitter:card content=summary_large_image><meta name=twitter:image content="%PUBLIC_URL%/static/og.png"><link rel=apple-touch-icon href=/apple-touch-icon.png><link rel=manifest href=/manifest.webmanifest><meta name=theme-color content="#bdcbdc"><meta name=apple-mobile-web-app-status-bar-style content=black><meta name=apple-mobile-web-app-title content=sidedrop>
<script>/* Dark Mode follows the phone's theme until the Settings switch picks one (localStorage.dark = "1"/"0") */
function theme(){let d=null;try{d=localStorage.dark}catch(e){}let on=document.documentElement.classList.toggle("dark",d?d=="1":matchMedia("(prefers-color-scheme: dark)").matches);
 document.querySelector("meta[name=theme-color]").content=on?"#5f656f":"#bdcbdc"}  /* Safari's top bar matches the nav */
theme();matchMedia("(prefers-color-scheme: dark)").addEventListener("change",theme)</script>
<style>
/* 2012 iOS look (pinstripes, glossy bars, App Store buttons), with a gunmetal Dark Mode below. */
:root{color-scheme:light;--mute:#6d7480;--sep:#e0e0e0;--line:#b7b9bd;--acc:#385487;--head:#4c566c;
 --pin:repeating-linear-gradient(90deg,#cbd0da 0 2.5px,#ced3dc 2.5px 8px);--gloss:linear-gradient(rgba(255,255,255,.55),rgba(255,255,255,.12) 50%,rgba(255,255,255,0) 51%);
 --tabh:calc(49px + env(safe-area-inset-bottom));--navbg:linear-gradient(#bdcbdc,#597498);--statbg:linear-gradient(#4f698b,#3f5b7f);--navhi:#eff2f7;--navedge:#2d3642;--table:#f7f7f7;--div:#c9c9c9;--divhi:#fff;--barbtn:linear-gradient(#99aac2,#41618e);  /* iOS 6 UIKit nav art: smooth, no gloss split */
 --bluebtn:linear-gradient(#7aa5ef,#3b72d4 50%,#2861c9 51%,#3a73da);--greenbtn:linear-gradient(#8fd96b,#4caa2b 50%,#3c9a1d 51%,#4cae2a);
 --greybtn:linear-gradient(#fdfdfd,#e3e6ea);--emboss:0 1px 0 rgba(255,255,255,.75);--chev:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 17.5 26.4'%3E%3Cpath fill='%237f7f7f' d='M.07 4.23 9.12 13.27 0 22.26 4.12 26.38 17.47 13.03 4.43 0Z'/%3E%3C/svg%3E");background:#c8cfd6}
/* fixed backdrop: stays put while iOS rubber-bands the page, so the bounce shows pinstripes instead of a flat color */
body::before{content:"";position:fixed;inset:0;z-index:-1;background:var(--pin)}
/* always 1px taller than the screen, so short pages still rubber-band like native */
#scr{scrollbar-width:none} #scr::-webkit-scrollbar{display:none} .page{min-height:calc(100% + 1px)}
/* scroll indicator, drawn by us between the nav and tab bar (iOS doesn't show one for a scrolling body) */
/* UIKit's UIScrollerIndicatorDefault: 5pt black at 50% with a 1pt 15% white ring, fully rounded (7pt overall) */
#sb{position:fixed;right:2px;z-index:6;width:5px;border-radius:3px;background:rgba(0,0,0,.5);box-shadow:0 0 0 1px rgba(255,255,255,.15);opacity:0;transition:opacity .3s;pointer-events:none}
/* the pages scroll in #scr, a fixed full-screen box, as iFizBox's screens do; <html> and <body> never scroll, and the bars and alerts are outside
   it, above. iOS 26 blurs the top edge of a scroller in the home-screen app, with no switch for it: over a nav bar inside the scroller, or the
   whole page, that washed the bar out; under an opaque bar on top it doesn't show. A fixed box also follows the screen through a rotation, where
   body at 100% went stale (top cut off, bars not taking taps). */
html,body{height:100%;overflow:hidden;margin:0}
body{font:17px/1.35 "Helvetica Neue",Helvetica,Arial,sans-serif;color:#000;-webkit-font-smoothing:antialiased}
#scr{position:fixed;inset:0;box-sizing:border-box;overflow-y:auto;overscroll-behavior:contain;
 padding:calc(56px + env(safe-area-inset-top)) max(10px,env(safe-area-inset-right),(100% - 30rem)/2) calc(72px + env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left),(100% - 30rem)/2)}
a{color:var(--acc);text-decoration:none} small,.m{color:var(--mute)} small{font-size:13px} .err{color:#d70015} h2{font-size:19px;margin:0}
html{touch-action:manipulation} /* no double-tap zoom; pinch is blocked by the viewport and gesturestart */
button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #f5c542;outline-offset:2px}
.nav{position:fixed;top:0;left:0;right:0;z-index:5;height:44px;padding:env(safe-area-inset-top) max(7px,env(safe-area-inset-right)) 0 max(7px,env(safe-area-inset-left));
 display:grid;grid-template-columns:1fr auto 1fr;align-items:center;
 background:linear-gradient(var(--navedge),var(--navedge)) bottom/100% 1px no-repeat,linear-gradient(var(--navhi),var(--navhi)) 0 env(safe-area-inset-top)/100% 1px no-repeat,var(--navbg) bottom/100% 44px no-repeat,var(--statbg)}
/* the kit's nav shadow: 2.5px of black at 18% fading down over the page */
.nav:after{content:"";position:absolute;left:0;right:0;top:100%;height:2.5px;pointer-events:none;background:linear-gradient(rgba(0,0,0,.18),rgba(0,0,0,0))}
.nav h1{margin:0;font-size:20px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45)}
.nav .bar{justify-self:start;width:auto;font-size:12px;font-weight:700;line-height:1.2;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45);background:var(--barbtn);border:1px solid #2f4769;border-top-color:#343a42;
 border-radius:5px;padding:6px 10px;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 1px 0 rgba(255,255,255,.25)} .nav .bar.r{justify-self:end}
/* iOS 6 back button: arrow art drawn after UIKit's UINavigationBarDefaultBack, stretched through the middle */
.nav .back{display:inline-flex;align-items:center;height:30px;box-sizing:border-box;max-width:40vw;overflow:hidden;white-space:nowrap;padding:0 5px 0 1px;background:none;box-shadow:none;border-radius:0;
 border:solid transparent;border-width:0 5px 0 13px;border-image:url(/static/back.svg) 0 10 0 26 fill/0 5px 0 13px} .nav .back.is-pressed{border-image-source:url(/static/back-pressed.svg)} .dark .nav .back.is-pressed{filter:brightness(.75)}
/* pressed states (UIKit's *Pressed art), on .is-pressed: the script below sets it while a finger is down */
.nav .bar:not(.back).is-pressed{background:linear-gradient(#8b97af,#283e6b);border-color:#1c2c4f;border-top-color:#30343c}
.dark .nav .bar:not(.back).is-pressed{background:linear-gradient(#2a2d32,#121316)}
/* held buttons, from the 4S art: white/grey round buttons go blue (iTunesStoreUI GradientButtonBackgroundPressed, same as the tiles);
   blue and green darken the way PurchaseButtonBluePressed (x.75) and PurchaseConfirmButtonPressed (x.8) do; red from UIAlertSheetDefaultDestroyButtonPressed */
.get:not(.go):not(.blue).is-pressed,a.b.grey.is-pressed,label.b.grey.is-pressed,button.grey.is-pressed,.act:not(.red).is-pressed{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.3);border-color:#005ee8;background:linear-gradient(#058af5,#0160e6);box-shadow:none}
.get.blue.is-pressed,a.b:not(.grey).is-pressed,form button:not(.grey):not(.act).is-pressed{border-color:#1f3b67;background:linear-gradient(#5c7cb3,#2c569f 50%,#1e4997 51%,#2c56a4);box-shadow:none}
.get.go.is-pressed{border-color:#255e12} .get.go.is-pressed:before,button.gbtn.is-pressed{border-color:#255e12;background:linear-gradient(#72ae56,#3d8822 50%,#307b17 51%,#3d8b22);box-shadow:none}
.act.red.is-pressed{border-color:#8a1c1c;background:linear-gradient(#cf848a,#9d010c 80%,#b33941)}
.alert .abtns button,.alert .abtns .ok{background-origin:border-box!important}  /* the background shorthands reset it; without it the gradient tiles into the see-through border and its bright top shows as a line at the bottom */
.alert .abtns button.is-pressed{background:linear-gradient(#6d7da3,#3c4e7d 49%,#22325e 51%,#2f3f6c)}
.sw.is-pressed .k{background:linear-gradient(#bcbcbc,#e6e6e6)} .dark .sw.is-pressed .k{background:linear-gradient(#55595f,#2e3136)}
.sw{touch-action:none} .sw.drag i:before,.sw.drag i:after,.sw.drag .k{transition:none}  /* while dragging, everything follows --x with the finger */
#sb.on{pointer-events:auto}
*{-webkit-tap-highlight-color:transparent}  /* no grey tap flash; controls have their own pressed looks */
body{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none} input,textarea{-webkit-user-select:text;user-select:text;-webkit-touch-callout:default}  /* app, not a document: holding never selects, except fields */ #sb::before{content:"";position:absolute;inset:-12px -2px -12px -26px} #sb.grab{width:7px;right:1px;border-radius:4px}
h3.hdr{font-size:17px;font-weight:700;line-height:21px;letter-spacing:-.01em;color:var(--head);margin:23px 9px 7px;text-shadow:var(--emboss)}
.ftr{font-size:15px;line-height:19px;color:var(--head);text-align:center;text-shadow:var(--emboss);margin:7px 9px 0;overflow-wrap:anywhere}
.c,.g{background:#fff;border:1px solid var(--line);border-radius:9.5px;box-shadow:inset 0 .5px .5px rgba(0,0,0,.2);overflow:hidden} .g{background:var(--table)}
.c{padding:14px;margin:0 0 12px;display:flex;flex-direction:column;gap:10px} .c p{margin:0}
a.b,label.b,button{display:block;box-sizing:border-box;width:100%;font:inherit;font-weight:700;line-height:1.2;text-align:center;cursor:pointer;padding:11px;color:#fff;
 text-shadow:0 -1px 0 rgba(0,0,0,.4);border:1px solid #2b4f8a;border-radius:9px;background:var(--bluebtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.45),0 1px 2px rgba(0,0,0,.3)}
a.b.grey,label.b.grey,button.grey{color:#38404b;text-shadow:var(--emboss);border-color:#8d97a5;background:linear-gradient(#fff,#e9ebee 50%,#dde0e5 51%,#eceef1)}
button:disabled{opacity:.5;cursor:default}
input{font:inherit;width:100%;box-sizing:border-box;padding:10px 12px;background:#fff;border:1px solid #9aa3ae;border-radius:6px;box-shadow:inset 0 1px 2px rgba(0,0,0,.2);color:var(--acc)}
.vh{position:absolute;width:1px;height:1px;opacity:0;overflow:hidden} /* file input behind its styled label */
textarea{width:100%;box-sizing:border-box;font:12px/1.5 ui-monospace,Menlo,monospace;border:1px solid #b7bec8;border-radius:6px;padding:8px;color:#333;resize:none;
 background:linear-gradient(#eef0f3,#fff 12px);box-shadow:inset 0 1px 2px rgba(0,0,0,.15);white-space:pre;overflow-x:auto}
ol{margin:0;padding-left:1.3rem} li{margin:.35rem 0}
.row{display:flex;align-items:center;gap:10px;min-height:43px;box-sizing:border-box;padding:8px 10px;border-top:1px solid var(--div);box-shadow:inset 0 1px 0 var(--divhi)}
.g>:first-child{border-top:0!important} .row>div:not(.ico){flex:1;min-width:0} .row small{display:block}
.ico{position:relative;width:50px;height:50px;flex:none;border-radius:10px;object-fit:cover;display:grid;place-items:center;color:#fff;font-weight:700;font-size:21px;
 text-shadow:0 -1px 0 rgba(0,0,0,.3);box-shadow:0 1px 3px rgba(0,0,0,.45)} div.ico:after{content:"";position:absolute;inset:0;border-radius:inherit;background:var(--gloss)}
.locked .ico{filter:grayscale(.8);opacity:.6}
details{border-top:1px solid var(--sep)} details>summary{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:10px;min-height:44px;
 padding:0 10px;font-weight:700} details>summary::-webkit-details-marker{display:none}
details>summary:after{content:"";flex:none;width:9px;height:13px;margin-right:.5px;background:var(--chev) center/contain no-repeat;transition:transform .2s}
details[open]>summary:after{transform:rotate(90deg)} details>:not(summary){margin:0 10px 12px}
.scrim[hidden]{display:none} .scrim{position:fixed;inset:0;z-index:20;display:grid;place-items:center;padding:16px;background:radial-gradient(rgba(0,0,0,.2),rgba(0,0,0,.6))}
.alert{width:min(284px,100%);box-sizing:border-box;border-radius:10px;border:2px solid #b1b7c1;border-bottom-color:#e1e3e3;padding:16px 14px 14px;text-align:center;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.5);
 background:linear-gradient(rgba(255,255,255,.25),rgba(255,255,255,.06) 40px,transparent 41px),rgba(4,20,70,.88);box-shadow:0 4px 18px rgba(0,0,0,.6),inset 0 0 0 1px #000;animation:pop .3s ease-out}
@keyframes pop{0%{transform:scale(.6);opacity:0}60%{transform:scale(1.07);opacity:1}100%{transform:scale(1)}}
.alert h3{margin:0 0 6px;font-size:17px} .alert p{margin:0 0 12px;font-size:15px}
.abtns{display:grid;grid-template-columns:1fr 1fr;gap:8px}
/* UIKit alert buttons: UIPopupAlertSheetDefaultButton (Cancel), UIPopupAlertSheetButton (OK), UIPopupAlertSheetButtonPress */
.alert .abtns button{height:43px;padding:0;font-size:16px;border:1px solid rgba(19,29,57,.9);border-radius:5px;box-shadow:none;
 
 background:linear-gradient(#707a91,#283659 49%,#0b1b43 50%,#182747)}  /* Cancel-style (left), as UIAlertView draws it on the 4S */
.alert .abtns .ok{background:linear-gradient(#b4b9c8,#5f6882 49%,#596484 51%,#4d597a)}  /* sampled from Cydia's alert on the 4S: opaque greys, no white line */
/* Dark Mode (follows the phone, or the Settings tab switch): gunmetal bars, dark pinstripes, inverted emboss */
html.dark{color-scheme:dark;--mute:#8b9099;--sep:#17191c;--line:#0d0e10;--acc:#6fa8ff;--head:#8b9099;--emboss:0 -1px 0 #000;
 --pin:repeating-linear-gradient(90deg,#1b1d21 0 5px,#202227 5px 7px);--navbg:linear-gradient(#5f656f,#3b4048 50%,#30343b 51%,#23262b);--statbg:#000;--navhi:#7a808a;--navedge:#0b0c0e;--table:#2c2f34;--div:#17191c;--divhi:rgba(255,255,255,.07);
 --barbtn:linear-gradient(#4a4f58,#24272c);--greybtn:linear-gradient(#4a4f58,#2c2f34);background:#1d1f23}
.dark body{color:#e6e8eb} .dark .nav .bar{border-color:#111} .dark .nav .back{border-image-source:url(/static/back-dark.svg)}
.dark .c,.dark .g{background:#2c2f34;border-color:#0d0e10;box-shadow:0 1px 0 rgba(255,255,255,.06)}
.dark .row,.dark details>summary{background:linear-gradient(#34373d,#2a2d32);box-shadow:inset 0 1px 0 rgba(255,255,255,.07)}
.dark input{background:#1f2125;border-color:#0d0e10;color:#e6e8eb;box-shadow:inset 0 1px 3px #000} .dark textarea{background:#1f2125;border-color:#0d0e10;color:#ccc}
.dark a.b.grey,.dark label.b.grey,.dark button.grey{color:#e6e8eb;border-color:#111;background:linear-gradient(#4a4f58,#2c2f34 50%,#24272c 51%,#2c2f34);box-shadow:inset 0 1px 0 rgba(255,255,255,.15)}
/* Cydia's reload bar while Reload syncs sources and re-signs: the kit's "Semi-transparent black bar" (#4c4c4c to black at 52%, a white-at-20%
   line on top, black-at-70% at the bottom) at .8, a 20pt white spinner, a bold white line. As iFizBox's F204: it sits on top of the tab bar, sliding
   up from behind it, and nothing on the page moves; the page gets 44pt more room at the bottom while it shows, so the last row still scrolls clear */
#rbar{position:fixed;z-index:4;bottom:var(--tabh,0);left:0;right:0;height:44px;box-sizing:border-box;padding:0 max(12px,env(safe-area-inset-right)) 0 max(12px,env(safe-area-inset-left));
 display:flex;align-items:center;gap:10px;font-size:14px;font-weight:700;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.8);pointer-events:none;
 background:linear-gradient(rgba(0,0,0,.7),rgba(0,0,0,.7)) bottom/100% 1px no-repeat,linear-gradient(rgba(255,255,255,.2),rgba(255,255,255,.2)) top/100% 1px no-repeat,linear-gradient(rgba(76,76,76,.8),rgba(0,0,0,.8) 52%);
 transform:translateY(100%);transition:transform .25s ease-in} html.reloading #rbar{transform:none;transition:transform .3s cubic-bezier(.25,.1,.25,1)}  /* F204's timings: up .3s, down .25s */
html.reloading #scr{padding-bottom:calc(116px + env(safe-area-inset-bottom))}
.spin{width:20px;height:20px;flex:none;animation:spin 1s steps(12) infinite} @keyframes spin{to{transform:rotate(360deg)}}
.scrim.clear{background:none} .nw{white-space:nowrap} .a2l>span{display:block;margin:2px 0} .ic{width:1.15em;height:1.15em;vertical-align:-.2em;margin-right:3px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}</style>
{% if back %}<header class=nav><a class="bar back" href="{{ back[1] }}" onclick="return goBack(this.href)">{{ back[0] }}</a><h1>{{ title }}</h1><span></span></header>
<script>/* a pushed page: tapping back pops; iOS's own edge swipe (Safari and the home-screen app) does the same. history.back() keeps the previous page's scroll, like a native pop; first visits (no "/" behind us) follow the link */
function goBack(h){try{if(new URL(document.referrer).pathname=="/"&&history.length>1){history.back();return false}}catch(e){}location.href=h;return false}
</script>
{% else %}<header class=nav><button type=button class=bar onclick="about.hidden=false;about.querySelector('.ok').focus()">About</button><h1 id=navT>sidedrop</h1>
<button type=button class="bar r" onclick="reloadData()">Reload</button></header>{% endif %}
<div class=scrim id=about hidden><div class=alert role=alertdialog aria-modal=true aria-labelledby=aboutT>
<h3 id=aboutT>About sidedrop</h3><p>Apps shared between friends, signed for each registered iPhone. Register once in Safari, then tap GET.</p>
{% if stats %}<p>{{ stats[0] }} of 100 iPhones registered.{% if stats[1] %} Apps keep working until {{ stats[1].strftime('%B %-d, %Y') }}.{% endif %}</p>{% endif %}
<div class=abtns><button type=button onclick="about.hidden=true;let d=document.getElementById('dev');if(d){go('settings');d.open=true;setTimeout(()=>goTo(d),50)}">Help</button><button type=button class=ok onclick="about.hidden=true">OK</button></div></div></div>
<script>/* alerts are modal like UIAlertView: only their buttons close them */
/* #scr is the scroller; scrollIntoView would also scroll the locked <html> and drag the fixed nav down */
/* clamp to the real bottom: iOS lets a smooth scroll on a non-root scroller overshoot past the end, then snaps back on the next touch */
function goTo(el){let b=scr;b.scrollTo({top:Math.min(b.scrollTop+el.getBoundingClientRect().top-56,b.scrollHeight-b.clientHeight),behavior:"smooth"})}
addEventListener("gesturestart",e=>e.preventDefault())
/* pressed looks: .is-pressed while a finger is down, off when it lifts, slides off the control or the page scrolls.
   Not :active: iOS keeps that on a held control after the touch has turned into a scroll. A quick tap still shows it for 140 ms, as UIKit does. */
const PRESS=".get,.tile,a.b,label.b,button,.nav .bar,.sw";let pd=null,pdAt=0;
const unpress=now=>{let el=pd;if(!el)return;pd=null;setTimeout(()=>{if(pd!==el)el.classList.remove("is-pressed")},now?0:Math.max(0,140-(performance.now()-pdAt)))};
addEventListener("touchstart",e=>{unpress(1);let el=e.target.closest&&e.target.closest(PRESS);if(!el||el.disabled||e.touches.length>1)return;pd=el;pdAt=performance.now();el.classList.add("is-pressed")},{passive:true});
addEventListener("touchmove",e=>{let t=e.touches[0];if(pd&&!pd.contains(document.elementFromPoint(t.clientX,t.clientY)))unpress(1)},{passive:true});
addEventListener("touchend",()=>unpress(),{passive:true});addEventListener("touchcancel",()=>unpress(1),{passive:true});
addEventListener("scroll",()=>unpress(1),{passive:true,capture:true});  // scroll doesn't bubble: capture catches every scroller
addEventListener("DOMContentLoaded",()=>{
 /* haptic tick: Safari has no vibration API, but toggling a hidden <input switch> plays the system switch haptic (iOS 18+); elsewhere navigator.vibrate. Only from a touch handler. */
 window.hap=()=>{if(navigator.vibrate){navigator.vibrate(10);return}let l=document.createElement("label"),i=document.createElement("input");i.type="checkbox";i.setAttribute("switch","");l.style.cssText="position:fixed;width:1px;height:1px;opacity:0;pointer-events:none";l.append(i);document.body.append(l);l.click();l.remove()};
 /* scroll indicator: shows while scrolling; while it's showing, grab it to scrub like native */
 let b=scr,sb=document.createElement("div"),t,grab=null,sm=[],fl=0,g=()=>{let n=document.querySelector(".nav").getBoundingClientRect().bottom,tb=document.querySelector(".tabs"),
  track=(tb?tb.getBoundingClientRect().top:innerHeight)-3-n-6,h=b.scrollHeight-b.clientHeight,th=Math.max(36,track*b.clientHeight/b.scrollHeight);return{n,track,h,th}};
 sb.id="sb";document.body.append(sb);
 let draw=()=>{let m=g(),st=b.scrollTop,ov=st<0?-st:st>m.h?st-m.h:0,th=Math.max(7,(m.h<=1?m.track:m.th)-ov),y=m.h<=1?(st>0?1:0):Math.min(Math.max(st/m.h,0),1);sb.style.top=m.n+3+(m.track-th)*y+"px";sb.style.height=th+"px";  /* like UIScrollView: a page that fits still shows a full-length indicator while it bounces; overscroll squashes it against that end */
  sb.style.opacity=1;sb.classList.add("on");clearTimeout(t);if(!grab)t=setTimeout(()=>{sb.style.opacity=0;sb.classList.remove("on")},grab===null?500:900)};
 b.addEventListener("scroll",draw,{passive:true});
 sb.addEventListener("touchstart",e=>{e.preventDefault();cancelAnimationFrame(fl);sm=[];grab=e.touches[0].clientY-sb.getBoundingClientRect().top;sb.classList.add("grab");b.classList.add("grabbing");clearTimeout(t)},{passive:false});  // preventDefault: no long-press text selection
 sb.addEventListener("touchmove",e=>{e.preventDefault();let m=g();if(m.h<=1)return;b.scrollTop=(e.touches[0].clientY-grab-m.n-3)/(m.track-m.th)*m.h;let n=performance.now();sm.push([n,b.scrollTop]);while(sm.length>2&&n-sm[0][0]>80)sm.shift()},{passive:false});
 sb.addEventListener("touchend",()=>{grab=undefined;sb.classList.remove("grab");b.classList.remove("grabbing");hap();  /* Safari plays its haptic only inside a finished touch: the tick comes on release */
  let a=sm[0],z=sm[sm.length-1];if(a&&z&&z[0]-a[0]>10){let v=(z[1]-a[1])/(z[0]-a[0]),last=performance.now();  /* momentum after letting go, like a native fling */
   if(Math.abs(v)>.3){let st=n=>{let dt=Math.min(32,n-last);last=n;v*=Math.pow(.95,dt/16.67);let mx=b.scrollHeight-b.clientHeight,nx=Math.max(0,Math.min(mx,b.scrollTop+v*dt));b.scrollTop=nx;fl=Math.abs(v)<.02||nx<=0||nx>=mx?0:requestAnimationFrame(st)};fl=requestAnimationFrame(st)}}
  draw();grab=null});
 addEventListener("touchstart",e=>{if(e.target!==sb)cancelAnimationFrame(fl)},{passive:true,capture:true});
 /* on/off switches drag like UISwitch; a plain tap still toggles */
 document.querySelectorAll(".sw").forEach(w=>{let i=w.querySelector("input"),x0,s0,mv;
  w.addEventListener("touchstart",e=>{x0=e.touches[0].clientX;s0=i.checked?50:0;mv=false},{passive:true});
  w.addEventListener("touchmove",e=>{let d=e.touches[0].clientX-x0;if(!mv&&Math.abs(d)<4)return;mv=true;e.preventDefault();w.classList.add("drag");w.style.setProperty("--x",Math.min(50,Math.max(0,s0+d))+"px")},{passive:false});
  /* iOS still sends a click after the drag, which would toggle it back: swallow that one */
  w.addEventListener("click",e=>{if(w.skip){e.preventDefault();w.skip=0}},true);
  let end=e=>{if(!mv)return;mv=false;if(e.cancelable)e.preventDefault();let on=parseFloat(w.style.getPropertyValue("--x"))>25;w.classList.remove("drag");w.style.removeProperty("--x");
   w.skip=1;setTimeout(()=>w.skip=0,400);if(on!=i.checked){i.checked=on;i.dispatchEvent(new Event("change"))}};
  w.addEventListener("touchend",end);w.addEventListener("touchcancel",end)})})  // iOS ends a gesture it took over with touchcancel  // Safari ignores user-scalable=no for pinch
</script>
{% if back %}<div id=scr><section class=page>{{ body|safe }}</section></div>{% else %}{{ body|safe }}{% endif %}""".replace("%PUBLIC_URL%", PUBLIC_URL).replace("%BUILD%", BUILD)  # link previews (iMessage, Discord) need absolute URLs; static/og.png is the card


def file_labels(folder):
    """appfiles/<app>/labels.txt: one "file name = label" line per file, e.g. "GMPE01.iso = the game disc"."""
    f = folder / "labels.txt"
    return {k.strip(): v.strip() for k, _, v in (l.partition("=") for l in f.read_text().splitlines() if "=" in l)} if f.exists() else {}


def page(body, back=None, title="sidedrop", **ctx):
    """back=("Settings", "/#settings") makes it a pushed screen: title in the nav, iOS back button and edge swipe."""
    stats = None
    if logged_in() and PROFILE.exists():  # for the About alert: devices used, and when the profile (so every app) expires
        prof = embedded_plist(PROFILE.read_bytes())
        stats = (len(prof.get("ProvisionedDevices", [])), prof.get("ExpirationDate"))
    return render_template_string(PAGE, body=render_template_string(body, stats=stats, **ctx), stats=stats, back=back, title=title)


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
    if enrolled:
        touch_seen(token_udid(tok))
    error = None
    try:
        with lock:
            resign()  # ponytail: signs stale IPAs on page load; first visit after an upload waits for it
    except Exception as e:
        error = str(e)
    apps = [dict(ipa_info(p), name=p.stem, files=sorted(f for f in (APP_FILES / p.stem).glob("*") if f.is_file() and f.name != "labels.txt"))
            for p in sorted(SIGNED.glob("*.ipa"))] if SIGNED.exists() else []
    apps = [a for a in apps if "feather" not in a["name"].lower()]  # iFizBox replaced it; a copy synced before stays on disk, unlisted
    third = [a for a in apps if (APPS / f".{a['name']}.third").exists()]
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
    ifizbox = [a for a in apps if IFIZBOX_ID in (a["id"], a["name"])]  # its own category, on top
    apps = [a for a in apps if a not in third and a not in ifizbox]
    ifz = ifizbox[0] if ifizbox else None
    resp = make_response(page("""<style>
.splash{display:flex;align-items:center;gap:14px;padding:2px 6px 4px} .splash img{width:76px;height:76px;flex:none;border-radius:15px;box-shadow:0 3px 6px rgba(0,0,0,.45)}
.splash h2{font-size:23px;font-weight:400;letter-spacing:-.3px;line-height:1.15;text-shadow:var(--emboss)} .splash p{margin:3px 0 0;font-size:16px;text-shadow:var(--emboss)}
.splash p a{font-weight:700}
/* iOS 5 App Store price button: grey GET, a tap turns it into a green INSTALL, a second tap installs */
.get{flex:none;display:inline-block;width:auto;min-width:62px;box-sizing:border-box;text-align:center;font-size:12px;font-weight:700;letter-spacing:.02em;line-height:1.2;font-family:inherit;padding:5px 10px;
 border-radius:4px;cursor:pointer;white-space:nowrap;color:#4e5866;text-shadow:var(--emboss);border:1px solid #9aa3ae;background:var(--greybtn);box-shadow:inset 0 1px 0 #fff,0 1px 1px rgba(0,0,0,.12)}
/* App Store GET -> INSTALL: the button widens while the green fades in over the grey (a gradient can't transition, so the green is a layer) */
.get{position:relative;isolation:isolate;overflow:hidden;transition:width .25s ease,min-width .25s ease,color .25s,text-shadow .25s,border-color .25s}
.get:before{content:"";position:absolute;inset:0;z-index:-1;background:var(--greenbtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.4);opacity:0;transition:opacity .25s}
.get.go{min-width:76px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);border-color:#2f7a17} .get.go:before{opacity:1}
.get.blue{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);border-color:#2b4f8a;background:var(--bluebtn);box-shadow:inset 0 1px 0 rgba(255,255,255,.4)}
.get[aria-expanded=true]{color:#7d8794;background:linear-gradient(#c9ced5,#dfe3e8);box-shadow:inset 0 1px 3px rgba(0,0,0,.3)}
.locked .get{min-width:44px} .get.done:not(.go){color:#8e959e}  /* iOS 6 App Store: INSTALLED is grey; tapping still reinstalls */
.steps{background:linear-gradient(#f3f5f8,#fff);display:grid;grid-template-rows:0fr;transition:grid-template-rows .3s cubic-bezier(.25,.1,.25,1)} .steps.open{grid-template-rows:1fr}
.steps>div{overflow:hidden;min-height:0} .steps .step:first-child{box-shadow:inset 0 1px var(--sep)}  /* real-height animation; max-height snapped */
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
button.gbtn{border-color:#2f7a17;background:var(--greenbtn)} /* not .green: that's the Settings tab's status panel */
fieldset{border:0;margin:0;padding:0;min-width:0} fieldset:disabled{opacity:.55;filter:grayscale(.6)}
.dark .warn{background:#3a3220;border-color:#6b5a26}
.nudge{animation:nudge .45s} @keyframes nudge{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
/* Settings tab: Cydia-style rows */
.green{background:#e9f8e4} .kv{display:flex;justify-content:space-between;gap:10px;padding:11px 12px;border-top:1px solid #d6e6cf} .kv span{color:var(--acc);text-align:right}
.split{display:grid;grid-template-columns:1fr 1fr;margin-top:12px} .pair{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.tile{display:flex;align-items:center;gap:9px;min-height:50px;padding:8px 10px;box-sizing:border-box;font-weight:700;color:#000;background:var(--table);cursor:pointer;text-align:left;border:0;border-radius:0;box-shadow:none;text-shadow:none;line-height:1.35}
.split .tile+.tile{border-left:1px solid var(--sep)} .pair .tile{border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 0 rgba(255,255,255,.8)}
.tile:after{content:"";margin-left:auto;flex:none;width:9px;height:13px;margin-right:.5px;background:var(--chev) center/contain no-repeat}
.tile.is-pressed:after,.tile.sel:after{filter:brightness(0) invert(1)}
.tile.is-pressed,.tile.sel{background:linear-gradient(#058cf5,#015fe6);color:#fff}
.tic{position:relative;flex:none;width:30px;height:30px;border-radius:7px;display:grid;place-items:center;box-shadow:0 1px 2px rgba(0,0,0,.4)}
.tic:after{content:"";position:absolute;inset:0;border-radius:inherit;background:var(--gloss)} .tic svg{width:19px;height:19px}
.out{margin-top:20px}
/* switch: the Teehan+Lax kit's size (77x27 track, 25pt knob 1pt inside it, 50pt travel); the knob, the blue fill (ends at the knob's centre) and both labels all ride on --x, so ON moves like OFF when tapped or dragged */
.sw{position:relative;flex:none;width:77px;height:27px;--x:0px} .sw:has(input:checked){--x:50px}
.sw input{position:absolute;inset:0;width:100%;height:100%;margin:0;padding:0;opacity:0;cursor:pointer;z-index:2}
.sw i{position:absolute;inset:0;border:1px solid #a7a7a7;border-radius:13.5px;overflow:hidden;background:linear-gradient(#e6e6e6,#fefefe);box-shadow:inset 0 2px 3px rgba(0,0,0,.3);font-size:16px;font-weight:700;line-height:25px;font-style:normal}
.sw i:before{content:"ON";position:absolute;inset:0 auto 0 0;width:77px;padding-left:25.5px;box-sizing:border-box;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);
 background:linear-gradient(#1b68d8,#3f8cf3 55%,#5da1f6);transform:translateX(calc(var(--x) - 63.5px));transition:transform .2s}
.sw i:after{content:"OFF";position:absolute;right:12px;color:#808080;transform:translateX(var(--x));transition:transform .2s}
.sw .k{position:absolute;top:1px;left:1px;width:25px;height:25px;border-radius:50%;background:linear-gradient(#cfcfcf,#fcfcfc);border:1px solid rgba(0,0,0,.42);box-sizing:border-box;
 box-shadow:0 1px 2px rgba(0,0,0,.3);transform:translateX(var(--x));transition:transform .2s;pointer-events:none}

.mini{border:1px solid var(--line);border-radius:8px;overflow:hidden}
.why .row{align-items:flex-start;padding:10px} .why .tic{margin-top:2px} .why b{display:block;font-size:16px} .why small{font-size:14px;line-height:1.3}
/* the install page, as ifizbox.com's (Cydia's Running/Complete screen made cleaner): black page and bar, bold white steps, grey output, a block
   cursor while it runs, then the black finish button (the 4S's UIAlertSheetBlackCancelButton; pressed, UIAlertSheetBlackButtonPressed) */
.con{position:fixed;inset:0;z-index:30;display:flex;flex-direction:column;background:#000;animation:conup .35s cubic-bezier(.36,.66,.04,1)} .con[hidden]{display:none}
@keyframes conup{from{transform:translateY(100%)}}
.con .nav{position:relative;flex:none;background:linear-gradient(rgba(0,0,0,.7),rgba(0,0,0,.7)) bottom/100% 1px no-repeat,linear-gradient(rgba(255,255,255,.2),rgba(255,255,255,.2)) 0 env(safe-area-inset-top)/100% 1px no-repeat,linear-gradient(#4c4c4c,#000 52%) bottom/100% 44px no-repeat,#000}
.con .nav .bar{border-color:#111;background:linear-gradient(#4a4f58,#24272c);background-origin:border-box} .con .nav .bar.is-pressed{background:linear-gradient(#2a2d32,#121316);background-origin:border-box}
.conlog{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:14px max(12px,env(safe-area-inset-right)) 14px max(12px,env(safe-area-inset-left));-webkit-user-select:text;user-select:text}
.pl{white-space:pre-wrap;overflow-wrap:anywhere} .pl-raw{font:11px/15px ui-monospace,"SF Mono",Menlo,monospace;color:#a9a9a9}
.pl-step{margin-top:7px;font:bold 13px/17px "Helvetica Neue",Helvetica,sans-serif;color:#fff} .pl-step:first-child{margin-top:0} .pl-raw+.pl-step{margin-top:9px}
.pl-error{margin:5px 0;font:bold 12px/16px "Helvetica Neue",Helvetica,sans-serif;color:#ff453a}
.concur{display:block;width:7px;height:13px;margin-top:3px;background:#a9a9a9;animation:blink 1s steps(1,end) infinite} .concur[hidden]{display:none} @keyframes blink{50%{opacity:0}}
.confoot{flex:none;display:flex;flex-direction:column;align-items:center;gap:8px;padding:12px max(21px,env(safe-area-inset-right)) calc(16px + env(safe-area-inset-bottom)) max(21px,env(safe-area-inset-left))}
.cons{min-height:16px;max-width:100%;color:#fff;font:bold 12px/16px "Helvetica Neue",Helvetica,sans-serif;text-align:center;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.con .confin{width:100%;max-width:360px;height:44px;margin:2px 0 0;padding:0 12px;border:0;border-radius:10px;font:bold 20px/44px "Helvetica Neue",Helvetica,sans-serif;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.5);
 box-shadow:0 0 0 2.5px #000,0 3.5px 0 0 rgba(211,211,211,.19);background:linear-gradient(#878787,#686868 7%,#545454 23%,#383838 38%,#1a1a1a 54%,#020202 69%,#000 77%,#131313)} .con .confin[hidden]{display:none}
.con .confin.is-pressed{background:linear-gradient(#c7cde9,#c7cde9 .5px,#818fce .5px,#7a8acb 8%,#6577c3 18%,#485db8 31%,#2b45ae 44%,#253eaa 50%,#001d9d 50%,#04229e 56%,#1330a7 69%,#1940b4 82%,#1354cd calc(100% - .5px),#2c68d4 calc(100% - .5px))}
.dark .get{color:#c9ced5;border-color:#111;box-shadow:inset 0 1px 0 rgba(255,255,255,.15)} .dark .get[aria-expanded=true]{color:#8b9099;background:linear-gradient(#1f2125,#2a2d32);box-shadow:inset 0 1px 3px #000}
.dark .steps{background:linear-gradient(#26292d,#2c2f34)} .dark .step+.step{border-top-color:#3a3d42}
.dark .green{background:#24302a} .dark .kv{border-top-color:#1a221d}
.dark .tile{background:linear-gradient(#34373d,#2a2d32);color:#e6e8eb} .dark .pair .tile{border-color:#0d0e10;box-shadow:0 1px 0 rgba(255,255,255,.06)} .dark .split .tile+.tile{border-left-color:#17191c}
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
.badge{position:absolute;top:-2px;left:calc(50% + 5px);min-width:20px;height:20px;padding:0 5px;box-sizing:border-box;border-radius:10px;border:2px solid #fff;color:#fff;letter-spacing:-.02em;
 font:700 13px/16px "Helvetica Neue",Helvetica,sans-serif;text-align:center;background:linear-gradient(#f7b3b7,#e92d35 48.8%,#e70f19 50.5%,#c50103);box-shadow:0 2px 2.5px rgba(0,0,0,.6)}
/* Cydia: while it checks for updates the badge spins instead of counting */
.badge.busy{font-size:0;padding:0} .badge.busy:after{content:"";position:absolute;inset:0;margin:auto;width:10px;height:10px;box-sizing:border-box;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite}
/* Cydia tab bar: 3pt + 44pt tabs + 2pt, then the home indicator's area. --tabh, in CSS (not measured once by script, before iOS has applied
   the safe area), so the reload bar and pushed pages always sit right on top of it */
.tabs{position:fixed;left:0;right:0;bottom:0;z-index:5;height:var(--tabh);box-sizing:border-box;display:grid;grid-template-columns:repeat(4,1fr);
 padding:0 max(2px,env(safe-area-inset-right)) calc(2px + env(safe-area-inset-bottom)) max(2px,env(safe-area-inset-left));
 background:linear-gradient(rgba(0,0,0,.7),rgba(0,0,0,.7)) top/100% 1px no-repeat,linear-gradient(rgba(255,255,255,.1),rgba(255,255,255,.1)) 0 1px/100% 1px no-repeat,linear-gradient(#2f2f2f,#151515 49.5%,#000 49.5%) 0 1px/100% 48px no-repeat,#000}
.tabs:before{content:"";position:absolute;left:0;right:0;bottom:100%;height:2.5px;pointer-events:none;background:linear-gradient(rgba(0,0,0,0),rgba(0,0,0,.18))}
.tabs a{position:relative;display:flex;flex-direction:column;align-items:center;height:44px;box-sizing:border-box;margin:3px 2px 0;padding-top:3.5px;border-radius:2.5px;color:#a8a8a8;font-size:10px;font-weight:700;line-height:12px}
.tabs svg{width:28px;height:28px;margin-bottom:1px;fill:url(#taboff);filter:drop-shadow(0 -1px 0 rgba(0,0,0,.75))}
.tabs a[aria-current]{background:rgba(255,255,255,.15);color:#fff;box-shadow:inset 0 0 1px rgba(0,0,0,.31)}
/* a pushed page (Manage, Sign) in place over its tab: the iOS slide (350 ms, UINavigationController's curve), the page below moving a third as far and
   darkening 10%; transform and opacity only */
.layer{position:fixed;z-index:6;top:0;left:0;right:0;bottom:var(--tabh,0);background:var(--pin);background-color:#c8cfd6} .dark .layer{background-color:#1d1f23}
.layer[hidden]{display:none} .layer .nav{position:absolute;z-index:1}  /* above its own scroller, as the main nav is above #scr */ .layer .nav h1{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.lscroll{position:absolute;inset:0;overflow-y:auto;overscroll-behavior:contain;box-sizing:border-box;scrollbar-width:none;
 padding:calc(56px + env(safe-area-inset-top)) max(10px,env(safe-area-inset-right),(100% - 30rem)/2) 20px max(10px,env(safe-area-inset-left),(100% - 30rem)/2)}
.lscroll>.page{min-height:calc(100% + 1px)}
.shade{position:fixed;inset:0;z-index:6;background:#000;opacity:0;pointer-events:none}
.ghost{position:absolute;margin:0;pointer-events:none;z-index:1}
.tabs a[aria-current] svg{fill:url(#tabglow);filter:drop-shadow(0 2.5px 2.5px rgba(0,0,0,.4))}
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
{% else %}{% set lbl = 'GET' if a.name not in mine else 'INSTALLED' if mine[a.name] == a.vkey else 'UPDATE' %}
{% if a.files %}<button type=button class="get{{ ' done' if lbl == 'INSTALLED' }}" data-app="{{ a.name }}" aria-expanded=false onclick="steps(this)">{{ lbl }}</button>
{% else %}<a class="get{{ ' done' if lbl == 'INSTALLED' }}" data-arm={{ lbl }} data-app="{{ a.name }}" aria-label="Install {{ a.title }}" href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}" onclick="return arm(this)">{{ lbl }}</a>{% endif %}{% endif %}{% endmacro %}
{% macro ifz_icon(a) %}{% if a.icon %}<img class=ico src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=ico style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}{% endmacro %}
{% macro install_list(apps) %}<div class="g{{ '' if enrolled else ' locked' }}">{% for a in apps %}
<div class=row>{% if a.icon %}<img class=ico src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=ico style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}
<div>{{ a.title }}<small>Version {{ a.short }}{% if a.files %} · needs {{ a.files|length }} file{{ 's' if a.files|length > 1 }}{% endif %}</small></div>{{ install(a) }}</div>
{% if enrolled and a.files %}{% set labels = file_labels(a.files[0].parent) %}<div class=steps><div>
<div class=step><span class=num>1</span><div><b>Install the app</b></div><a class="get go" data-app="{{ a.name }}" aria-label="Install {{ a.title }}" onclick="mark(this);this.closest('.step').classList.add('ok')"
 href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">INSTALL</a></div>
{% for f in a.files %}<div class=step><span class=num>{{ loop.index + 1 }}</span><div><b>Download {{ labels.get(f.name, f.name) }}</b>
<small>{% if f.name in labels %}{{ f.name }} · {% endif %}{{ '%.1f'|format(f.stat().st_size/1e6) }} MB · save to Files</small></div>
<a class="get blue" href="{{ adl(f) }}" target=_blank download onclick="this.closest('.step').classList.add('ok')">DOWNLOAD</a></div>{% endfor %}</div></div>{% endif %}
{% endfor %}</div>{% endmacro %}

<i id=stamp hidden data-v="{{ stamp }}"></i><div id=rbar role=status aria-live=polite><svg class=spin viewBox="0 0 24 24" aria-hidden=true><g stroke="#fff" stroke-width="2.2" stroke-linecap="round">
<line x1=12 y1=2.5 x2=12 y2=7 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(30 12 12)" opacity=.92 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(60 12 12)" opacity=.84 />
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(90 12 12)" opacity=.76 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(120 12 12)" opacity=.68 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(150 12 12)" opacity=.6 />
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(180 12 12)" opacity=.52 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(210 12 12)" opacity=.44 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(240 12 12)" opacity=.36 />
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(270 12 12)" opacity=.3 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(300 12 12)" opacity=.25 /><line x1=12 y1=2.5 x2=12 y2=7 transform="rotate(330 12 12)" opacity=.2 /></g></svg><span id=rbarT>Reloading Data</span></div>
<div id=scr><!-- only the pages scroll; the bars and alerts sit outside, above it, as in iFizBox: iOS 26 blurs a scroller's top edge, which the
     opaque nav bar then hides, instead of blurring the nav bar itself -->
<section class=page id=t-apps data-title=sidedrop>
<div class=splash><img src=/apple-touch-icon.png alt=""><div><h2>Welcome to sidedrop</h2><p>by <a href="https://github.com/RyanAHayden">Ryan Hayden</a></p></div></div>
{% if not enrolled %}<h3 class=hdr>First, set up this iPhone</h3>
<details class=c id=sdp open><summary><span class=num>1</span><div>Turn off Stolen Device Protection</div></summary>
{{ sdp_steps }}
<button type=button class=gbtn onclick="sdpDone(true)">I turned it off</button></details>
<div class=c id=reg><div class=sh><span class=num>2</span><div>Register this iPhone<small>In Safari on this iPhone</small></div></div>
<fieldset id=regf disabled>{{ enroll_form }}</fieldset><small>Registered before but the apps are locked? Register again, it's instant.</small></div>{% endif %}
{% if ifz %}<h3 class=hdr>iFizBox</h3><div class="g{{ '' if enrolled else ' locked' }}"><div class=row>{{ ifz_icon(ifz) }}
<div>{{ ifz.title }}<small>Version {{ ifz.short }} · your certificate inside</small></div>
{% if enrolled %}<a class="get{{ ' done' if mine.get(ifz.name) == ifz.vkey }}" data-app="{{ ifz.name }}" aria-label="{{ ifz.title }}: why and install" href=#ifizbox onclick="go('ifizbox');return false">{{ 'GET' if ifz.name not in mine else 'INSTALLED' if mine[ifz.name] == ifz.vkey else 'UPDATE' }}</a>
{% else %}<a class=get aria-label="Register first" href=#apps onclick="return nudge()">🔒</a>{% endif %}</div></div>
<p class=ftr>Installs apps right on your iPhone. <a href=#ifizbox onclick="go('ifizbox');return false">Why iFizBox</a></p>{% endif %}
<h3 class=hdr>Apps</h3>{% if apps %}{{ install_list(apps) }}{% else %}<p class="c m">No apps yet.</p>{% endif %}
{% if third %}<h3 class=hdr>Third-party apps</h3>{{ install_list(third) }}<p class=ftr>Made by other people, mirrored from their sources.</p>{% endif %}
</section>

{% macro cyrow(a, up) %}<div class="cyr{{ ' up' if up }}">{% if a.icon %}<img class=cyi src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=cyi style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}
<div class=cyt><b>{{ a.title }}</b><small>from {{ a.source }} · {{ a.short }}</small>{% if a.desc %}<p>{{ a.desc }}</p>{% endif %}</div>
{% if up %}<a class=get data-arm=UPDATE data-app="{{ a.name }}" aria-label="Update {{ a.title }}" href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}" onclick="return arm(this)">UPDATE</a>{% endif %}</div>{% endmacro %}
<section class=page id=t-changes data-title=Changes><div class=cy>
{% if updates %}<div class=cyh id=uph>Available Updates</div>{% for a in updates %}{{ cyrow(a, True) }}{% endfor %}{% endif %}
{% for day, group in recent %}<div class=cyh>New at {{ day.strftime('%b %-d, %Y') }}</div>{% for a in group %}{{ cyrow(a, False) }}{% endfor %}{% endfor %}</div>
{% if not recent %}<p class="c m">No apps yet.</p>{% endif %}
<p class=ftr>{% if enrolled %}Updates show for apps you installed from here on this iPhone.{% else %}Register this iPhone to get updates.{% endif %}</p>
</section>

<section class=page id=t-ifizbox data-title=iFizBox>
{% if ifz %}<div class=splash>{% if ifz.icon %}<img src="{{ ifz.icon }}" alt="">{% else %}<div class=ico style="width:76px;height:76px;border-radius:15px;background:hsl({{ ifz.name|hue }} 65% 50%)">{{ ifz.title[:1] }}</div>{% endif %}
<div><h2>{{ ifz.title }}</h2><p>A package manager for your iPhone</p></div></div>
<div class=c style="margin-top:16px">{% if enrolled %}<button type=button class=gbtn id=ifzb data-app="{{ ifz.name }}" data-m="{{ ifz_m }}" data-title="{{ ifz.title }}" data-v="{{ ifz.short }}" data-n="{{ n_sources }}" onclick="ifzRun()">Install {{ ifz.title }}</button>
{% else %}<button type=button class=gbtn onclick="nudge()">Register This iPhone First</button>{% endif %}
<small>Version {{ ifz.short }}, signed for this iPhone. Your certificate and {{ n_sources }} sources come with it.</small></div>
<h3 class=hdr>Why {{ ifz.title }}</h3><div class="g why">
<div class=row><span class=tic style="background:linear-gradient(#ffb36b,#d9650f)"><svg viewBox="0 0 24 24"><path d="M8 11V8a4 4 0 0 1 8 0v3" fill="none" stroke="#fff" stroke-width="2.4"/><rect x="5" y="11" width="14" height="10" rx="2" fill="#fff"/></svg></span><div><b>Your certificate, already in it</b><small>No .p12 to find and no password to type: it signs with this site's certificate from the first launch.</small></div></div>
<div class=row><span class=tic style="background:linear-gradient(#8fc6ff,#2a72d6)"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="4" rx="1.5" fill="#fff"/><rect x="4" y="10" width="16" height="4" rx="1.5" fill="#fff"/><rect x="4" y="16" width="16" height="4" rx="1.5" fill="#fff"/></svg></span><div><b>Comes with the sources</b><small>{{ n_sources }} sources, ready the first time it opens.</small></div></div>
<div class=row><span class=tic style="background:linear-gradient(#8fd96b,#3c9a1d)"><svg viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2" fill="#fff"/><path d="M12 7v7m-3-3 3 3 3-3" fill="none" stroke="#3c9a1d" stroke-width="2"/></svg></span><div><b>Signs on your iPhone</b><small>Install any IPA or AltStore app right on the phone: no computer, nothing uploaded.</small></div></div>
<div class=row><span class=tic style="background:linear-gradient(#ff8f8f,#d42a2a)"><svg viewBox="0 0 24 24"><path fill-rule="evenodd" d="M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18zm0 2.5a6.5 6.5 0 1 1 0 13 6.5 6.5 0 1 1 0-13z" fill="#fff"/><path d="M11 7.5h2.2v4.4l3 2-1.2 1.8-4-2.7z" fill="#fff"/></svg></span><div><b>Updates in one tap</b><small>Changes lists the new versions of what you installed.</small></div></div>
<div class=row><span class=tic style="background:linear-gradient(#b7c0cc,#5d6878)"><svg viewBox="0 0 24 24"><path d="M12 3 21 7.5v9L12 21l-9-4.5v-9z" fill="#fff"/></svg></span><div><b>The iOS 6 look, at 120 Hz</b><small>A package manager with the classic look, smooth on today's iPhones.</small></div></div></div>
<p class=ftr>It needs Developer Mode, like every app here. <a href="https://ifizbox.com">ifizbox.com</a></p>
{% else %}<p class="c m">iFizBox isn't here yet. Tap Reload in a minute.</p>{% endif %}
</section>

<section class=page id=t-settings data-title=Settings>
<h3 class=hdr>This iPhone</h3><div class="g green">
<div class=kv><b>Status</b><span>{{ 'Registered' if enrolled else 'Not registered' }}</span></div>
{% if stats %}<div class=kv><b>iPhones used</b><span>{{ stats[0] }} of 100</span></div>
{% if stats[1] %}<div class=kv><b>Apps work until</b><span>{{ stats[1].strftime('%b %-d, %Y') }}</span></div>{% endif %}{% endif %}</div>
{% if enrolled %}<p class=ftr>This iPhone is registered and can install every app.</p>{% endif %}
<div class="g split">
{% if enrolled and admin_on %}<a class=tile href=/admin data-push><span class=tic style="background:linear-gradient(#ffb36b,#d9650f)"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="4" fill="#fff"/><path d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7z" fill="#fff"/></svg></span>Manage</a>
{% else %}<a class=tile href=#apps><span class=tic style="background:linear-gradient(#8fd96b,#3c9a1d)"><svg viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2" fill="#fff"/><rect x="8.5" y="5" width="7" height="12" fill="#3c9a1d"/></svg></span>Register</a>{% endif %}
<button type=button class=tile onclick="goTo(document.getElementById('sign'))"><span class=tic style="background:linear-gradient(#b7c0cc,#5d6878)"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"><path d="M4 20c3-1 5-4 7-4s1 3 3 3 3-2 6-3M15 4l5 5-8 8H7v-5z"/></svg></span>Sign IPA</button></div>
<div class=pair>
<button type=button class=tile onclick="let d=document.getElementById('dev');d.open=true;goTo(d)"><span class=tic style="background:linear-gradient(#bfc4c9,#5f666e)"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3.4" stroke-dasharray="2.4 2"><circle cx="12" cy="12" r="7"/></svg></span>Help</button>
<button type=button class=tile onclick="about.hidden=false;about.querySelector('.ok').focus()"><span class=tic style="background:linear-gradient(#8fc6ff,#2a72d6)"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="#fff"/><path d="M12 10v7M12 6.5v1" stroke="#2a72d6" stroke-width="2.6" stroke-linecap="round"/></svg></span>About</button></div>
<h3 class=hdr>Display</h3><div class=g><div class=row><div>Dark Mode</div><label class=sw><input type=checkbox id=darkSw aria-label="Dark Mode"
 onchange="try{localStorage.dark=this.checked?1:0}catch(e){}theme()"><i></i><span class=k></span></label></div></div>
{% if enrolled %}<h3 class=hdr>Notifications</h3><div class=g><div class=row><div>Update Alerts</div><label class=sw><input type=checkbox id=pushSw aria-label="Update Alerts"
 onchange="pushSet(this.checked)"><i></i><span class=k></span></label></div></div>
<p class=ftr id=pushNote>Tells you when an app you installed has a new version.</p>{% endif %}
<h3 class=hdr>Help</h3><div class=g>
{% if enrolled %}<details><summary>Turn off Stolen Device Protection</summary>{{ sdp_steps }}</details>{% endif %}
<details id=dev><summary>Turn on Developer Mode</summary>
<figure class=shot><figcaption><span class=num>a</span><span>Settings → <b>Privacy &amp; Security</b></span></figcaption>
<img src=/static/dev1.jpg alt="Settings with Privacy and Security circled" width=640 height=243></figure>
<figure class=shot><figcaption><span class=num>b</span><span>Scroll down, tap <b>Developer Mode</b></span></figcaption>
<img src=/static/dev2.jpg alt="The Developer Mode row circled" width=640 height=215></figure>
<figure class=shot><figcaption><span class=num>c</span><span>Turn it <b>on</b>, tap <b>Restart</b>, then <b>Turn On</b> after the restart</span></figcaption>
<img src=/static/dev3.jpg alt="The Developer Mode switch turned on, circled" width=640 height=305></figure>
<div class=warn><span aria-hidden=true>💡</span><div>Don't see it? Install an app first, then look again.</div></div></details>
<details id=a2hs><summary>Add to Home Screen</summary><p class=a2l><span>1. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M8 9H6.5A1.5 1.5 0 0 0 5 10.5v9A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 17.5 9H16M12 3v12M8 7l4-4 4 4"/></svg><b>Share</b></span></span><span>2. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><rect x=4 y=4 width=16 height=16 rx=4 /><path d="M12 8v8M8 12h8"/></svg><b>Add to Home Screen</b></span></span><span>3. Open sidedrop from there</span></p></details></div>
<h3 class=hdr id=sign>Sign your own IPA</h3>
<form class=c method=post action=/sign enctype=multipart/form-data data-push onsubmit="this.querySelector('button').textContent='Signing…'">
<input type=file name=ipa id=ipaf accept=.ipa class=vh onchange="ipal.textContent=this.files[0]?this.files[0].name:'Choose .ipa File'"><label class="b grey" for=ipaf id=ipal>Choose .ipa File</label>
<input type=url name=url placeholder="…or paste a link to an .ipa" aria-label="Link to an .ipa">
<button>Sign</button><small>Signed for registered iPhones. The install link lasts 7 days.</small></form>
<a class="b grey out" href=/logout>Sign out</a>
</section>
</div>
{% if just_enrolled %}<div class=scrim id=welcome><div class=alert role=alertdialog aria-modal=true aria-labelledby=welT>
<h3 id=welT>Setup Complete</h3><p>This iPhone is registered. Enjoy!</p><p>Tap GET to install apps.</p>
<div class=abtns style="grid-template-columns:1fr"><button type=button class=ok onclick="welcomeOk()">OK</button></div></div></div>
<script>function welcomeOk(){welcome.hidden=true;history.replaceState(null,"","/")}</script>{% endif %}
<div class=scrim id=upq hidden><div class=alert role=alertdialog aria-modal=true aria-labelledby=upqT>
<h3 id=upqT>Update</h3><p id=upqL></p><div class=abtns><button type=button onclick="upq.hidden=true">Cancel</button><button type=button class=ok onclick="upgradeGo()">Confirm</button></div></div></div>

{% if enrolled %}<div class=scrim id=devAsk hidden><div class=alert role=alertdialog aria-modal=true aria-labelledby=devT>
<h3 id=devT>Developer Mode Required</h3><p>When the app finishes installing, opening it will ask you to turn on Developer Mode.</p>
<p>Turn it on in Settings, restart, and the app will open.</p>
<div class=abtns><button type=button onclick="devDone(1)">Show Me</button><button type=button class=ok onclick="devDone()">OK</button></div></div></div>{% endif %}
{% if enrolled %}<div class=scrim id=pushAsk hidden><div class=alert role=alertdialog aria-modal=true aria-labelledby=pushT>
<h3 id=pushT>Get Notified of Updates?</h3><p>sidedrop can tell you when an app you installed has a new version.</p>
<div id=pushWeb hidden><div><p class=a2l><span>1. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M8 9H6.5A1.5 1.5 0 0 0 5 10.5v9A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 17.5 9H16M12 3v12M8 7l4-4 4 4"/></svg><b>Share</b></span></span><span>2. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><rect x=4 y=4 width=16 height=16 rx=4 /><path d="M12 8v8M8 12h8"/></svg><b>Add to Home Screen</b></span></span><span>3. Open sidedrop from there</span></p></div></div>
<div class=abtns><button type=button onclick="pushAsk.hidden=true">Not Now</button><button type=button class=ok id=pushOk>Allow</button></div></div></div>{% endif %}
<div class=con id=con hidden role=dialog aria-modal=true aria-labelledby=conT><header class=nav><span></span><h1 id=conT>Running</h1>
<button type=button class="bar r" id=conX onclick="conClose()">Cancel</button></header><div class=conlog id=conL aria-live=polite><span class=concur id=conCur></span></div>
<div class=confoot><div class=cons id=conS></div><button type=button class=confin id=conF hidden></button></div></div>
<nav class=tabs aria-label=Sections>
<a href=#apps><svg viewBox="0 0 30 30"><path d="M4 4h9v9H4zm13 0h9v9h-9zM4 17h9v9H4zm13 0h9v9h-9z"/></svg>Apps</a>
<a href=#changes><svg viewBox="0 0 30 30"><path fill-rule=evenodd d="M15 3a12 12 0 1 0 0 24a12 12 0 1 0 0-24zm0 3a9 9 0 1 1 0 18a9 9 0 1 1 0-18z"/><path d="M14 8h2.4v6.8l4.8 3.1-1.3 2-5.9-3.8z"/></svg>Changes<span class=badge id=badge{% if not updates %} hidden{% endif %}>{{ updates|length }}</span></a>
<a href=#ifizbox><svg viewBox="0 0 30 30"><path d="M15 3l11 5.5-11 5.5L4 8.5zM4 10.7l10 5v11.1l-10-5zM16 15.7l10-5v11.1l-10 5z"/></svg>iFizBox</a>
<a href=#settings><svg viewBox="0 0 30 30"><path fill-rule=evenodd d="M15 7.5a7.5 7.5 0 1 0 0 15a7.5 7.5 0 1 0 0-15zm0 4.3a3.2 3.2 0 1 1 0 6.4a3.2 3.2 0 1 1 0-6.4z"/>{% for r in range(0, 360, 45) %}<rect x="12.8" y="3" width="4.4" height="6" rx="1" transform="rotate({{ r }} 15 15)"/>{% endfor %}</svg>Settings</a></nav>
<svg width=0 height=0 style="position:absolute" aria-hidden=true><linearGradient id=taboff x1=0 y1=0 x2=0 y2=1><stop offset=0 stop-color="#9d9d9d"/><stop offset=1 stop-color="#595959"/></linearGradient><linearGradient id=tabglow x1=.37 y1=0 x2=.63 y2=1><stop offset=0 stop-color="#d9e5f9"/><stop offset=.473 stop-color="#77b5eb"/><stop offset=.488 stop-color="#0091e5"/><stop offset=1 stop-color="#0fbff7"/></linearGradient></svg>
<script>
/* tabs keep their place (scroll, and a page pushed on Settings) and add no history, as in an iOS app; tapping the open tab pops its page, then scrolls to the top */
let cur=null,pos={},L=null,cache={},STAMP={{ stamp }};
function go(t){history.replaceState(history.state,"","#"+t);dispatchEvent(new HashChangeEvent("hashchange"))}  // replaceState fires no hashchange of its own
function show(){let t=location.hash.slice(1);if(t=="more")t="settings";/* more: Home Screen links from before */if(!document.getElementById("t-"+t))t="apps";if(cur&&cur!=t)pos[cur]=scr.scrollTop;
 document.querySelectorAll("#scr>.page").forEach(p=>p.hidden=p.id!="t-"+t);
 document.querySelectorAll(".tabs a").forEach(a=>a.getAttribute("href")=="#"+t?a.setAttribute("aria-current","page"):a.removeAttribute("aria-current"));
 navT.textContent=document.getElementById("t-"+t).dataset.title;if(cur!=t)scr.scrollTo(0,pos[t]||0);cur=t;if(L)L.hidden=L.dataset.tab!=t;navR()}
document.querySelectorAll(".tabs a").forEach(a=>a.addEventListener("click",e=>{e.preventDefault();let t=a.getAttribute("href").slice(1);
 if(t!=cur)return go(t);if(L)history.back();else scr.scrollTo({top:0,behavior:"smooth"})}));
/* a pushed page: fetched and drawn over the tab (its own nav with Back), one history entry, so Back, iOS's edge swipe and forward all work.
   The server still serves each page whole (a reload, or no JS, gets the old full-page screen); anything unexpected falls back to that. */
function parsePage(r,h){if(!r.ok||new URL(r.url).pathname=="/")return null;let d=new DOMParser().parseFromString(h,"text/html"),s=d.querySelector("section.page"),n=d.querySelector(".nav h1");return s&&n?{title:n.textContent,body:s.innerHTML,url:r.url}:null}
function fetchPage(url,init){return fetch(url,Object.assign({credentials:"same-origin"},init)).then(r=>r.text().then(h=>parsePage(r,h))).catch(()=>null)}
function fill(p){L.url=p.url;L.querySelector("h1").textContent=p.title;L.querySelector(".page").innerHTML=p.body;L.querySelector(".lscroll").scrollTop=0}
const EASE="cubic-bezier(.36,.66,.04,1)";
function slide(l,from,to,done){  /* p: 0 the tab alone, 1 the pushed page l in place */
 let o={duration:350,easing:EASE,fill:"forwards"},base=[document.querySelector(".nav"),document.getElementById("t-"+cur)],sh=document.createElement("div");sh.className="shade";l.before(sh);
 let an=[l.animate([{transform:`translate3d(${(1-from)*100}%,0,0)`},{transform:`translate3d(${(1-to)*100}%,0,0)`}],o),sh.animate([{opacity:.1*from},{opacity:.1*to}],o),
  ...base.map(b=>b.animate([{transform:`translate3d(${-30*from}%,0,0)`},{transform:`translate3d(${-30*to}%,0,0)`}],o))];
 an[0].finished.then(()=>{an.forEach(a=>a.cancel());sh.remove();done&&done()})}
function open(p,from,anim){
 L=document.createElement("div");L.className="layer";L.dataset.tab=cur;
 L.innerHTML='<header class=nav><button type=button class="bar back"></button><h1></h1><span></span></header><div class=lscroll><section class=page></section></div>';
 L.querySelector(".back").textContent=navT.textContent;L.querySelector(".back").onclick=()=>history.back();L.sel=from;fill(p);document.body.append(L);
 if(anim)slide(L,0,1,()=>from&&from.classList.remove("sel"));else if(from)from.classList.remove("sel")}
function close(anim){let l=L;if(!l)return;L=null;if(!anim||l.hidden)return l.remove();
 /* the row that opened it fades from blue as the page slides off (a copy over it, so only opacity animates) */
 let el=l.sel,g=null;if(el&&el.offsetParent){g=el.cloneNode(true);g.removeAttribute("href");g.classList.add("sel","ghost");
  Object.assign(g.style,{left:el.offsetLeft+"px",top:el.offsetTop+"px",width:el.offsetWidth+"px",height:el.offsetHeight+"px"});el.parentElement.style.position="relative";el.parentElement.append(g);
  g.animate([{opacity:1},{opacity:0}],{duration:350,easing:EASE,fill:"forwards"})}
 slide(l,1,0,()=>{l.remove();g&&g.remove()})}
function push(url,init,from){return fetchPage(url,init).then(p=>{if(!p)return false;let id=Date.now();cache[id]=p;
 if(L){fill(p);history.replaceState({push:id},"");return true}  // a form on the pushed page: its answer replaces it (the server redirects back to the same page)
 history.pushState({push:id},"");open(p,from,true);return true})}
if(history.state&&history.state.push)history.replaceState(null,"");  // a reload forgets pushed pages
addEventListener("popstate",e=>{let id=e.state&&e.state.push,anim=!e.hasUAVisualTransition;  // iOS's edge swipe animates it already
 if(id&&!L&&cache[id])open(cache[id],null,anim);else if(!id&&L)close(anim)});
document.addEventListener("click",e=>{let a=e.target.closest("a[data-push]");if(!a||e.defaultPrevented)return;e.preventDefault();if(L)return;
 a.classList.add("sel");push(a.href,{},a).then(ok=>{if(!ok)location.href=a.href})});
document.querySelectorAll("form button").forEach(b=>b.dataset.t=b.textContent);
/* a form with no action posts to its own page: on a pushed page that's the page's URL, not / */
document.addEventListener("submit",e=>{let f=e.target;if(e.defaultPrevented||!(f.matches("[data-push]")||f.closest(".layer")))return;e.preventDefault();
 push(L&&L.contains(f)?new URL(f.getAttribute("action")||"",L.url).href:f.action,{method:"POST",body:new FormData(f)}).then(ok=>{if(!ok)return f.submit();f.querySelectorAll("button[data-t]").forEach(b=>b.textContent=b.dataset.t)})});
/* iFizBox's install, as on ifizbox.com: iOS's prompt straight from the tap, then a log that follows iOS's own requests for the manifest and
   the app (the server sees them, /install/<token>). The page completes once iOS starts the download: the rest happens on the Home Screen. */
const IFZ_STEPS=a=>["Waiting for iOS…","iOS is asking: tap Install.",`iOS is installing ${a}. Press Home to watch it on the Home Screen.`];
let conRun=0;const wait=ms=>new Promise(r=>setTimeout(r,ms));
function conLine(kind,text){let d=document.createElement("div");d.className="pl pl-"+kind;d.textContent=text;conL.insertBefore(d,conCur);conL.scrollTop=conL.scrollHeight}
function conOpen(){conRun++;conL.replaceChildren(conCur);conCur.hidden=false;conT.textContent="Running";conX.textContent="Cancel";conF.hidden=true;conS.textContent="";con.hidden=false;return conRun}
function conDone(status,label,action){conT.textContent="Complete";conCur.hidden=true;conS.textContent=status;conX.textContent="Close";conF.textContent=label;conF.onclick=()=>{if(!(action&&action()))conClose()};conF.hidden=false}
function conClose(){conRun++;con.hidden=true;setTimeout(devMaybe,400)}
function ifzRun(){let b=document.getElementById("ifzb");if(!b)return nudge();
 let t=[...crypto.getRandomValues(new Uint8Array(12))].map(x=>x.toString(16).padStart(2,"0")).join(""),itms="itms-services://?action=download-manifest&url="+encodeURIComponent(b.dataset.m+"&t="+t);
 location.href=itms;mark(b,1);  // first, while Safari still counts this as the tap
 let run=conOpen(),a=b.dataset.title,st=IFZ_STEPS(a),shown=-1,at=0,t0=Date.now();
 conLine("step","Installing "+a+" "+b.dataset.v);conLine("raw","Signed for this iPhone by sidedrop");conLine("raw","Certificate: inside, imported on first launch");conLine("raw",b.dataset.n+" sources: inside, added on first launch");
 const show=async n=>{while(shown<n&&run==conRun){if(shown>=0){let l=400-(Date.now()-at);if(l>0)await wait(l)}if(run!=conRun)return;shown++;conLine("step",st[shown]);conS.textContent=st[shown];at=Date.now()}};  // each step shows at least 400 ms
 (async()=>{for(;;){if(run!=conRun)return;let s=null;try{s=await(await fetch("/install/"+t,{cache:"no-store"})).json()}catch(e){}
  let stage=s?(s.started?2:s.manifest?1:0):Math.max(shown,0);await show(stage);if(run!=conRun)return;
  if(stage==2){await wait(400);if(run==conRun)conDone(st[2],"Done");return}
  if(!(s&&s.started)&&Date.now()-t0>60000){conLine("error","iOS didn't ask for the app. Tap Retry.");conDone("iOS didn't ask for the app.","Retry",()=>{ifzRun();return true});return}
  await wait(500)}})()}
/* Reload: Cydia's reload bar while sources sync, then the lists swap in place (scroll, the open tab and a pushed page stay). Pull down past the top does the same. */
function reloadData(){let h=document.documentElement;if(h.classList.contains("reloading"))return;h.classList.add("reloading");
 fetch("/refresh",{method:"POST"}).catch(()=>{}).then(refreshIn).finally(()=>h.classList.remove("reloading"))}
function refreshIn(){return fetch("/",{credentials:"same-origin"}).then(r=>r.text()).then(t=>{let d=new DOMParser().parseFromString(t,"text/html");
 if(!d.getElementById("t-apps")||!d.getElementById("reg")!=!document.getElementById("reg"))return location.reload();  // signed out, or registered since: the whole page changes
 if(newBuild((d.querySelector("meta[name=build]")||{}).content))return;  // a new deploy: newBuild reloads the whole page
 ["t-apps","t-changes","t-ifizbox"].forEach(i=>document.getElementById(i).innerHTML=d.getElementById(i).innerHTML);STAMP=+d.getElementById("stamp").dataset.v;
 try{if(localStorage.sdp)sdpDone()}catch(e){}document.querySelectorAll("input[name=name]").forEach(i=>i.oninput());navR()}).catch(()=>{})}
let held=0,pulled=0;addEventListener("touchstart",()=>{held=1;pulled=0},{passive:true});
scr.addEventListener("scroll",()=>{if(held&&!pulled&&scr.scrollTop<-70){pulled=1;hap()}},{passive:true});  // the tick as it arms, like UIRefreshControl
addEventListener("touchend",()=>{held=0;if(pulled){pulled=0;reloadData()}},{passive:true});
/* on Changes with upgrades, the nav is Cydia's: Refresh (reloads data) on the left, Update (n) on the right */
function navR(){let n=document.querySelectorAll(".cyr.up").length,r=document.querySelector(".nav .bar.r"),l=document.querySelector(".nav .bar:not(.r)"),ch=location.hash=="#changes",c=ch&&n;
 r.textContent=c?"Update ("+n+")":"Reload";r.onclick=c?upgradeAll:reloadData;
 l.textContent=c?"Refresh":"About";l.onclick=c?reloadData:()=>{about.hidden=false;about.querySelector(".ok").focus()};badge.textContent=n;badge.hidden=!n&&!badge.classList.contains("busy");let h=document.getElementById("uph");if(h)h.hidden=!n}
function mark(b,quiet){let n=b.dataset.app;if(!n)return;navigator.sendBeacon("/installed",new URLSearchParams({name:n}));
 document.querySelectorAll('.row .get[data-app="'+n+'"]').forEach(x=>{x.classList.add("done");if(x.dataset.arm)x.dataset.arm="INSTALLED";if(!x.classList.contains("go"))x.textContent="INSTALLED"});if(!quiet)setTimeout(devMaybe,1500);  // after iOS's install prompt
 setTimeout(()=>{document.querySelectorAll('.cyr.up [data-app="'+n+'"]').forEach(x=>x.closest(".cyr").remove());navR()},500)}  // after the link has followed: a removed link doesn't navigate
function upgradeAll(){let l=[...document.querySelectorAll(".cyr.up b")].map(b=>b.textContent);upqT.textContent="Update "+l.length+(l.length>1?" Apps":" App");upqL.textContent=l.join(", ");upq.hidden=false}
/* ponytail: one install link every 3 s; iOS shows one install prompt per link, re-tap UPDATE on any it drops */
function upgradeGo(){upq.hidden=true;[...document.querySelectorAll(".cyr.up a.get")].map(b=>[b,b.href]).forEach(([b,h],i)=>setTimeout(()=>{mark(b);location.href=h},i*3000))}
addEventListener("hashchange",show);
/* check sources in the background (the page no longer waits on it); swap the lists in only if a new build got signed */
/* and when the Home Screen app comes back: iOS keeps it running for days, so a new deploy (another build) reloads the whole page, not just the lists */
const BUILD=document.querySelector("meta[name=build]").content;
/* once per new build: a server still answering with another one (mid-deploy) mustn't loop the page */
function newBuild(b){if(!b||b==BUILD)return false;let seen=null;try{seen=sessionStorage.reloadedFor}catch(e){}if(seen==b)return false;try{sessionStorage.reloadedFor=b}catch(e){}location.reload();return true}
function checkNow(){return fetch("/check",{method:"POST"}).then(r=>r.json()).then(d=>{if(newBuild(d.build))return;if(d.stamp!=STAMP)return refreshIn()}).catch(()=>{})}
addEventListener("visibilitychange",()=>{if(document.visibilityState=="visible"&&con.hidden)checkNow()});  // not mid-install: the install page would vanish
{% if enrolled %}badge.classList.add("busy");badge.hidden=false;checkNow().finally(()=>{badge.classList.remove("busy");navR()});{% endif %}
/* web push: iOS offers it only to the Home Screen app (separate storage from Safari, so Safari's "asked" doesn't stop the app asking) */
const PUSHKEY="{{ vapid }}",pushOK="PushManager" in window&&"serviceWorker" in navigator&&{{ 'true' if enrolled else 'false' }};
function pushSub(){return navigator.serviceWorker.register("/sw.js").then(r=>r.pushManager.getSubscription().then(s=>[r,s]))}
function pushSet(on){if(!pushOK){pushSw.checked=false;pushShow();return}  // Safari: explain Add to Home Screen in the alert
 if(!on){pushSub().then(([r,s])=>s&&s.unsubscribe());return}  // the server drops it the next time a push gets a 410
 Notification.requestPermission().then(p=>{if(p!="granted")throw 0;return pushSub()}).then(([r,s])=>s||r.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:Uint8Array.from(atob(PUSHKEY.replace(/-/g,"+").replace(/_/g,"/")),c=>c.charCodeAt(0))}))
  .then(s=>fetch("/push",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(s)})).catch(()=>{if(window.pushSw)pushSw.checked=false})}
/* asked once per phone: after the first INSTALL tap or the first visit to Changes */
/* first INSTALL on this phone: warn that opening the app will ask for Developer Mode; then the notifications ask */
function devMaybe(){let a=null;try{a=localStorage.devTold}catch(e){}if(a||!window.devAsk)return pushMaybe();try{localStorage.devTold=1}catch(e){}devAsk.hidden=false}
function devDone(show){devAsk.hidden=true;if(show){go("settings");let d=document.getElementById("dev");d.open=true;setTimeout(()=>goTo(d),50)}else setTimeout(pushMaybe,400)}
function pushMaybe(){let a=null;try{a=localStorage.pushAsked}catch(e){}if(a||!window.pushAsk||(pushOK&&Notification.permission!="default"))return;
 try{localStorage.pushAsked=1}catch(e){}pushShow()}
function pushShow(){pushWeb.hidden=pushOK;pushOk.textContent=pushOK?"Allow":"OK";let bs=pushOk.parentNode;bs.style.gridTemplateColumns=pushOK?"":"1fr";bs.firstElementChild.style.display=pushOK?"":"none";
 pushOk.onclick=()=>{pushAsk.hidden=true;if(pushOK){pushSet(true);if(window.pushSw)pushSw.checked=true}};pushAsk.hidden=false}
if(pushOK&&window.pushSw)pushSub().then(([r,s])=>pushSw.checked=!!s&&Notification.permission=="granted").catch(()=>{});
let pushOnChanges=()=>{if(location.hash=="#changes")setTimeout(pushMaybe,600)};addEventListener("hashchange",pushOnChanges);pushOnChanges();
/* change a GET button's label and colour with its width animating, like the App Store (a label swap alone jumps the width) */
function morph(b,f){let w0=b.offsetWidth;f();let w1=b.offsetWidth;if(w0==w1)return;b.style.width=w0+"px";b.offsetWidth;b.style.width=w1+"px";clearTimeout(b.mt);b.mt=setTimeout(()=>b.style.width="",300)}
function disarm(keep){document.querySelectorAll(".get.go[data-arm]").forEach(b=>{if(b!=keep)morph(b,()=>{b.classList.remove("go");b.textContent=b.dataset.arm})})}
function arm(b){if(b.classList.contains("go")){mark(b);setTimeout(()=>disarm(),1500);return true}disarm(b);morph(b,()=>{b.classList.add("go");b.textContent="INSTALL"});return false}
addEventListener("click",e=>{if(!e.target.closest("[data-arm]"))disarm()});
function steps(b){let open=b.getAttribute("aria-expanded")!="true";b.setAttribute("aria-expanded",open);b.closest(".row").nextElementSibling.classList.toggle("open",open)}
function sdpDone(save){let d=document.getElementById("sdp");if(!d)return;d.classList.add("ok");d.open=false;regf.disabled=false;
 if(save){try{localStorage.sdp=1}catch(e){}regf.querySelector("input").focus()}}
try{if(localStorage.sdp)sdpDone()}catch(e){}
function nudge(){go("apps");let r=document.querySelector("#sdp:not(.ok)")||document.getElementById("reg");if(r.open===false)r.open=true;r.classList.remove("nudge");void r.offsetWidth;r.classList.add("nudge");if(r.id=="reg")r.querySelector("input").focus();return false}
show();
addEventListener("pageshow",()=>{document.querySelectorAll("input[name=name]").forEach(i=>i.oninput());theme();darkSw.checked=document.documentElement.classList.contains("dark")});
</script>""", error=error, enrolled=enrolled, mine=mine, stamp=signed_stamp(), vapid=vapid_public() if enrolled else "", admin_on=bool(ADMIN_PASSWORD), updates=updates, recent=recent, just_enrolled=enrolled and bool(request.args.get("enrolled")) and request.cookies.get("device") != tok, apps=apps, ifz=ifz, third=third, n_sources=len(read_urls(IFIZBOX_SOURCES)),
        ifz_m=signed_url(f"/m/{ifz['name']}.plist") if ifz else "",
        manifest=lambda n: quote(signed_url(f"/m/{n}.plist"), safe=""),
        adl=lambda f: signed_url(f"/af/{f.relative_to(APP_FILES)}"),
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


@app.get("/sw.js")
def service_worker():
    """Shows pushes; tapping one opens Changes. Served from / so its scope is the whole site."""
    return """self.addEventListener("push",e=>{let d=e.data.json();e.waitUntil(self.registration.showNotification(d.title,{body:d.body,icon:"/apple-touch-icon.png",data:d.url}))});
self.addEventListener("notificationclick",e=>{e.notification.close();e.waitUntil(clients.openWindow(e.notification.data||"/"))});""", 200, {
        "Content-Type": "text/javascript", "Cache-Control": "no-cache"}


@app.get("/manifest.webmanifest")
def manifest_json():  # iOS only offers web push to Home Screen apps with display: standalone
    return {"name": "sidedrop", "short_name": "sidedrop", "display": "standalone", "start_url": "/", "background_color": "#c8cfd6",
            "icons": [{"src": "/apple-touch-icon.png", "sizes": "180x180", "type": "image/png"}]}


@app.post("/push")
def push_subscribe():
    """Save this phone's push subscription. Upgrades already waiting count as told, so only new releases notify."""
    udid, sub = token_udid(request.cookies.get("device", "")), request.get_json(silent=True) or {}
    if not logged_in() or not udid:
        abort(403)
    if not str(sub.get("endpoint", "")).startswith("https://") or not isinstance(sub.get("keys"), dict):
        abort(400)
    with push_lock:
        subs = load_json(PUSH)
        subs[sub["endpoint"]] = {"sub": {"endpoint": sub["endpoint"], "keys": sub["keys"]}, "udid": udid, "sent": pending(udid, signed_versions())}
        save_json(PUSH, subs)
    return "", 204


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
        save_json(INSTALLED, data)
    return "", 204


# --- admin: list the developer account's iPhones, disable the ones that shouldn't have apps any more ---

admin_fails = []  # times of recent wrong admin passwords; a right one unlocks admin on that device for as long as its login lasts


def is_admin():
    return bool(ADMIN_PASSWORD) and logged_in() and bool(session.get("admin")) and bool(session.get("csrf"))


MORE = ("Settings", "/#settings")  # back button for screens pushed from the Settings tab
ADMIN_CSS = """<style>.act{flex:none;width:auto;min-width:76px;padding:5px 10px;font-size:12px;border-radius:4px;letter-spacing:.02em}
.act.red{border-color:#8a1c1c;background:linear-gradient(#f58b8b,#d43a3a 50%,#c22424 51%,#d23333)} .off>div{opacity:.5} .row b{font-weight:700}</style>"""


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not ADMIN_PASSWORD:
        abort(404)
    if not logged_in():
        return redirect("/")
    err = None
    if request.method == "POST":
        admin_fails[:] = [t for t in admin_fails if time.time() - t < 900]
        if len(admin_fails) >= 5:  # ponytail: global lockout, not per IP; friends could lock the admin out for 15 min at worst
            err = "Too many wrong passwords. Try again in 15 minutes."
        elif hmac.compare_digest(request.form.get("password", "").encode(), ADMIN_PASSWORD.encode()):
            session["admin"], session["csrf"] = time.time(), secrets.token_urlsafe(32)
            return redirect("/admin")
        else:
            admin_fails.append(time.time())
            time.sleep(2)
            err = "Wrong admin password."
    if not is_admin():
        return page(ADMIN_CSS + """
<form class=c method=post><input type=password name=password placeholder="Admin password" aria-label="Admin password" autofocus required
 oninput="this.form.querySelector('button').disabled=!this.value"><script>addEventListener("pageshow",()=>{let i=document.querySelector("input[name=password]");i.oninput()})</script>
{% if err %}<p class=err>{{ err }}</p>{% endif %}<button disabled>Unlock</button></form>""", back=MORE, title="Manage iPhones", err=err)
    seen, me = load_json(SEEN), token_udid(request.cookies.get("device", ""))
    now = time.time()
    def ago(t):
        days = int((now - t) // 86400)
        return "today" if days < 1 else "yesterday" if days < 2 else f"{days} days ago" if days < 60 else time.strftime("%b %-d, %Y", time.localtime(t))
    devices = []
    try:
        listed = asc("GET", "/devices", params={"filter[platform]": "IOS", "limit": 200})["data"]
    except Exception as e:
        return page(ADMIN_CSS + """
<p class="c err">Apple's developer service didn't answer. Try again in a few minutes.<small>{{ e }}</small></p>""", back=MORE, title="Manage iPhones", e=str(e)[:200])
    for d in listed:
        a = d["attributes"]
        added = datetime.datetime.strptime(a["addedDate"][:10], "%Y-%m-%d") if a.get("addedDate") else None
        devices.append(dict(id=d["id"], name=a.get("name", ""), model=a.get("model") or a.get("deviceClass", ""), udid=a.get("udid", ""),
                            on=a.get("status") == "ENABLED", added=added, me=a.get("udid") == me,
                            used=f"Last used {ago(seen[a['udid']])}" if a.get("udid") in seen else "Not seen yet"))
    devices.sort(key=lambda d: (not d["on"], -(d["added"].timestamp() if d["added"] else 0)))
    return page(ADMIN_CSS + """
<div class=g>{% for d in devices %}<div class="row{{ '' if d.on else ' off' }}"><div><b>{{ d.name }}</b>{% if d.me %} · this iPhone{% endif %}
<small>{{ d.model }}{% if d.added %} · added {{ d.added.strftime('%b %-d, %Y') }}{% endif %}</small><small>{{ d.used }}{% if not d.on %} · disabled{% endif %}</small></div>
<form method=post action=/admin/device data-name="{{ d.name }}" onsubmit="{% if d.on %}if(!confirm('Disable '+this.dataset.name+'? Its apps stop opening.'))return false;{% endif %}this.querySelector('button').textContent='Saving…'">
<input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=id value="{{ d.id }}"><input type=hidden name=status value="{{ 'DISABLED' if d.on else 'ENABLED' }}">
<button class="act{{ ' red' if d.on }}">{{ 'DISABLE' if d.on else 'ENABLE' }}</button></form></div>{% endfor %}</div>
<p class=ftr>{{ devices|selectattr('on')|list|length }} enabled, {{ devices|rejectattr('on')|list|length }} disabled. Disabling takes an iPhone out of the profile, so its apps stop opening.
Apple still counts it toward the 100 until your membership renews, when you can remove it at developer.apple.com.</p>""", back=MORE, title="Manage iPhones",
                devices=devices, csrf=session["csrf"])


@app.post("/admin/device")
def admin_device():
    if not is_admin() or not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]):
        abort(403)
    did, status = request.form.get("id", ""), request.form.get("status")
    if not re.fullmatch(r"[A-Za-z0-9]{1,40}", did) or status not in ("ENABLED", "DISABLED"):
        abort(400)
    with lock:
        asc("PATCH", f"/devices/{did}", json={"data": {"type": "devices", "id": did, "attributes": {"status": status}}})
        regen_profile()
        resign(force=True)
    return redirect("/admin")


def signed_stamp():
    """Changes whenever a build is signed or replaced, so the page can tell its list is stale."""
    return max((int(p.stat().st_mtime) for p in SIGNED.glob("*.ipa")), default=0) if SIGNED.exists() else 0


@app.post("/check")
def check():
    """Page-load update check: sync sources if the last one is over a minute old, sign what's new, notify phones."""
    if not logged_in():
        abort(403)
    sync_if_stale(60)
    resign_and_notify()
    return {"stamp": signed_stamp(), "build": BUILD}


@app.post("/refresh")
def refresh():
    """Reload button: pull new releases from the sources and re-sign now, while the "Reloading Data" bar shows."""
    if not logged_in():
        abort(403)
    with sync_lock:  # waits out a background sync already running, then does a full one, so the bar stays up until it's done
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
        return page("<p class='c err'>No iPhones are registered yet.</p>", back=MORE, title="Sign")
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
            return page("<p class='c err'>Pick an .ipa or paste an http(s) link.</p>", back=MORE, title="Sign")
        with lock:
            sign_ipa(src, out)
        info = ipa_info(out)
    except Exception as e:
        out.unlink(missing_ok=True)
        return page("<p class='c err'>Couldn't sign that: {{ e }}</p>", e=e, back=MORE, title="Sign")
    finally:
        src.unlink(missing_ok=True)
    return page("""<div class=c><h3>{{ i.title }} <small>v{{ i.short }}</small></h3>
<p><a class=b href="itms-services://?action=download-manifest&url={{ m }}">Install {{ i.title }}</a></p>
<small>Link works for 7 days. Developer Mode must be on.</small></div>""",
                i=info, m=quote(signed_url(f"/m/custom/{name}.plist"), safe=""), back=MORE, title="Sign")


@app.post("/sync")
def sync_now():
    if not SYNC_TOKEN or not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {SYNC_TOKEN}"):
        abort(403)

    def run():
        sync_if_stale(0)
        resign_and_notify()
    threading.Thread(target=run, daemon=True).start()  # return right away; CI shouldn't wait on downloads
    return "", 202


def install_mark(step):
    """Note iOS fetching a manifest or app for an install page's token (?t=, outside the signature: it only names the page)."""
    t, now = request.args.get("t", ""), time.time()
    if not re.fullmatch(r"[0-9a-f]{24}", t):
        return ""
    for k in [k for k, v in INSTALLS.items() if now - v["at"] > 3600]:
        INSTALLS.pop(k, None)
    INSTALLS.setdefault(t, {"at": now})[step] = now
    return t


@app.get("/install/<t>")
def install_status(t):
    """The install page's poll: has iOS asked for the manifest (its prompt is up) and the app (it's installing)?"""
    if not logged_in():
        abort(403)
    s = INSTALLS.get(t, {})
    return {"manifest": "manifest" in s, "started": "started" in s}


@app.get("/m/<path:name>.plist")
def manifest(name):
    check_sig()
    t = install_mark("manifest")
    ipa = SIGNED / f"{name}.ipa"
    if not ipa.exists():
        abort(404)
    info = ipa_info(ipa)
    icon = (APPS / f".{name}.icon").read_text().strip() if (APPS / f".{name}.icon").exists() else ""
    return plistlib.dumps({"items": [{
        "assets": [{"kind": "software-package", "url": signed_url(f"/i/{name}.ipa", ttl=3600) + (f"&t={t}" if t else "")}]
                  + [{"kind": k, "url": icon} for k in ("display-image", "full-size-image") if icon],
        "metadata": {"bundle-identifier": info["id"], "bundle-version": info["version"],
                     "kind": "software", "title": info["title"]}}]}), 200, {"Content-Type": "text/xml"}


@app.get("/i/<path:name>.ipa")
def ipa(name):
    check_sig()
    install_mark("started")
    return send_from_directory(SIGNED, f"{name}.ipa", mimetype="application/octet-stream")


@app.get("/af/<path:rel>")
def app_file(rel):
    check_sig()
    return send_from_directory(APP_FILES, rel, as_attachment=True)  # handles Range, so downloads resume


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
