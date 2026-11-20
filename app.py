"""SideDrop: password-gated UDID enrollment, ad hoc OTA installs and private file downloads."""
import base64, datetime, gzip, hashlib, hmac, json, os, plistlib, re, secrets, subprocess, threading, time, uuid, zipfile, zlib
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
FILES = DATA / "files"  # files the admin uploads on Manage for every friend, listed on the Files tab (shown only when there are some)
HERE = Path(__file__).parent  # config files edited on GitHub; the NAS pulls and rebuilds (deploy.sh)
CONFIG = DATA / "config"  # the admin's edits of the repo's config files (Manage); the repo copies stay the defaults
conf = lambda f: CONFIG / f if (CONFIG / f).exists() else HERE / f
read_urls = lambda f: [u for u in conf(f).read_text().split() if u.startswith(("https://", "http://"))] if conf(f).exists() else []
IFIZBOX_SOURCES = "ifizbox-sources.txt"  # the sources iFizBox starts with (ifizbox_transfer)
IFIZBOX_SETTINGS = "ifizbox-settings.json"  # a JSON object of iFizBox settings it imports with them; none in the repo, set on Manage
IFIZBOX_ID = "com.ryha.ifizbox"  # signed with our certificate and sources inside it (ifizbox_identity, ifizbox_transfer)
INSTALLS = {}  # ponytail: in memory (one gunicorn worker); {token: {"at", "manifest", "started"}}: iOS's requests, for the install page
PROFILE = DATA / "adhoc.mobileprovision"
P12, ASC_KEY = DATA / "cert.p12", DATA / "asc.p8"


def data_secret():
    """SECRET_KEY left empty: one random key, made on first start and kept in the data folder so logins survive restarts."""
    f = DATA / "secret.key"
    if not f.exists():
        DATA.mkdir(parents=True, exist_ok=True)
        f.write_text(secrets.token_hex(32))
        f.chmod(0o600)
    return f.read_text().strip().encode()


PASSWORD = os.environ.get("PASSWORD", "")  # unset: the first sign-in uses DEFAULT_PASSWORD and sets it on the setup splash (/setup)
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")  # must be https with a real cert, iOS refuses otherwise
SECRET = os.environ.get("SECRET_KEY", "").encode() or data_secret()  # unset: made once and kept in the data folder
P12_PASSWORD = os.environ.get("P12_PASSWORD", "")
BUNDLE_ID = os.environ.get("BUNDLE_ID", "")  # explicit App ID with Push (apps keep their IDs); a wildcard com.you.* re-IDs apps to fit
PROFILE_NAME = os.environ.get("PROFILE_NAME", "sidedrop adhoc")
LINK_TTL = int(os.environ.get("LINK_TTL", 7 * 86400))
# AltStore sources to mirror into apps/: one per line, a URL then optionally the bundle IDs to take (else all its apps);
# third-party-sources.txt's apps are listed under "Third-party apps"
read_sources = lambda f: [(l.split()[0], l.split()[1:]) for l in conf(f).read_text().splitlines()
                          if l.startswith(("https://", "http://"))] if conf(f).exists() else []
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
INSTALLED, installed_lock = DATA / "installed.json", threading.Lock()  # {udid: {app: "short/build"}} from INSTALL taps, for Home's update rows
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
    """Signed in, with a password that hasn't been changed since (F12): the session keeps which password it used ("f" friends',
    "a" admin) and that password's version; a change bumps the version, which signs those sessions out."""
    if session.get("ok") is not True:
        return False
    pv = session.get("pv") or ("a" if session.get("admin") else "f", 0)  # sessions from before F12: version 0
    if pv[0] == "g":  # F16: a guest from a one-iPhone invite
        return guest_ok(*pv[1:3])
    kind, ver = pv[0], pv[1]
    return ver == password_ver(kind == "a")


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


def register(udid, name, invite=None):
    """invite=(token, sid): through a one-iPhone invite (F16), which the first UDID uses up; a second UDID raises InviteRefused."""
    with lock:
        if invite:
            invite_check(invite[0], udid)
        if udid not in profile_udids():
            if not asc("GET", "/devices", params={"filter[udid]": udid})["data"]:
                asc("POST", "/devices", json={"data": {"type": "devices", "attributes": {
                    "name": name[:50], "udid": udid, "platform": "IOS"}}})
            regen_profile()
            resign(force=True)
        if invite:
            invite_use(invite[0], invite[1], udid, name)


PRODUCTS, products_lock = DATA / "products.json", threading.Lock()  # {udid: "iPhone15,2"}: each iPhone's PRODUCT from registration (F15)


def save_product(udid, product):
    if product:
        with products_lock:
            save_json(PRODUCTS, {**load_json(PRODUCTS), udid: product})


def device_model(udid):
    """The model identifier for the version line: the PRODUCT it registered with, else (iPhones registered before F15)
    the one in the ASC device's name ("Sam iPhone16,1") or Apple's model, else plain "iPhone"."""
    if not udid:
        return "iPhone"
    if load_json(PRODUCTS).get(udid):
        return load_json(PRODUCTS)[udid]
    for d in cached_devices()[0] or []:
        a = d.get("attributes") or {}
        if a.get("udid") == udid:
            m = re.search(r"\b(?:iPhone|iPad|iPod)\d+,\d+\b", a.get("name") or "")
            return m.group(0) if m else a.get("model") or "iPhone"
    return "iPhone"


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
    """The profile's entitlements, with a wildcard narrowed to this app, the way Xcode signs.

    zsign copies TEAM.com.you.* verbatim, and iOS can then match the app to a development
    profile on the phone and demand Developer Mode. (Narrowing doesn't spare the phone Developer Mode: iOS 27 asks
    for it for these Ad Hoc apps too, get-task-allow false and all; F23.) An explicit App ID (with push) keeps the profile's
    application-identifier (TEAM.<App ID>), the way paid signing services sign: iOS checks it against
    the profile but not Info.plist, so the app keeps its own bundle ID and registers for push under it,
    and its developer's server can reach it. Either way the keychain group is narrowed to that one ID
    (the profile has TEAM.*), and zsign puts the same entitlements on every extension."""
    ents = embedded_plist(PROFILE.read_bytes())["Entitlements"]
    team = ents["com.apple.developer.team-identifier"]
    appid = f"{team}.{bid}" if BUNDLE_ID.endswith("*") else ents["application-identifier"]
    ents["application-identifier"] = appid
    ents["keychain-access-groups"] = [appid]
    ents["get-task-allow"] = False
    return ents


def ifizbox_identity():
    """iFizBox's sideload build imports this file from its bundle into the Keychain on first launch (its
    BundledIdentity), so friends never pick a certificate: our .p12, its password and the ad hoc profile."""
    return plistlib.dumps({"p12": P12.read_bytes(), "password": P12_PASSWORD, "profile": PROFILE.read_bytes()})


def ifizbox_transfer():
    """iFizBox imports web/transfer.link from its bundle once, on first launch: ifizbox://import?d=<base64url of gzipped JSON>
    (iFizBox's core/transfer.js), here only our sources."""
    payload = {"v": 1, "sources": read_urls(IFIZBOX_SOURCES), "settings": ifizbox_settings(), "holds": []}
    return "ifizbox://import?d=" + base64.urlsafe_b64encode(gzip.compress(json.dumps(payload).encode())).decode().rstrip("=")


def ifizbox_settings():
    try:
        s = json.loads(conf(IFIZBOX_SETTINGS).read_text())
        return s if isinstance(s, dict) else {}
    except (OSError, ValueError):
        return {}


def sign_ipa(src, out):
    """Sign one IPA. Under an explicit App ID every app keeps its Info.plist bundle ID, iFizBox's own too: it is installed as
    com.ryha.ifizbox already (it fitted the old com.ryha.* wildcard), and iFizBox signs its own IPA the old way only when the
    installed copy has another ID. Extensions stay, signed with the app's entitlements (installd wants their IDs prefixed by
    the app's, which keeping the IDs does); watch apps go (--rm_watch): no watch is in the profile."""
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
                        "-e", ents, "--rm_watch", "-o", out, tmp], check=True, timeout=600)
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
        deps = [src, PROFILE] + [p for p in [conf(IFIZBOX_SOURCES), conf(IFIZBOX_SETTINGS)] if src.stem == IFIZBOX_ID and p.exists()]  # inside it
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
                webpush(s["sub"], json.dumps({"title": "Update Available" if len(new) == 1 else f"{len(new)} Updates Available", "body": body, "url": "/#apps"}),
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


def read_commit():
    """The commit for the version line (F15): the Docker image has no .git, so deploy.sh passes it as SIDEDROP_COMMIT;
    a checkout asks git; else none, and no commit line."""
    if os.environ.get("SIDEDROP_COMMIT"):
        return os.environ["SIDEDROP_COMMIT"].strip()
    try:  # Popen, not run: test_app.py stubs subprocess.run for zsign
        with subprocess.Popen(["git", "rev-parse", "--short", "HEAD"], cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as p:
            out = p.communicate(timeout=5)[0].strip()
        return out if p.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


COMMIT = read_commit()
# The two grey lines at the bottom of Apps and Settings and in About, iFizBox's: "iPhone15,2, iOS 18.1, SideDrop (en-us)"
# then the commit. The model comes from the server (device_model); iOS and the language from the browser (VERSION_JS)
VERSION_FOOT = """<p class=ver data-m="{{ m }}">{{ m }}, SideDrop</p>{% if commit %}<p class="ver vc">{{ commit }}</p>{% endif %}"""
VERSION_JS = """<script>/* F15: iOS from the user agent, as iFizBox's device.js (iOS 26 Safari freezes it at 18.x/26.0: we show what it says) */
addEventListener("DOMContentLoaded",()=>{let o=navigator.userAgent.match(/\\b(?:iPhone|CPU) OS (\\d+)[_.](\\d+)(?:[_.](\\d+))?[^)]*like Mac OS X/),
 ios=o?o[1]+"."+o[2]+(o[3]?"."+o[3]:""):"",lang=String(navigator.language||"en").toLowerCase();
 document.querySelectorAll(".ver[data-m]").forEach(p=>p.textContent=[p.dataset.m,ios&&"iOS "+ios,"SideDrop"].filter(Boolean).join(", ")+" ("+lang+")")})</script>"""


def version_foot():
    from markupsafe import Markup
    tok = request.args.get("enrolled") or request.cookies.get("device", "")
    udid = token_udid(tok)
    return Markup(render_template_string(VERSION_FOOT, m=device_model(udid if udid in profile_udids() else None), commit=COMMIT))


# ---- F18: themes, after iFizBox's Settings > Theme (its ios6.css, palettes.css and theme-boot.js; values copied, no file shared) ----
# <html data-theme=light|dark data-palette=<name>> (plus the old .dark class on a dark page, which every .dark rule below keys on) is put
# on the page before first paint by THEME_BOOT. Each palette is one block of sidedrop's own CSS variables: Classic is also :root's and
# Gunmetal (sidedrop's dark before F18) also html.dark's, so every other palette only has to win over those. The first of each tone is
# its default. A new palette: add it here with every token its tone's first block sets (test_app.py checks).
def back_arrow(edge_top, edge_bottom, fill_top, fill_bottom, rim=".3"):
    """static/back.svg (the iOS 6 back button) with a palette's edge and fill gradients, as a data: URL."""
    stops = iter((edge_top, edge_bottom, fill_top, fill_bottom))
    svg = re.sub(r'stop-color="[^"]+"', lambda m: f'stop-color="{next(stops)}"', BACK_SVG).replace('opacity=".3"', f'opacity="{rim}"')
    return 'url("data:image/svg+xml;base64,' + base64.b64encode(svg.encode()).decode() + '")'


BACK_SVG = (Path(__file__).with_name("static") / "back.svg").read_text().strip()
pin = lambda a, b: f"repeating-linear-gradient(90deg,{a} 0 2.5px,{b} 2.5px 8px)"  # the pinstripe: 2.5px dark, 5.5px light
nav = lambda edge, hi, bar, status: f"--navedge:{edge};--navhi:{hi};--navbg:{bar};--statbg:{status};"
TABS_BLACK = ("linear-gradient(rgba(0,0,0,.7),rgba(0,0,0,.7)) top/100% 1px no-repeat,linear-gradient(rgba(255,255,255,.1),rgba(255,255,255,.1)) 0 1px/100% 1px no-repeat,"
              "linear-gradient(#2f2f2f,#151515 49.5%,#000 49.5%) 0 1px/100% 48px no-repeat,#000")  # the kit's black tab bar
# name: (tone, label, Safari's top-bar colour (iFizBox's THEME_COLORS), tokens)
PALETTES = {
    "classic": ("light", "Classic", "#4f698b",
        "--text:#000;--plain:#fff;--ground:#c8cfd6;--pin:" + pin("#cbd0da", "#ced3dc") + ";--head:#4c566c;--emboss:0 1px 0 rgba(255,255,255,.75);--acc:#385487;"
        "--select:linear-gradient(#85a7e9,#2765db);--sub:#7f7f7f;--mute:#6d7480;--table:#f7f7f7;--line:#b7b9bd;--div:#c9c9c9;--divhi:#fff;--sep:#e0e0e0;"
        + nav("#2d3642", "#eff2f7", "linear-gradient(#bdcbdc,#597498)", "linear-gradient(#4f698b,#3f5b7f)") +
        "--barbtn:linear-gradient(#99aac2,#41618e);--barpress:linear-gradient(#8b97af,#283e6b);--baredge:#2f4769;--baredgetop:#343a42;--barpe:#1c2c4f;--barpet:#30343c;"
        "--back:url(/static/back.svg);--backp:url(/static/back-pressed.svg);--greybtn:linear-gradient(#fdfdfd,#e3e6ea);--tabbar:" + TABS_BLACK + ";"
        "--cyh:linear-gradient(rgba(152,165,177,.92),rgba(184,193,201,.92))"),
    "sepia": ("light", "Sepia", "#7a5c36",  # iBooks 2012's sepia page, a leather-brown nav bar
        "--text:#3b2f22;--plain:#fbf4e4;--ground:#ebdfc5;--pin:" + pin("#e6d9bd", "#ebdfc5") + ";--head:#6b5434;--emboss:0 1px 0 rgba(255,250,235,.75);--acc:#8a5a2b;"
        "--select:linear-gradient(#c9a26e,#93652f);--sub:#806b52;--mute:#806b52;--table:#fbf4e4;--line:#c2b08a;--div:#dccdab;--divhi:#fffaf0;--sep:#e5d9be;"
        + nav("#3e2e1a", "#f5ecdc", "linear-gradient(#d2bf9c,#8c6c43)", "linear-gradient(#7a5c36,#6a4e2c)") +
        "--barbtn:linear-gradient(#c4a77d,#7f5f36);--barpress:linear-gradient(#b39469,#5f4424);--baredge:#5a4224;--baredgetop:#3f3a33;--barpe:#5a4224;--barpet:#3f3a33;"
        f"--back:{back_arrow('#3f3a33', '#5a4224', '#c4a77d', '#7f5f36')};--backp:{back_arrow('#3a3530', '#4a361c', '#b39469', '#5f4424')};"
        "--greybtn:linear-gradient(#fdf9ef,#ece2cb);--tabbar:" + TABS_BLACK + ";"
        "--cyh:linear-gradient(rgba(146,118,80,.9),rgba(190,166,128,.9) 5%,rgba(184,160,122,.9) 94%,rgba(150,124,88,.9))"),
    "solarized": ("light", "Solarized", "#2a74a8",  # Solarized Light: base3 tables on base2, a Solarized-blue nav bar
        "--text:#073642;--plain:#fdf6e3;--ground:#eee8d5;--pin:" + pin("#e9e2cd", "#eee8d5") + ";--head:#4d6168;--emboss:0 1px 0 rgba(253,246,227,.8);--acc:#1b6fab;"
        "--select:linear-gradient(#5aa9e0,#1f73b0);--sub:#586e75;--mute:#586e75;--table:#fdf6e3;--line:#c9c1aa;--div:#e2dbc4;--divhi:#fffcf2;--sep:#eee8d5;"
        + nav("#0f3d5c", "#e6f2fa", "linear-gradient(#9fcbea,#2f7fb8)", "linear-gradient(#2a74a8,#22679b)") +
        "--barbtn:linear-gradient(#79b3dd,#22679b);--barpress:linear-gradient(#6aa0c8,#1a547f);--baredge:#1d4f73;--baredgetop:#2f3a40;--barpe:#1d4f73;--barpet:#2f3a40;"
        f"--back:{back_arrow('#2f3a40', '#1d4f73', '#79b3dd', '#22679b')};--backp:{back_arrow('#2a343a', '#163f5d', '#6aa0c8', '#1a547f')};"
        "--greybtn:linear-gradient(#fffcf2,#eee8d5);--tabbar:" + TABS_BLACK + ";"
        "--cyh:linear-gradient(rgba(101,123,131,.9),rgba(147,161,161,.9) 5%,rgba(140,155,156,.9) 94%,rgba(106,126,132,.9))"),
    "oled": ("dark", "OLED Black", "#000",  # pure black ground and bars, near-black tables, no pinstripe or emboss
        "--text:#fff;--plain:#000;--ground:#000;--pin:#000;--head:#d6d6db;--emboss:none;--acc:#5fa2ff;--sub:#8d8d93;--mute:#8d8d93;"
        "--table:#0e0e0f;--line:#1f1f22;--div:#1c1c1f;--divhi:transparent;--sep:#1c1c1f;--inset:transparent;--rowbg:#0e0e0f;--keyline:#1c1c1f;"
        + nav("#1a1a1c", "rgba(255,255,255,.16)", "linear-gradient(#333336,#151517 50%,#070708 51%,#000)", "#000") +
        "--barbtn:linear-gradient(#3a3a3e,#121214);--barpress:linear-gradient(#1c1c1f,#050506);--baredge:#000;--baredgetop:#000;--barpe:#000;--barpet:#000;"
        f"--back:{back_arrow('#000', '#000', '#3a3a3e', '#121214', '.12')};--backp:var(--back);--tabbar:linear-gradient(#1c1c1e,#1c1c1e) top/100% 1px no-repeat,#000;"
        "--cyh:linear-gradient(rgba(36,36,40,.94),rgba(22,22,24,.94) 5%,rgba(14,14,15,.94) 94%,rgba(0,0,0,.94));"
        "--field:#1c1c1f;--fieldtext:#d6d6db;--btn:linear-gradient(#3a3a3e,#1c1c1f 90%,#121214);--btnhi:transparent;--greybtn:linear-gradient(#3a3a3e,#121214);"
        "--getc:#d6d6db;--getoff:#8d8d93;--getdown:linear-gradient(#1c1c1f,#0e0e0f);--steps:linear-gradient(#000,#0e0e0f);--greenbg:#0f2414;--greenline:#1c1c1f;"
        "--warnbg:#241f08;--warnedge:#5a4f1a;--warntext:#fff3b0;--badbg:#2a1212;--badedge:#610d14;--badtext:#ff7b6b;"
        "--swtrack:linear-gradient(#0e0e0f,#1f1f22);--swoff:#8d8d93;--swon:linear-gradient(#0b4fb0,#3d8cf0);--swknob:linear-gradient(#55555b,#2a2a2e);--swheld:linear-gradient(#444449,#1f1f22)"),
    "gunmetal": ("dark", "Gunmetal", "#5f656f",  # sidedrop's dark before F18: gunmetal bars, dark pinstripes, inverted emboss
        "--text:#e6e8eb;--plain:#2c2f34;--ground:#1d1f23;--pin:repeating-linear-gradient(90deg,#1b1d21 0 5px,#202227 5px 7px);--head:#8b9099;--emboss:0 -1px 0 #000;"
        "--acc:#6fa8ff;--sub:#8b9099;--mute:#8b9099;--table:#2c2f34;--line:#0d0e10;--div:#17191c;--divhi:rgba(255,255,255,.07);--sep:#17191c;--inset:rgba(255,255,255,.06);"
        "--rowbg:linear-gradient(#34373d,#2a2d32);--keyline:#3a3d42;"
        + nav("#0b0c0e", "#7a808a", "linear-gradient(#5f656f,#3b4048 50%,#30343b 51%,#23262b)", "#000") +
        "--barbtn:linear-gradient(#4a4f58,#24272c);--barpress:linear-gradient(#2a2d32,#121316);--baredge:#111;--baredgetop:#111;--barpe:#111;--barpet:#111;"
        "--back:url(/static/back-dark.svg);--backp:var(--back);--tabbar:" + TABS_BLACK + ";--cyh:linear-gradient(rgba(86,92,102,.94),rgba(58,62,70,.94));"
        "--field:#1f2125;--fieldtext:#ccc;--btn:linear-gradient(#4a4f58,#2c2f34 50%,#24272c 51%,#2c2f34);--btnhi:rgba(255,255,255,.15);--greybtn:linear-gradient(#4a4f58,#2c2f34);"
        "--getc:#c9ced5;--getoff:#8b9099;--getdown:linear-gradient(#1f2125,#2a2d32);--steps:linear-gradient(#26292d,#2c2f34);--greenbg:#24302a;--greenline:#1a221d;"
        "--warnbg:#3a3220;--warnedge:#6b5a26;--warntext:#f0c870;--badbg:#3a2020;--badedge:#6b2626;--badtext:#ff8a8a;"
        "--swtrack:linear-gradient(#2b2e33,#3c4047);--swoff:#9aa0a8;--swon:linear-gradient(#0b4fb0,#3d8cf0);--swknob:linear-gradient(#6a6f78,#3c4047);--swheld:linear-gradient(#55595f,#2e3136)"),
    "midnight": ("dark", "Midnight", "#0a1424",  # deep navy ground and bars, navy tables, cool blue-grey text
        "--text:#fff;--plain:#0c1628;--ground:#0a1424;--pin:" + pin("#0a1424", "#0c172a") + ";--head:#c3cde0;--emboss:0 -1px 0 rgba(0,0,0,.8);--acc:#7fb0ff;"
        "--sub:#93a0ba;--mute:#93a0ba;--table:#121d31;--line:#050a14;--div:#0a1322;--divhi:rgba(255,255,255,.05);--sep:#0a1322;--inset:rgba(255,255,255,.05);"
        "--rowbg:#121d31;--keyline:#1a2740;"
        + nav("#050a14", "rgba(255,255,255,.18)", "linear-gradient(#2c3d5f,#18253e 50%,#0f1a2f 51%,#0a1424)", "#0a1424") +
        "--barbtn:linear-gradient(#34476b,#142038);--barpress:linear-gradient(#1c2a44,#0a1222);--baredge:#050a14;--baredgetop:#050a14;--barpe:#050a14;--barpet:#050a14;"
        f"--back:{back_arrow('#050a14', '#050a14', '#34476b', '#142038', '.12')};--backp:var(--back);--tabbar:linear-gradient(#1a2740,#1a2740) top/100% 1px no-repeat,#070e1b;"
        "--cyh:linear-gradient(rgba(42,58,90,.94),rgba(30,44,70,.94) 5%,rgba(22,34,56,.94) 94%,rgba(8,14,26,.94));"
        "--field:#18253e;--fieldtext:#c3cde0;--btn:linear-gradient(#34476b,#1c2a44 90%,#142038);--btnhi:rgba(255,255,255,.05);--greybtn:linear-gradient(#34476b,#142038);"
        "--getc:#c3cde0;--getoff:#93a0ba;--getdown:linear-gradient(#18253e,#121d31);--steps:linear-gradient(#0c1628,#121d31);--greenbg:#102a24;--greenline:#0a1322;"
        "--warnbg:#2a2510;--warnedge:#5a4f1a;--warntext:#fff3b0;--badbg:#2a1212;--badedge:#610d14;--badtext:#ff7b6b;"
        "--swtrack:linear-gradient(#0a1322,#18253e);--swoff:#93a0ba;--swon:linear-gradient(#1d56b8,#4a8ef0);--swknob:linear-gradient(#56688c,#26344f);--swheld:linear-gradient(#45577a,#1c2a44)"),
    "linen": ("dark", "Linen", "#000",  # iOS 6's Notification Center linen (woven in CSS) behind charcoal tables, the kit's black bars
        "--text:#fff;--plain:#2a2c30;--ground:#36383d;--pin:repeating-linear-gradient(0deg,rgba(255,255,255,.035) 0 1px,rgba(0,0,0,0) 1px 2px,rgba(0,0,0,.06) 2px 3px),"
        "repeating-linear-gradient(90deg,rgba(0,0,0,.09) 0 1px,rgba(255,255,255,.02) 1px 2px,rgba(0,0,0,0) 2px 3px),repeating-linear-gradient(45deg,rgba(255,255,255,.015) 0 1px,rgba(0,0,0,0) 1px 5px),#36383d;"
        "--head:#e1e3e8;--emboss:0 -1px 0 rgba(0,0,0,.85);--acc:#a9c4f2;--sub:#b9bdc5;--mute:#b9bdc5;--table:#2a2c30;--line:#121315;--div:#1b1c1f;--divhi:rgba(255,255,255,.06);"
        "--sep:#1b1c1f;--inset:rgba(255,255,255,.06);--rowbg:#2a2c30;--keyline:#3a3c41;"
        + nav("#000", "rgba(255,255,255,.18)", "linear-gradient(#4c4c4c,#262626 50%,#141414 51%,#000)", "#000") +
        "--barbtn:linear-gradient(#4a4d54,#222428);--barpress:linear-gradient(#2a2c30,#111214);--baredge:#111;--baredgetop:#111;--barpe:#111;--barpet:#111;"
        f"--back:{back_arrow('#111', '#111', '#4a4d54', '#222428', '.12')};--backp:var(--back);--tabbar:" + TABS_BLACK + ";"
        "--cyh:linear-gradient(rgba(64,66,72,.94),rgba(50,52,57,.94) 5%,rgba(40,42,46,.94) 94%,rgba(18,19,21,.94));"
        "--field:#232528;--fieldtext:#d6d9e0;--btn:linear-gradient(#55585f,#3a3c41 90%,#303236);--btnhi:rgba(255,255,255,.06);--greybtn:linear-gradient(#4a4d54,#222428);"
        "--getc:#e1e3e8;--getoff:#b9bdc5;--getdown:linear-gradient(#232528,#2a2c30);--steps:linear-gradient(#232528,#2a2c30);--greenbg:#243a2a;--greenline:#1b1c1f;"
        "--warnbg:#3e3714;--warnedge:#7a6c26;--warntext:#fff3b0;--badbg:#4a2a2a;--badedge:#610d14;--badtext:#ff7b6b;"
        "--swtrack:linear-gradient(#1b1c1f,#303236);--swoff:#a2a6ae;--swon:linear-gradient(#0b4fb0,#3d8cf0);--swknob:linear-gradient(#6a6d74,#3a3c41);--swheld:linear-gradient(#55585f,#2a2c30)"),
    "nord": ("dark", "Nord", "#2e3440",  # Polar Night ground, bars and tables, Snow Storm text, Frost accents, Aurora status colours
        "--text:#eceff4;--plain:#2e3440;--ground:#2e3440;--pin:" + pin("#2e3440", "#313744") + ";--head:#d8dee9;--emboss:0 -1px 0 rgba(0,0,0,.5);--acc:#88c0d0;"
        "--sub:#aeb7c7;--mute:#aeb7c7;--table:#3b4252;--line:#232831;--div:#2e3440;--divhi:rgba(255,255,255,.05);--sep:#2e3440;--inset:rgba(255,255,255,.05);"
        "--rowbg:#3b4252;--keyline:#4c566a;"
        + nav("#1f232c", "rgba(255,255,255,.15)", "linear-gradient(#4c566a,#3b4252 50%,#343a48 51%,#2b303b)", "#2e3440") +
        "--barbtn:linear-gradient(#4c566a,#2e3440);--barpress:linear-gradient(#353c4a,#232831);--baredge:#1f232c;--baredgetop:#1f232c;--barpe:#1f232c;--barpet:#1f232c;"
        f"--back:{back_arrow('#1f232c', '#1f232c', '#4c566a', '#2e3440', '.12')};--backp:var(--back);"
        "--tabbar:linear-gradient(#1f232c,#1f232c) top/100% 1px no-repeat,linear-gradient(#3b4252,#2b303b) 0 1px/100% 48px no-repeat,#2b303b;"
        "--cyh:linear-gradient(rgba(76,86,106,.94),rgba(67,76,94,.94) 5%,rgba(59,66,82,.94) 94%,rgba(35,40,49,.94));"
        "--field:#343a48;--fieldtext:#d8dee9;--btn:linear-gradient(#4c566a,#3b4252 90%,#343a48);--btnhi:rgba(255,255,255,.05);--greybtn:linear-gradient(#4c566a,#2e3440);"
        "--getc:#d8dee9;--getoff:#aeb7c7;--getdown:linear-gradient(#343a48,#3b4252);--steps:linear-gradient(#343a48,#3b4252);--greenbg:#34403a;--greenline:#2e3440;"
        "--warnbg:#4a4434;--warnedge:#8a7a50;--warntext:#ebcb8b;--badbg:#4a3439;--badedge:#69353a;--badtext:#eea2a8;"
        "--swtrack:linear-gradient(#2b303b,#3b4252);--swoff:#aeb7c7;--swon:linear-gradient(#5e81ac,#88c0d0);--swknob:linear-gradient(#6b768c,#434c5e);--swheld:linear-gradient(#5b657a,#3b4252)"),
    "dracula": ("dark", "Dracula", "#21222c",  # #282a36 ground, #44475a bars and lines, purple headers, pink links, Dracula status colours
        "--text:#f8f8f2;--plain:#282a36;--ground:#282a36;--pin:" + pin("#282a36", "#2b2d3a") + ";--head:#bd93f9;--emboss:0 -1px 0 rgba(0,0,0,.6);--acc:#ff79c6;"
        "--sub:#a4abcf;--mute:#a4abcf;--table:#343746;--line:#191a21;--div:#282a36;--divhi:rgba(255,255,255,.04);--sep:#282a36;--inset:rgba(255,255,255,.05);"
        "--rowbg:#343746;--keyline:#3a3d4d;"
        + nav("#15161c", "rgba(255,255,255,.15)", "linear-gradient(#4f5268,#383b4c 50%,#2c2e3b 51%,#21222c)", "#21222c") +
        "--barbtn:linear-gradient(#5a5e78,#2c2e3b);--barpress:linear-gradient(#383b4c,#1e1f28);--baredge:#15161c;--baredgetop:#15161c;--barpe:#15161c;--barpet:#15161c;"
        f"--back:{back_arrow('#15161c', '#15161c', '#5a5e78', '#2c2e3b', '.12')};--backp:var(--back);"
        "--tabbar:linear-gradient(#15161c,#15161c) top/100% 1px no-repeat,linear-gradient(#383b4c,#21222c) 0 1px/100% 48px no-repeat,#21222c;"
        "--cyh:linear-gradient(rgba(80,84,106,.94),rgba(68,71,90,.94) 5%,rgba(56,59,76,.94) 94%,rgba(25,26,33,.94));"
        "--field:#44475a;--fieldtext:#f8f8f2;--btn:linear-gradient(#5a5e78,#44475a 90%,#383b4c);--btnhi:rgba(255,255,255,.04);--greybtn:linear-gradient(#5a5e78,#2c2e3b);"
        "--getc:#f8f8f2;--getoff:#a4abcf;--getdown:linear-gradient(#2c2e3b,#343746);--steps:linear-gradient(#2c2e3b,#343746);--greenbg:#1f3a2a;--greenline:#282a36;"
        "--warnbg:#3e3a20;--warnedge:#8a8440;--warntext:#f1fa8c;--badbg:#4a2630;--badedge:#772828;--badtext:#ff7b7b;"
        "--swtrack:linear-gradient(#21222c,#383b4c);--swoff:#a4abcf;--swon:linear-gradient(#8a5fe0,#bd93f9);--swknob:linear-gradient(#6c708c,#44475a);--swheld:linear-gradient(#5a5e78,#383b4c)"),
}
THEMES = {t: [n for n, p in PALETTES.items() if p[0] == t] for t in ("light", "dark")}  # in menu order; [0] is the default
THEMES_CSS = "/* F18 palettes (PALETTES in app.py) */\n" + "\n".join(
    (":root," if n == "classic" else "html.dark," if n == "gunmetal" else "") + f"html[data-theme={t}][data-palette={n}]{{{css}}}"
    for n, (t, _, _, css) in PALETTES.items()) + "\n.tabs{background:var(--tabbar)}"
# Before first paint: Mode (localStorage.mode: light, dark or auto) picks the tone, lightTheme and darkTheme the palette in each. Before F18 a
# Dark Mode switch stored localStorage.dark = 1 or 0, read here as Mode Dark or Light until a Mode is picked; with neither, Mode is Automatic
# (it followed the phone before, so nobody's page changes tone). theme() runs again when the phone's appearance flips and after a pick.
THEME_BOOT = ("<script>/* F18 themes: THEME_BOOT in app.py */\nconst THEMES=" + json.dumps(THEMES, separators=(",", ":")) + ",THEME_COLORS="
              + json.dumps({n: p[2] for n, p in PALETTES.items()}, separators=(",", ":")) + """;
function themeState(){let s={};try{s={mode:localStorage.mode,light:localStorage.lightTheme,dark:localStorage.darkTheme,old:localStorage.dark}}catch(e){}
 return{mode:["light","dark","auto"].includes(s.mode)?s.mode:s.old=="1"?"dark":s.old=="0"?"light":"auto",
  light:THEMES.light.includes(s.light)?s.light:THEMES.light[0],dark:THEMES.dark.includes(s.dark)?s.dark:THEMES.dark[0]}}
var themeTone=null;  /* F20: "light" or "dark" while Settings > Theme > Light or Dark is open, its live preview, whatever Mode says */
function theme(){let s=themeState(),h=document.documentElement,dk=themeTone?themeTone=="dark":s.mode=="dark"||s.mode=="auto"&&matchMedia("(prefers-color-scheme: dark)").matches,p=dk?s.dark:s.light;
 h.classList.toggle("dark",dk);h.setAttribute("data-theme",dk?"dark":"light");h.setAttribute("data-palette",p);
 document.querySelector("meta[name=theme-color]").content=THEME_COLORS[p];s.tone=dk?"dark":"light";return s}  /* Safari's top bar matches the status bar */
theme();matchMedia("(prefers-color-scheme: dark)").addEventListener("change",()=>{theme();if(window.themeMarks)themeMarks()})</script>""")
# Settings > Theme's checklists (theme_page below): a checkmark on the one in use (iOS 6's UITableViewCellAccessoryCheckmark, the row's
# label turning blue with it). Each theme row has a little swatch: its bar over its ground.
THEMES_CSS += """
.ck{cursor:pointer;color:var(--text)} .ck[aria-checked=true]{color:var(--acc)} .ck .sws{flex:none;width:26px;height:26px;border-radius:5px;box-sizing:border-box;border:1px solid rgba(0,0,0,.45);box-shadow:0 1px 0 var(--divhi)}
.ck[aria-checked=true]:after{content:"";flex:none;width:15px;height:14px;background:currentColor;-webkit-mask:var(--tick) center/contain no-repeat;mask:var(--tick) center/contain no-repeat}
:root{--tick:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 15 14'%3E%3Cpath d='M1 7.6 3.2 5.5 6 8.2 12.4 0.8 14.5 2.6 6.1 12.6Z'/%3E%3C/svg%3E")}"""

# ---- F20: Settings > Theme as iFizBox's (its screens/settings.js modeControl, listPage and themePreview; settings.css; ios6.css) ----
# The segmented control: iFizBox's ios6.css .store-segmented (UISegmentedControl's plain style, sampled from the 4S's UISegmentButton,
# UISegmentButtonHighlighted and UISegmentDivider art) at settings.css .settings-segmented's group size (44px, 9.5px corners, 15px labels).
# Its colours are tokens per palette: Classic the kit's (ios6.css); the dark ones ios6.css/palettes.css --dk-seg, --dk-seg-pressed,
# --dk-btn-edge and --dk-ctl-hi; Sepia and Solarized palettes.css --lt-seg, --lt-seg-pressed and --lt-seg-edge. The blue selected segment
# is the kit's in every palette, as in iFizBox. (segment, held segment, edge, divider, white line under it, label, label emboss)
SEG = {
    "classic": ("linear-gradient(#fbfbfb,#fbfbfb 5%,#cccccc 90%,#bdbdbd)", "linear-gradient(#e6e6e6,#c2c2c2 90%,#b3b3b3)", "#9e9e9e", "#aeaeae",
                "rgba(255,255,255,.28)", "#4c566c", "0 1px 0 #fff"),
    "sepia": ("linear-gradient(#fdf9ef,#fdf9ef 5%,#e0d2b4 90%,#d2c19e)", "linear-gradient(#ece2cb,#d2c19e 90%,#c5b28c)", "#b8a37c", "#b8a37c",
              "rgba(255,255,255,.28)", "#6b5434", "0 1px 0 #fff"),
    "solarized": ("linear-gradient(#fffcf2,#fffcf2 5%,#e4ddc8 90%,#d6cfb8)", "linear-gradient(#eee8d5,#d6cfb8 90%,#cac2aa)", "#b9b29c", "#b9b29c",
                  "rgba(255,255,255,.28)", "#4d6168", "0 1px 0 #fff"),
    "oled": ("linear-gradient(#3a3a3e,#1c1c1f 90%,#121214)", "linear-gradient(#1c1c1f,#0a0a0b)", "#000", "#000", "transparent", "#d6d6db", "none"),
    "gunmetal": ("linear-gradient(#5a5f68,#3c4047 90%,#33363c)", "linear-gradient(#45494f,#2b2e33)", "#111", "#111", "rgba(255,255,255,.08)",
                 "#e4e8ef", "0 -1px 0 rgba(0,0,0,.8)"),
    "midnight": ("linear-gradient(#34476b,#1c2a44 90%,#142038)", "linear-gradient(#1c2a44,#0a1222)", "#050a14", "#050a14", "rgba(255,255,255,.05)",
                 "#c3cde0", "0 -1px 0 rgba(0,0,0,.8)"),
    "linen": ("linear-gradient(#55585f,#3a3c41 90%,#303236)", "linear-gradient(#3a3c41,#232528)", "#111", "#111", "rgba(255,255,255,.06)",
              "#e1e3e8", "0 -1px 0 rgba(0,0,0,.8)"),
    "nord": ("linear-gradient(#4c566a,#3b4252 90%,#343a48)", "linear-gradient(#353c4a,#2b303b)", "#1f232c", "#1f232c", "rgba(255,255,255,.05)",
             "#d8dee9", "none"),
    "dracula": ("linear-gradient(#5a5e78,#44475a 90%,#383b4c)", "linear-gradient(#383b4c,#282a36)", "#15161c", "#15161c", "rgba(255,255,255,.04)",
                "#bd93f9", "none"),
}
# A theme's swatch in its checklist: iFizBox's core/settings.js `swatch` (its bar colour over its ground), as settings.css .theme-swatch draws it.
SWATCH = {"classic": ("#6f88a8", "#c5ccd4"), "sepia": ("#a5865a", "#ebdfc5"), "solarized": ("#4b93c8", "#eee8d5"), "oled": ("#000", "#0e0e0f"),
          "gunmetal": ("#5f656f", "#3b3f46"), "midnight": ("#18253e", "#121d31"), "linen": ("#262626", "#36383d"), "nord": ("#3b4252", "#2e3440"),
          "dracula": ("#383b4c", "#282a36")}
THEMES_CSS += "\n/* F20 segmented control tokens (SEG in app.py) */\n" + "\n".join(
    (":root," if n == "classic" else "") + f"html[data-palette={n}]{{--seg:{s};--segp:{p};--segedge:{e};--segdiv:{d};--seghi:{h};--segtext:{t};--segemb:{m}}}"
    for n, (s, p, e, d, h, t, m) in SEG.items()) + """
.seg{display:flex;height:44px;border-radius:9.5px;overflow:hidden;box-sizing:border-box;border:1px solid var(--segedge);box-shadow:0 1px 0 var(--seghi)}
.seg button{flex:1;width:auto;min-width:0;height:100%;margin:0;padding:0 6px;border:0;border-radius:0;box-shadow:none;cursor:pointer;
 font:bold 15px/42px "Helvetica Neue",Helvetica,Arial,sans-serif;color:var(--segtext);text-shadow:var(--segemb);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;
 background:var(--seg);background-origin:border-box}
.seg button+button{border-left:1px solid var(--segdiv)}
.seg button.is-pressed:not([aria-checked=true]){background:var(--segp);background-origin:border-box}
.seg button[aria-checked=true]{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.4);background:linear-gradient(#22488c,#2e5fb5 5%,#3d7adf 14%,#407ee6 23%,#407ee6 41%,#6ea4f9 88%,#487bcc 96%,#4a85d6);background-origin:border-box}
.seg button[aria-checked=true]+button,.seg button+button[aria-checked=true]{border-left-color:#093786}
.seg:has(>[aria-checked=true]:first-child){border-left-color:#093786} .seg:has(>[aria-checked=true]:last-child){border-right-color:#093786}
.seg.sm{height:30px;border-radius:5px} .seg.sm button{font-size:13px;line-height:28px}
/* iFizBox's F205 row icons in a Settings row (ios6.css .cell-icon.row-icon): the 29pt tile 7pt in from the row's edge, the label 11pt after
   it, labels bold as ios6.css .cell-label; .mrow pushes a page (the chevron, "arrows copy", 10.5px in from the edge) */
.rico{flex:none;display:block;width:29px;height:29px} .row:has(>.rico){padding-left:7px;gap:11px} .irow>div{font-weight:700}
.g.grp{margin-top:23px}  /* ios6.css .group + .group: the next group of rows, no header */
.g a.mrow,.g a.irow{color:var(--text)} .mrow>div{font-weight:700}
.mrow:after{content:"";flex:none;width:9px;height:13px;margin-right:.5px;background:var(--chev) center/contain no-repeat}
.mrow.is-pressed:after,.mrow.sel:after{filter:brightness(0) invert(1)}
.g a.row.sel,.dark .g a.row.sel{background:var(--select);color:#fff;text-shadow:none} .g a.row.sel *{color:#fff}
.mrow .val{flex:none;max-width:60%;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-weight:400;color:var(--acc)}
.kv:has(>.rico){align-items:center;justify-content:flex-start;padding:7px 12px 7px 7px;gap:11px} .kv>.rico+b{flex:1}
details>summary:has(>.rico){justify-content:flex-start;padding-left:7px;gap:11px} details>summary>.rico+span{flex:1}
/* the checklist's swatch, as iFizBox's settings.css .theme-swatch: 24px, 5px corners, a hairline edge so OLED Black shows on a black row */
.ck .sws{width:24px;height:24px;border:0;box-shadow:inset 0 0 0 1px rgba(127,127,127,.45)}
/* Theme > Light / Dark's preview (iFizBox's themePreview): a sample of the controls in the theme showing, inert */
.tpv{pointer-events:none;border:1px solid var(--line);border-radius:9.5px;overflow:hidden;background:var(--pin);background-color:var(--ground)}
.tpv .nav.nav{position:relative;z-index:0;  /* .nav.nav: over .layer .nav's absolute, which comes later in the page */padding:0 7px;height:44px;box-sizing:border-box;
 background:linear-gradient(var(--navedge),var(--navedge)) bottom/100% 1px no-repeat,linear-gradient(var(--navhi),var(--navhi)) top/100% 1px no-repeat,var(--navbg)}
.tpv .nav h1{max-width:none} .tpv .nav .bar{display:block}
.tpv .seg{margin:10px} .tpv .tpb{display:flex;align-items:center;gap:10px;padding:0 10px} .tpv .tpb .badge{position:relative;top:0;left:0}
.tpv>.g{margin:0 10px} .tpv>.hdr{margin-top:14px} .tpv>.ftr{margin-bottom:12px}"""

PAGE = """<!doctype html><meta charset=utf-8><meta name=build content=%BUILD%><meta name=viewport content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no,viewport-fit=cover">
<title>SideDrop</title><meta name=description content="Share an Apple developer account with friends and sideload apps.">
<meta property=og:title content=SideDrop><meta property=og:description content="Share an Apple developer account with friends and sideload apps."><meta property=og:site_name content=SideDrop>
<meta property=og:type content=website><meta property=og:url content="%PUBLIC_URL%/"><meta property=og:image content="%PUBLIC_URL%/static/og.png"><meta property=og:image:width content=1200><meta property=og:image:height content=630>
<meta name=twitter:card content=summary_large_image><meta name=twitter:image content="%PUBLIC_URL%/static/og.png"><link rel=apple-touch-icon href=/apple-touch-icon.png><link rel=manifest href=/manifest.webmanifest><meta name=theme-color content="#4f698b"><meta name=apple-mobile-web-app-capable content=yes><meta name=apple-mobile-web-app-status-bar-style content=black><meta name=apple-mobile-web-app-title content=SideDrop>
%THEME_BOOT%
<style>
/* 2012 iOS look (pinstripes, glossy bars, App Store buttons). Colours that change with the theme are variables, set per palette by
   THEMES_CSS at the end of this sheet (Classic's are :root's, Gunmetal's html.dark's). */
:root{color-scheme:light;--gloss:linear-gradient(rgba(255,255,255,.55),rgba(255,255,255,.12) 50%,rgba(255,255,255,0) 51%);
 --tabh:calc(49px + env(safe-area-inset-bottom));
 --bluebtn:linear-gradient(#7aa5ef,#3b72d4 50%,#2861c9 51%,#3a73da);--greenbtn:linear-gradient(#8fd96b,#4caa2b 50%,#3c9a1d 51%,#4cae2a);
 --chev:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 17.5 26.4'%3E%3Cpath fill='%237f7f7f' d='M.07 4.23 9.12 13.27 0 22.26 4.12 26.38 17.47 13.03 4.43 0Z'/%3E%3C/svg%3E");background:var(--ground)}
/* fixed backdrop: stays put while iOS rubber-bands the page, so the bounce shows pinstripes instead of a flat color */
body::before{content:"";position:fixed;inset:0;z-index:-1;background:var(--pin)}
/* always 1px taller than the screen, so short pages still rubber-band like native */
#scr{scrollbar-width:none} #scr::-webkit-scrollbar{display:none} .page{min-height:calc(100% + 1px)}
/* scroll indicator, drawn by us between the nav and tab bar (iOS doesn't show one for a scrolling body) */
/* UIKit's UIScrollerIndicatorDefault: 5pt black at 50% with a 1pt 15% white ring, fully rounded (7pt overall) */
#sb{position:fixed;right:2px;z-index:6;width:5px;border-radius:3px;background:rgba(0,0,0,.5);box-shadow:0 0 0 1px rgba(255,255,255,.15);opacity:0;transition:opacity .3s,width .1s;pointer-events:none;will-change:transform}
/* the pages scroll in #scr, a fixed full-screen box, as iFizBox's screens do; <html> and <body> never scroll, and the bars and alerts are outside
   it, above. iOS 26 blurs the top edge of a scroller in the home-screen app, with no switch for it: over a nav bar inside the scroller, or the
   whole page, that washed the bar out; under an opaque bar on top it doesn't show. A fixed box also follows the screen through a rotation, where
   body at 100% went stale (top cut off, bars not taking taps). */
html,body{height:100%;overflow:hidden;margin:0}
body{font:17px/1.35 "Helvetica Neue",Helvetica,Arial,sans-serif;color:var(--text);-webkit-font-smoothing:antialiased}
#scr{position:fixed;inset:0;box-sizing:border-box;overflow-y:auto;overscroll-behavior:contain;
 padding:calc(56px + env(safe-area-inset-top)) max(10px,env(safe-area-inset-right),(100% - 30rem)/2) calc(72px + env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left),(100% - 30rem)/2)}
a{color:var(--acc);text-decoration:none} small,.m{color:var(--mute)} small{font-size:13px} .err{color:#d70015} h2{font-size:19px;margin:0}
html{touch-action:manipulation} /* no double-tap zoom; pinch is blocked by the viewport and gesturestart */
:focus,:focus-visible{outline:none}  /* as iFizBox: a tapped button kept a ring, which iOS 6 never draws */
a,img{-webkit-user-drag:none}  /* iFizBox's B24: holding a link row or an image lifted WebKit's skewed drag preview */
.nav{position:fixed;top:0;left:0;right:0;z-index:5;height:44px;padding:env(safe-area-inset-top) max(7px,env(safe-area-inset-right)) 0 max(7px,env(safe-area-inset-left));
 display:grid;grid-template-columns:1fr auto 1fr;align-items:center;
 background:linear-gradient(var(--navedge),var(--navedge)) bottom/100% 1px no-repeat,linear-gradient(var(--navhi),var(--navhi)) 0 env(safe-area-inset-top)/100% 1px no-repeat,var(--navbg) bottom/100% 44px no-repeat,var(--statbg)}
/* the kit's nav shadow: 2.5px of black at 18% fading down over the page */
.nav:after{content:"";position:absolute;left:0;right:0;top:100%;height:2.5px;pointer-events:none;background:linear-gradient(rgba(0,0,0,.18),rgba(0,0,0,0))}
.nav h1{margin:0;font-size:20px;font-weight:700;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.5);max-width:calc(100vw - 180px);overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
/* bar buttons as iFizBox's: 29pt high, a long label ends in "…", and background-origin:border-box, without which the gradient tiles into the
   1px border and its light top shows as a line along the bottom */
.nav .bar{justify-self:start;width:auto;height:29px;min-width:50px;max-width:100%;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-size:12px;font-weight:700;line-height:27px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.45);
 background:var(--barbtn);background-origin:border-box;border:1px solid var(--baredge);border-top-color:var(--baredgetop);
 border-radius:5px;padding:0 9px;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 1px 0 rgba(255,255,255,.25)} .nav .bar.r{justify-self:end}
/* iOS 6 back button: arrow art drawn after UIKit's UINavigationBarDefaultBack, stretched through the middle */
.nav .back{display:inline-block;height:30px;line-height:28px;min-width:0;box-sizing:border-box;max-width:40vw;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;padding:0 5px 0 1px;background:none;box-shadow:none;border-radius:0;
 border:solid transparent;border-width:0 5px 0 13px;border-image:var(--back) 0 10 0 26 fill/0 5px 0 13px} .nav .back.is-pressed{border-image-source:var(--backp)} .dark .nav .back.is-pressed{filter:brightness(.75)}
/* pressed states (UIKit's *Pressed art), on .is-pressed: the script below sets it while a finger is down */
.nav .bar:not(.back).is-pressed{background:var(--barpress);background-origin:border-box;border-color:var(--barpe);border-top-color:var(--barpet)}
/* held buttons, from the 4S art: white/grey round buttons go blue (iTunesStoreUI GradientButtonBackgroundPressed, same as the tiles);
   blue and green darken the way PurchaseButtonBluePressed (x.75) and PurchaseConfirmButtonPressed (x.8) do; red from UIAlertSheetDefaultDestroyButtonPressed */
.get:not(.go):not(.blue).is-pressed,a.b.grey.is-pressed,label.b.grey.is-pressed,button.grey.is-pressed,.act:not(.red).is-pressed{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.3);border-color:#005ee8;background:linear-gradient(#058af5,#0160e6);box-shadow:none}
.get.blue.is-pressed,a.b:not(.grey).is-pressed,form button:not(.grey):not(.act).is-pressed{border-color:#1f3b67;background:linear-gradient(#5c7cb3,#2c569f 50%,#1e4997 51%,#2c56a4);box-shadow:none}
.get.go.is-pressed{border-color:#255e12} .get.go.is-pressed:before,button.gbtn.is-pressed{border-color:#255e12;background:linear-gradient(#72ae56,#3d8822 50%,#307b17 51%,#3d8b22);box-shadow:none}
.act.red.is-pressed{border-color:#8a1c1c;background:linear-gradient(#cf848a,#9d010c 80%,#b33941)}
.alert .abtns button,.alert .abtns .ok{background-origin:border-box!important}  /* the background shorthands reset it; without it the gradient tiles into the see-through border and its bright top shows as a line at the bottom */
.alert .abtns button.is-pressed{background:linear-gradient(#6d7da3,#3c4e7d 49%,#22325e 51%,#2f3f6c)}
.sw.is-pressed .k{background:linear-gradient(#bcbcbc,#e6e6e6)} .dark .sw.is-pressed .k{background:var(--swheld)}
/* B5: plain blue action buttons outside a form (Copy Link) hold like the form ones (PurchaseButtonBluePressed). :where keeps it at one class, so
   the controls with their own looks (segments, alerts, bars, tiles, GET) still win; dark themes keep the blue, as iFizBox's do */
:where(button:not(.grey,.act,.gbtn,.get,.tile,.bar,.ok,.mkc,.confin)).is-pressed{border-color:#1f3b67;background:linear-gradient(#5c7cb3,#2c569f 50%,#1e4997 51%,#2c56a4);box-shadow:none}
/* B5: dark grey buttons (Share, Make New Link): .dark button.grey below outranked the light pressed look, so a held one never changed;
   iFizBox's dark button press, --dk-btn-pressed, which is each dark palette's --barpress */
.dark a.b.grey.is-pressed,.dark label.b.grey.is-pressed,.dark button.grey.is-pressed{color:var(--text);border-color:var(--barpe);background:var(--barpress);background-origin:border-box;box-shadow:inset 0 1px 2px rgba(0,0,0,.5)}
.sw{touch-action:none} .sw.drag i:before,.sw.drag i:after,.sw.drag .k{transition:none}  /* while dragging, everything follows --x with the finger */
#sb.on{pointer-events:auto}
*{-webkit-tap-highlight-color:transparent}  /* no grey tap flash; controls have their own pressed looks */
body{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none} input,textarea{-webkit-user-select:text;user-select:text;-webkit-touch-callout:default}  /* app, not a document: holding never selects, except fields */ #sb::before{content:"";position:absolute;inset:-12px -2px -12px -26px} #sb.grab{width:7px;right:1px;border-radius:4px}
h3.hdr{font-size:17px;font-weight:700;line-height:21px;letter-spacing:-.01em;color:var(--head);margin:23px 9px 7px;text-shadow:var(--emboss)}
.ftr{font-size:15px;line-height:19px;color:var(--head);text-align:center;text-shadow:var(--emboss);margin:7px 9px 0;overflow-wrap:anywhere}
.ver{margin:14px 10px 6px;font-size:13px;line-height:16px;text-align:center;color:var(--head);text-shadow:var(--emboss);overflow-wrap:anywhere} .ver.vc{margin-top:-4px;opacity:.8}
.alert .ver{margin:0 0 4px;font-size:13px;line-height:16px;color:inherit;text-shadow:inherit;opacity:.85} .alert .ver.vc{margin-bottom:10px;opacity:.7}
.c,.g{background:var(--plain);border:1px solid var(--line);border-radius:9.5px;box-shadow:inset 0 .5px .5px rgba(0,0,0,.2);overflow:hidden} .g{background:var(--table)}
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
.g>:first-child{border-top:0!important} .row>div:not(.ico){flex:1;min-width:0} .row small{display:block;font-size:14px;color:var(--sub)}
/* a held row in a table (a file link, a Help row) takes iFizBox's cell selection: the blue, white text, a white chevron */
.g a.row.is-pressed,.g details>summary.is-pressed,.dark .g a.row.is-pressed,.dark .g details>summary.is-pressed{background:var(--select);color:#fff;text-shadow:none}
.g a.row.is-pressed *,.g details>summary.is-pressed *{color:#fff} .g details>summary.is-pressed:after{filter:brightness(0) invert(1)}
.ico{position:relative;width:50px;height:50px;flex:none;border-radius:10px;object-fit:cover;display:grid;place-items:center;color:#fff;font-weight:700;font-size:21px;
 text-shadow:0 -1px 0 rgba(0,0,0,.3);box-shadow:0 1px 3px rgba(0,0,0,.45)} div.ico:after{content:"";position:absolute;inset:0;border-radius:inherit;background:var(--gloss)}
.locked .ico{filter:grayscale(.8);opacity:.6}
details{border-top:1px solid var(--sep)} details>summary{list-style:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;gap:10px;min-height:44px;
 padding:0 10px;font-weight:700} details>summary::-webkit-details-marker{display:none}
details>summary:after{content:"";flex:none;width:9px;height:13px;margin-right:.5px;background:var(--chev) center/contain no-repeat;transition:transform .2s}
details[open]>summary:after{transform:rotate(90deg)} details>:not(summary){margin:0 10px 12px}
/* UIAlertView as iFizBox draws it (its sources.css): one grid column exactly the screen's width (B32: a long URL in a message can't push the box
   off the screen), the box widened from iOS 6's 284pt to 340 for today's screens, #0b1b43 at 80% in a 2px rim, a white gloss over the top 31px that
   dips in a curve, 18pt titles and buttons, and the iOS bounce (scale 1.15, .95, 1.02, 1 in 360 ms) while the scrim fades in */
.scrim[hidden]{display:none} .scrim{position:fixed;inset:0;z-index:20;display:grid;grid-template-columns:minmax(0,1fr);place-items:center;padding:16px;
 background:radial-gradient(ellipse at center,rgba(0,0,0,.25),rgba(0,0,0,.6) 70%);animation:fadein .2s ease-out} .scrim.clear{animation:none}
@keyframes fadein{from{opacity:0}}
.alert{position:relative;width:min(340px,100%);max-width:100%;min-width:0;box-sizing:border-box;border-radius:10px;border:2px solid #b1b7c1;border-bottom-color:#e1e3e3;padding:16px 12px 11px;text-align:center;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.8);
 background:rgba(11,27,67,.8);box-shadow:0 8px 19px rgba(0,0,0,.9);animation:pop .36s ease-out}
.alert:before{content:"";position:absolute;left:0;right:0;top:0;height:31px;border-radius:8px 8px 0 0;pointer-events:none;
 background:radial-gradient(ellipse 150% 100% at 50% 0,rgba(255,255,255,.5),rgba(255,255,255,.25) 99%,transparent 100%)}
@keyframes pop{0%{transform:scale(1.15);opacity:0}55%{transform:scale(.95);opacity:1}80%{transform:scale(1.02)}100%{transform:scale(1)}}
.alert h3{position:relative;margin:0 0 6px;font-size:18px;line-height:22px;overflow-wrap:anywhere;word-break:break-word}
.alert p{position:relative;margin:0 0 10px;font-size:16px;line-height:20px;overflow-wrap:anywhere;word-break:break-word}
.abtns{position:relative;display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:4px} .abtns.v{grid-template-columns:1fr}  /* 3 buttons stack, as iOS 6's */
/* UIKit alert buttons: UIPopupAlertSheetDefaultButton (Cancel), UIPopupAlertSheetButton (OK), UIPopupAlertSheetButtonPress */
.alert .abtns button{height:43px;min-width:0;padding:0 6px;font-size:18px;text-shadow:0 -1px 0 rgba(0,0,0,.8);overflow:hidden;white-space:nowrap;text-overflow:ellipsis;border:1px solid rgba(19,29,57,.9);border-radius:5px;box-shadow:none;
 
 background:linear-gradient(#707a91,#283659 49%,#0b1b43 50%,#182747)}  /* Cancel-style (left), as UIAlertView draws it on the 4S */
.alert .abtns .ok{background:linear-gradient(#b4b9c8,#5f6882 49%,#596484 51%,#4d597a)}  /* sampled from Cydia's alert on the 4S: opaque greys, no white line */
/* Dark (Settings > Theme's Mode, or the phone's while it's Automatic): the dark palette's variables (THEMES_CSS), inverted emboss */
html.dark{color-scheme:dark}
.dark .c,.dark .g{background:var(--table);border-color:var(--line);box-shadow:0 1px 0 var(--inset)}
.dark .row,.dark details>summary{background:var(--rowbg);box-shadow:inset 0 1px 0 var(--divhi)}
.dark input{background:var(--field);border-color:var(--line);color:var(--text);box-shadow:inset 0 1px 3px #000} .dark textarea{background:var(--field);border-color:var(--line);color:var(--fieldtext)}
.dark a.b.grey,.dark label.b.grey,.dark button.grey{color:var(--text);border-color:var(--baredge);background:var(--btn);box-shadow:inset 0 1px 0 var(--btnhi)}
/* Cydia's reload bar while Reload syncs sources and re-signs: the kit's "Semi-transparent black bar" (#4c4c4c to black at 52%, a white-at-20%
   line on top, black-at-70% at the bottom) at .8, a 20pt white spinner, a bold white line. As iFizBox's F204: it sits on top of the tab bar, sliding
   up from behind it, and nothing on the page moves; the page gets 44pt more room at the bottom while it shows, so the last row still scrolls clear */
#rbar{position:fixed;z-index:7;  /* over a pushed page (.layer 6), under the tab bar (8), which it hides behind */bottom:var(--tabh,0);left:0;right:0;height:44px;box-sizing:border-box;padding:0 max(12px,env(safe-area-inset-right)) 0 max(12px,env(safe-area-inset-left));
 display:flex;align-items:center;gap:10px;font-size:14px;font-weight:700;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.8);pointer-events:none;
 background:linear-gradient(rgba(0,0,0,.7),rgba(0,0,0,.7)) bottom/100% 1px no-repeat,linear-gradient(rgba(255,255,255,.2),rgba(255,255,255,.2)) top/100% 1px no-repeat,linear-gradient(rgba(76,76,76,.8),rgba(0,0,0,.8) 52%);
 transform:translateY(100%);transition:transform .25s ease-in} html.reloading #rbar{transform:none;transition:transform .3s cubic-bezier(.25,.1,.25,1)}  /* F204's timings: up .3s, down .25s */
html.reloading #scr{padding-bottom:calc(116px + env(safe-area-inset-bottom))}
.spin{width:20px;height:20px;flex:none;animation:spin .96s linear infinite}
/* iFizBox's F166: spinners turn a spoke at a time by holding each 30-degree turn for 1/12 of the cycle. Not steps(12): WebKit on iOS 15 hands the
   animation to Core Animation, where steps() leaves it standing still */
@keyframes spin{0%,8.332%{transform:rotate(0)}8.333%,16.666%{transform:rotate(30deg)}16.667%,24.999%{transform:rotate(60deg)}25%,33.332%{transform:rotate(90deg)}
 33.333%,41.666%{transform:rotate(120deg)}41.667%,49.999%{transform:rotate(150deg)}50%,58.332%{transform:rotate(180deg)}58.333%,66.666%{transform:rotate(210deg)}
 66.667%,74.999%{transform:rotate(240deg)}75%,83.332%{transform:rotate(270deg)}83.333%,91.666%{transform:rotate(300deg)}91.667%,100%{transform:rotate(330deg)}}
.scrim.clear{background:none} .nw{white-space:nowrap} .a2l>span{display:block;margin:2px 0} .ic{width:1.15em;height:1.15em;vertical-align:-.2em;margin-right:3px}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
%THEMES_CSS%</style>
{% if back %}<header class=nav><a class="bar back" href="{{ back[1] }}" onclick="return goBack(this.href)">{{ back[0] }}</a><h1>{{ title }}</h1><span></span></header>
<script>/* a pushed page: tapping back pops; iOS's own edge swipe (Safari and the home-screen app) does the same. history.back() keeps the previous page's scroll, like a native pop; first visits (no "/" behind us) follow the link */
function goBack(h){try{if(new URL(document.referrer).pathname=="/"&&history.length>1){history.back();return false}}catch(e){}location.href=h;return false}
</script>
{% else %}<header class=nav><span></span><h1 id=navT>SideDrop</h1>{# F26: no About button or alert; the version line stays at the bottom of Apps and Settings #}
<button type=button class="bar r" onclick="reloadData()">Reload</button></header>{% endif %}
<script>/* alerts are modal like UIAlertView: only their buttons close them */
/* #scr is the scroller; scrollIntoView would also scroll the locked <html> and drag the fixed nav down */
/* clamp to the real bottom: iOS lets a smooth scroll on a non-root scroller overshoot past the end, then snaps back on the next touch */
function goTo(el){let b=scr;b.scrollTo({top:Math.min(b.scrollTop+el.getBoundingClientRect().top-56,b.scrollHeight-b.clientHeight),behavior:"smooth"})}
addEventListener("gesturestart",e=>e.preventDefault())
/* pressed looks: .is-pressed while a finger is down, off when it lifts, slides off the control or the page scrolls.
   Not :active: iOS keeps that on a held control after the touch has turned into a scroll. A quick tap still shows it for 140 ms, as UIKit does. */
const PRESS=".get,.tile,a.b,label.b,button,.nav .bar,.sw,.g a.row,.g details>summary";let pd=null,pdAt=0;
const unpress=now=>{let el=pd;if(!el)return;pd=null;setTimeout(()=>{if(pd!==el)el.classList.remove("is-pressed")},now?0:Math.max(0,140-(performance.now()-pdAt)))};
addEventListener("touchstart",e=>{unpress(1);let el=e.target.closest&&e.target.closest(PRESS);if(!el||el.disabled||e.touches.length>1)return;pd=el;pdAt=performance.now();el.classList.add("is-pressed")},{passive:true});
addEventListener("touchmove",e=>{let t=e.touches[0];if(pd&&!pd.contains(document.elementFromPoint(t.clientX,t.clientY)))unpress(1)},{passive:true});
addEventListener("touchend",()=>unpress(),{passive:true});addEventListener("touchcancel",()=>unpress(1),{passive:true});
addEventListener("scroll",()=>unpress(1),{passive:true,capture:true});  // scroll doesn't bubble: capture catches every scroller
/* B5: a mouse held on a control in a desktop browser shows the same look (what :active would), off when it lifts or leaves the control */
addEventListener("pointerdown",e=>{if(e.pointerType!=="mouse"||e.button)return;unpress(1);let el=e.target.closest&&e.target.closest(PRESS);if(!el||el.disabled)return;pd=el;pdAt=performance.now();el.classList.add("is-pressed")});
addEventListener("pointerup",e=>{if(e.pointerType==="mouse")unpress()});addEventListener("pointermove",e=>{if(e.pointerType==="mouse"&&pd&&!pd.contains(e.target))unpress(1)});
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
{% if "<div id=scr" in body %}{{ body|safe }}{% else %}<div id=scr><section class=page>{{ body|safe }}</section></div>{% endif %}""".replace("%PUBLIC_URL%", PUBLIC_URL).replace("%BUILD%", BUILD).replace("%THEME_BOOT%", THEME_BOOT).replace("%THEMES_CSS%", THEMES_CSS)  # link previews (iMessage, Discord) need absolute URLs; static/og.png is the card


def file_labels(folder):
    """appfiles/<app>/labels.txt: one "file name = label" line per file, e.g. "GMPE01.iso = the game disc"."""
    f = folder / "labels.txt"
    return {k.strip(): v.strip() for k, _, v in (l.partition("=") for l in f.read_text().splitlines() if "=" in l)} if f.exists() else {}


def page(body, back=None, title="SideDrop", **ctx):
    """back=("Settings", "/#settings") makes it a pushed screen: title in the nav, iOS back button and edge swipe."""
    stats = None
    if logged_in() and PROFILE.exists():  # for the About alert: devices used, and when the profile (so every app) expires
        prof = embedded_plist(PROFILE.read_bytes())
        stats = (len(prof.get("ProvisionedDevices", [])), prof.get("ExpirationDate"))
    vfoot = version_foot()
    return render_template_string(PAGE + VERSION_JS, body=render_template_string(body, stats=stats, vfoot=vfoot, **ctx), stats=stats, back=back, title=title, vfoot=vfoot)


@app.get("/")
def home():
    if "password" in request.args:  # shareable ?password= link; redirect drops it from the address bar
        return login()
    if needs_setup() and session.get("setup"):
        return redirect("/setup")
    if not logged_in():
        return page("""<form class=c method=post action=/login>
<label>Password<input type=password name=password autofocus required></label>
{% if err %}<p class=err>Wrong password.</p>{% endif %}<button>Sign in</button></form>
{% if first %}<p class=ftr>New server: sign in with the default password, <b>{{ first }}</b>, to set it up.</p>
{% else %}<p class=ftr>SideDrop shares an Apple developer account with friends so they can sideload apps. The friend who sent you the link has the password.</p>{% endif %}
{{ vfoot }}""",
                    err=request.args.get("err"), first=needs_setup() and DEFAULT_PASSWORD)
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
    for a in apps:
        a["vkey"] = f"{a['short']}/{a['version']}"
    mine = installed().get(token_udid(tok), {}) if enrolled else {}
    updates = [a for a in apps if a["name"] in mine and mine[a["name"]] != a["vkey"]]  # Home's UPDATE rows; their count is the Apps tab's badge
    ifizbox = [a for a in apps if IFIZBOX_ID in (a["id"], a["name"])]  # its own category, on top
    apps = [a for a in apps if a not in third and a not in ifizbox]
    ifz = ifizbox[0] if ifizbox else None
    resp = make_response(page("""<style>
.splash{display:flex;align-items:center;gap:14px;padding:2px 6px 4px} .splash img{width:76px;height:76px;flex:none;border-radius:15px;box-shadow:0 3px 6px rgba(0,0,0,.45)}
.splash h2{font-size:23px;font-weight:400;letter-spacing:-.3px;line-height:1.15;text-shadow:var(--emboss)} .splash p{margin:3px 0 0;font-size:16px;text-shadow:var(--emboss)}
.splash p a{font-weight:700}
/* Apps header, as iFizBox's Home: icon and welcome, then 43px tiles (row 1 an outlined pair over the pinstripes, row 2 two white tiles, row 3 one status tile) */
.hd{display:flex;align-items:center;padding:4px 0 0 16px} .hd img{width:57px;height:57px;flex:none;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,.45)}
.hd>div{flex:1;display:flex;justify-content:center;min-width:0} .hd h2{font-size:21px;font-weight:400;line-height:26px;text-shadow:var(--emboss)}
.hd p{margin:0;font-size:17px;line-height:22px;text-shadow:var(--emboss)} .hd p a{font-weight:700;color:#586c90;text-shadow:0 1px 0 #fff}
.hx{display:flex;flex-direction:column;gap:10px;margin:14px 0 0} .hx .tile{min-height:43px;padding:0 10px;gap:9px;font-size:17px;line-height:1.2;border:1px solid #999;border-radius:8px}
.hx .hp,.hx .hw{display:grid;grid-template-columns:1fr 1fr} .hx .hw{gap:9px} .hx .hw:has(>:only-child){grid-template-columns:1fr}  /* F26: a lone tile (Help) spans the row */
.hx .hp{border:1px solid #999;border-radius:8px;overflow:hidden} .hx .hp .tile{background:none;border:0;border-radius:0} .hx .hp .tile+.tile{border-left:1px solid #999}
.hx .hw .tile{background:#fff} .hx .tile.reg{background:#eefff0} .hx .tile.todo{background:#fff8e1;border-color:#c9a74a}
.hx .tile small{display:block;font-size:13px;font-weight:400} .hx .hdt{margin-left:auto;font-weight:400;color:#7f7f7f} .hx .tile:has(.hdt):after{margin-left:8px}
.hx .tile:after{transition:transform .2s} .hx .tile[aria-expanded=true]:after{transform:rotate(90deg)}
.hx .tic{width:29px;height:29px;border-radius:6.5px} .hx .tic svg{width:19px;height:19px}
#setup{margin-top:12px} #setup[hidden]{display:none}
.dark .hd p a{color:var(--acc);text-shadow:var(--emboss)} .dark .hx .hp{border-color:var(--line);box-shadow:0 1px 0 var(--inset)} .dark .hx .hp .tile+.tile{border-left-color:var(--line)}
.dark .hx .tile,.dark .hx .hw .tile,.dark .hx .tile.reg,.dark .hx .tile.todo{background:var(--rowbg);border-color:var(--line);color:var(--text)} .dark .hx .hp .tile{background:none}
.hx .tile.is-pressed,.dark .hx .tile.is-pressed{background:var(--select);color:#fff} .hx .tile.is-pressed small,.hx .tile.is-pressed .hdt{color:#fff}
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
/* UPDATE stands out (F24): iFizBox's "Button (Gloss Blue)" (its Done: sources.css .bar-button.done), the same in both themes; held, its
   darker pressed gloss. border-box so the gradient's light top doesn't tile into the bottom border. Tapped it still arms to the green
   INSTALL (the :before layer paints over this background), and once installed it is the grey INSTALLED again. */
.get.upd:not(.go):not(.done):not([aria-expanded=true]){color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.4);border-color:#1f3f86;border-top-color:#30363e;
 background:linear-gradient(#79a1f3,#3b71e1 49%,#215fdd 51%,#2361dd);background-origin:border-box;box-shadow:inset 0 1px 0 rgba(255,255,255,.35),0 1px 1px rgba(0,0,0,.2)}
.get.upd:not(.go):not(.done):not([aria-expanded=true]).is-pressed{background:linear-gradient(#5f86d6,#2a5bc0 49%,#164bb8 51%,#184db9);background-origin:border-box;box-shadow:none}
/* a row with an update: the iOS 6 red badge (the Apps tab's, without a number) on its icon's top-right corner; gone with .up once installed */
/* Home's iFizBox card (F25): icon, name and its green INSTALL on top, the "Recommended" line under the whole row: in Helvetica Neue 13px it is
   323px, which fits the row's 333px at 375pt but not the 273px beside the icon; narrower screens cut it with an ellipsis, still one line */
.ifzr{display:grid;grid-template-columns:50px minmax(0,1fr) auto;column-gap:10px;row-gap:6px;align-items:center}
.ifzr>div:not(.ico){grid-column:2;grid-row:1} .ifzr>.get{grid-column:3;grid-row:1}
.ifzr>.rec{grid-column:1/4;grid-row:2;font-size:13px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis} .ifv{margin-left:6px;font-size:14px;color:var(--sub)}
.dark .ifzr .get.go{color:#fff;border-color:#2f7a17}  /* .dark .get comes later and would grey the green button's label */
.row.up{position:relative} .ub{display:none} .row.up .ub{display:block;position:absolute;left:47px;top:calc(50% - 32px);width:20px;min-width:0;padding:0;pointer-events:none}
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
.dark .warn{background:var(--warnbg);border-color:var(--warnedge)}
.nudge{animation:nudge .45s} @keyframes nudge{20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
/* Settings tab: Cydia-style rows */
.green{background:#e9f8e4} .kv{display:flex;justify-content:space-between;gap:10px;padding:11px 12px;border-top:1px solid #d6e6cf} .kv span{color:var(--acc);text-align:right}
.sg .row>.val{flex:none;max-width:60%;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;font-weight:400;color:var(--acc)}  /* F26: a row's detail, UITableViewCellStyleValue1 */
.split{display:grid;grid-template-columns:1fr 1fr;margin-top:12px} .pair{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:12px}
.tile{display:flex;align-items:center;gap:9px;min-height:50px;padding:8px 10px;box-sizing:border-box;font-weight:700;color:var(--text);background:var(--table);cursor:pointer;text-align:left;border:0;border-radius:0;box-shadow:none;text-shadow:none;line-height:1.35}
.split .tile+.tile{border-left:1px solid var(--sep)} .pair .tile{border:1px solid var(--line);border-radius:10px;box-shadow:0 1px 0 rgba(255,255,255,.8)}
.tile:after{content:"";margin-left:auto;flex:none;width:9px;height:13px;margin-right:.5px;background:var(--chev) center/contain no-repeat}
.tile.is-pressed:after,.tile.sel:after{filter:brightness(0) invert(1)}
.tile.is-pressed,.tile.sel,.dark .tile.is-pressed,.dark .tile.sel{background:var(--select);color:#fff}  /* iFizBox's cell selection */
/* row icons as iFizBox's F205 (iOS 6 Settings, measured on the 4S): a flat 29pt tile, 6pt corners, no gloss or shadow (user's pick for iFizBox),
   7pt in from the row's edge with the label 11pt after it */
.tic{position:relative;flex:none;width:29px;height:29px;border-radius:6px;display:grid;place-items:center} .tic svg{width:19px;height:19px}
.split .tile,.pair .tile{padding-left:7px;gap:11px}
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
.dark .get{color:var(--getc);border-color:var(--baredge);box-shadow:inset 0 1px 0 var(--btnhi)} .dark .get[aria-expanded=true]{color:var(--getoff);background:var(--getdown);box-shadow:inset 0 1px 3px #000}
.dark .get.go{color:#fff;border-color:#2f7a17} .dark .get.go.is-pressed{border-color:#255e12}  /* B3: an armed INSTALL stays white on green, not .dark .get's grey */
.dark .steps{background:var(--steps)} .dark .step+.step{border-top-color:var(--keyline)}
.dark .green{background:var(--greenbg)} .dark .kv{border-top-color:var(--greenline)}
.dark .tile{background:var(--rowbg);color:var(--text)} .dark .pair .tile{border-color:var(--line);box-shadow:0 1px 0 var(--inset)} .dark .split .tile+.tile{border-left-color:var(--div)}
.dark .sw i{border-color:var(--baredge);background:var(--swtrack);box-shadow:inset 0 1px 3px rgba(0,0,0,.8)} .dark .sw i:after{color:var(--swoff)}
.dark .sw i:before{background:var(--swon)} .dark .sw .k{background:var(--swknob);border-color:var(--baredge)}
/* iOS 5 red count badge on the Apps tab: how many of this iPhone's apps have an update */
.badge{position:absolute;top:-2px;left:calc(50% + 5px);min-width:20px;height:20px;padding:0 5px;box-sizing:border-box;border-radius:10px;border:2px solid #fff;color:#fff;letter-spacing:-.02em;
 font:700 13px/16px "Helvetica Neue",Helvetica,sans-serif;text-align:center;background:linear-gradient(#f7b3b7,#e92d35 48.8%,#e70f19 50.5%,#c50103);box-shadow:0 2px 2.5px rgba(0,0,0,.6)}
/* Cydia: while it checks for updates the badge spins instead of counting. As iFizBox's: the white UIActivityIndicatorView (spokes drawn from the
   4S's frames) inside the 2px ring, turning a spoke at a time */
.badge.busy{font-size:0;padding:0;width:20px} .badge.busy:after{content:"";position:absolute;inset:0;animation:spin .96s linear infinite;
 background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 20 20'%3E%3Cg stroke='%23fff' stroke-width='2' stroke-linecap='round'%3E%3Cline x1='10' y1='1' x2='10' y2='4' opacity='0.271'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(30 10 10)' opacity='0.271'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(60 10 10)' opacity='0.271'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(90 10 10)' opacity='0.271'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(120 10 10)' opacity='0.369'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(150 10 10)' opacity='0.463'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(180 10 10)' opacity='0.561'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(210 10 10)' opacity='0.659'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(240 10 10)' opacity='0.753'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(270 10 10)' opacity='0.851'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(300 10 10)' opacity='0.271'/%3E%3Cline x1='10' y1='1' x2='10' y2='4' transform='rotate(330 10 10)' opacity='0.271'/%3E%3C/g%3E%3C/svg%3E") center/16px no-repeat}
/* Cydia tab bar: 3pt + 44pt tabs + 2pt, then the home indicator's area. --tabh, in CSS (not measured once by script, before iOS has applied
   the safe area), so the reload bar and pushed pages always sit right on top of it */
.tabs{position:fixed;left:0;right:0;bottom:0;z-index:8;height:var(--tabh);box-sizing:border-box;display:grid;grid-auto-flow:column;grid-auto-columns:1fr;  /* one column a tab: 3, or 4 with Files */
 padding:0 max(2px,env(safe-area-inset-right)) calc(2px + env(safe-area-inset-bottom)) max(2px,env(safe-area-inset-left));
 background:linear-gradient(rgba(0,0,0,.7),rgba(0,0,0,.7)) top/100% 1px no-repeat,linear-gradient(rgba(255,255,255,.1),rgba(255,255,255,.1)) 0 1px/100% 1px no-repeat,linear-gradient(#2f2f2f,#151515 49.5%,#000 49.5%) 0 1px/100% 48px no-repeat,#000}
.tabs:before{content:"";position:absolute;left:0;right:0;bottom:100%;height:2.5px;pointer-events:none;background:linear-gradient(rgba(0,0,0,0),rgba(0,0,0,.18))}
.tabs a{position:relative;display:flex;flex-direction:column;align-items:center;height:44px;box-sizing:border-box;margin:3px 2px 0;padding-top:3.5px;border-radius:2.5px;color:#a8a8a8;font-size:10px;font-weight:700;line-height:12px}
.tabs svg{width:28px;height:28px;margin-bottom:1px;fill:url(#taboff);filter:drop-shadow(0 -1px 0 rgba(0,0,0,.75))}
.tabs a[aria-current]{background:rgba(255,255,255,.15);color:#fff;box-shadow:inset 0 0 1px rgba(0,0,0,.31)}
/* a pushed page (Manage) in place over its tab: the iOS slide (350 ms, UINavigationController's curve), the page below moving a third as far and
   darkening 10%; transform and opacity only */
.layer{position:fixed;z-index:6;top:0;left:0;right:0;bottom:var(--tabh,0);background:var(--pin);background-color:var(--ground)}
.layer[hidden]{display:none} .layer .nav{position:absolute;z-index:1}  /* above its own scroller, as the main nav is above #scr */ .layer .nav h1{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.lscroll{position:absolute;inset:0;overflow-y:auto;overscroll-behavior:contain;box-sizing:border-box;scrollbar-width:none;
 padding:calc(56px + env(safe-area-inset-top)) max(10px,env(safe-area-inset-right),(100% - 30rem)/2) 20px max(10px,env(safe-area-inset-left),(100% - 30rem)/2)}
.lscroll>.page{min-height:calc(100% + 1px)} html.reloading .lscroll{padding-bottom:64px}  /* the reload bar over a pushed page: its last row still scrolls clear */
/* first install tap: a one-time sheet (Developer Mode; F26 took SDP out) over everything, sliding up like the install page; its screenshots are Help's */
.fl{position:fixed;inset:0;z-index:25;background:var(--pin);background-color:var(--ground);animation:conup .35s cubic-bezier(.36,.66,.04,1)} .fl[hidden]{display:none}
.fl .nav{position:absolute;z-index:1} .fl .c>.shot{margin:0} .fl .c>.shot+.shot{margin-top:12px} .fl .lead{margin:0 4px 12px;font-size:15px}
.shade{position:fixed;inset:0;z-index:6;background:#000;opacity:0;pointer-events:none}
.ghost{position:absolute;margin:0;pointer-events:none;z-index:1}
.tabs a[aria-current] svg{fill:url(#tabglow);filter:drop-shadow(0 2.5px 2.5px rgba(0,0,0,.4))}
/* F27: hold an Apps row for its options. The held row takes the cell selection, as a held UITableViewCell; the sheet is iOS 6's UIActionSheet
   (default style): a smoky blue-grey panel sliding up from the bottom, white glossy 44pt buttons with bold black titles, a dark Cancel */
#t-apps .g:not(.locked) .row{-webkit-touch-callout:none;-webkit-user-select:none;user-select:none}
#t-apps .g .row.held,.dark #t-apps .g .row.held{background:var(--select);color:#fff;text-shadow:none} #t-apps .row.held>div,#t-apps .row.held small,#t-apps .row.held .ifv{color:#fff;text-shadow:none}
.mks{position:fixed;inset:0;z-index:22;background:rgba(0,0,0,.4);animation:fadein .25s ease-out} .mks[hidden]{display:none}
.mkp{position:absolute;left:0;right:0;bottom:0;box-sizing:border-box;padding:14px max(20px,env(safe-area-inset-right),(100% - 30rem)/2) calc(20px + env(safe-area-inset-bottom)) max(20px,env(safe-area-inset-left),(100% - 30rem)/2);
 background:linear-gradient(rgba(148,156,173,.97),rgba(64,74,96,.97) 22px,rgba(38,46,66,.97));border-top:1px solid rgba(255,255,255,.55);box-shadow:0 -1px 0 rgba(0,0,0,.6);animation:mkup .3s cubic-bezier(.36,.66,.04,1)}
@keyframes mkup{from{transform:translateY(100%)}}
.mkp p{margin:0 0 12px;text-align:center;font-size:14px;line-height:18px;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.7);overflow-wrap:anywhere}
.mkp button{display:block;width:100%;height:46px;margin:0 0 9px;padding:0 10px;border:1px solid rgba(0,0,0,.75);border-radius:10px;font:bold 20px/44px -apple-system,"Helvetica Neue",Helvetica,sans-serif;
 color:#000;text-shadow:0 1px 0 rgba(255,255,255,.75);background:linear-gradient(#fff,#f0f0f0 49%,#dfdfdf 51%,#e8e8e8);background-origin:border-box;box-shadow:0 1px 0 rgba(255,255,255,.3);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mkp button.mkc{margin:9px 0 0;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.7);background:linear-gradient(#7d8495,#4b5263 49%,#353c4e 51%,#3c4355);background-origin:border-box}
.mkp button.is-pressed{color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.4);background:linear-gradient(#5d89f2,#2d63e3 49%,#1352dd 51%,#1a57de);background-origin:border-box}
</style>
{% if error %}<p class="c err">{{ error }}</p>{% endif %}
{% set enroll_form %}<form method=post action=/enroll style="display:flex;flex-direction:column;gap:10px"
 onsubmit="document.getElementById('next').hidden=false;this.querySelector('button').textContent='Check the popup…'">
{% if inv_name %}<button>Register iPhone</button>{# a named one-iPhone invite: registered under its name, no typing #}
{% else %}<input name=name required maxlength=30 placeholder="Your name" aria-label="Your name" autocomplete=given-name
 oninput="this.form.querySelector('button').disabled=!this.value.trim()"><button disabled>Register iPhone</button>{% endif %}</form>
{# R1: where iOS puts each tap. The Profile Downloaded row sits under the Apple Account name; Install is a top-right nav button, not a
   button at the bottom; iOS deletes a downloaded profile not installed within 8 minutes; a dismissed row is still under VPN & Device Management #}
<ol id=next hidden><li>Tap <b>Allow</b>, then <b>Close</b>.</li><li>Leave Safari and open the <b>Settings</b> app (the grey gear), within a few minutes.</li>
<li>Tap <b>Profile Downloaded</b>, just under your name at the top. Not there? Go to <b>General</b> › <b>VPN &amp; Device Management</b> and tap <b>SideDrop device registration</b>.</li>
<li>Tap <b>Install</b> in the top-right corner, enter your iPhone passcode, then tap <b>Install</b> again if iOS asks.</li>
<li>Safari opens back here by itself, registered.</li></ol>{% endset %}
{# sdp_steps, dev_steps and a2hs_steps: Jinja globals (F26, SDP_STEPS etc. in app.py), shared with the Help page #}
{% macro install(a) %}{% if not enrolled %}<a class=get aria-label="Register first" href=#apps onclick="return nudge()">🔒</a>
{% else %}{% set lbl = 'GET' if a.name not in mine else 'INSTALLED' if mine[a.name] == a.vkey else 'UPDATE' %}
{% set cls = ' done' if lbl == 'INSTALLED' else ' upd' if lbl == 'UPDATE' else '' %}
{% if a.files %}<button type=button class="get{{ cls }}" data-app="{{ a.name }}" aria-expanded=false onclick="steps(this)">{{ lbl }}</button>
{% else %}<a class="get{{ cls }}" data-arm={{ lbl }} data-app="{{ a.name }}" aria-label="Install {{ a.title }}" href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}" onclick="return arm(this)">{{ lbl }}</a>{% endif %}{% endif %}{% endmacro %}
{% macro ifz_icon(a) %}{% if a.icon %}<img class=ico src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=ico style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}{% endmacro %}
{# a newer signed version than this iPhone last installed: the row says so (.up, counted for the Apps tab's badge) and its button says UPDATE #}
{% macro upnote(a) %}{% if a.name in mine and mine[a.name] != a.vkey %}<span class=upn> · Update available</span>{% endif %}{% endmacro %}
{% macro ubadge(a) %}{% if a.name in mine and mine[a.name] != a.vkey %}<i class="badge ub" aria-hidden=true></i>{% endif %}{% endmacro %}
{% macro install_list(apps) %}<div class="g{{ '' if enrolled else ' locked' }}">{% for a in apps %}
<div class="row{{ ' up' if a.name in mine and mine[a.name] != a.vkey }}">{% if a.icon %}<img class=ico src="{{ a.icon }}" alt="" loading=lazy>{% else %}<div class=ico style="background:hsl({{ a.name|hue }} 65% 50%)">{{ a.title[:1] }}</div>{% endif %}{{ ubadge(a) }}
<div>{{ a.title }}<small>Version {{ a.short }}{{ upnote(a) }}{% if a.files %} · needs {{ a.files|length }} file{{ 's' if a.files|length > 1 }}{% endif %}</small></div>{{ install(a) }}</div>
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
<section class=page id=t-apps data-title=SideDrop>
<div class=hd><img src=/apple-touch-icon.png alt=""><div><div><h2>Welcome to SideDrop</h2><p>by <a href="https://github.com/RyanAHayden">Ryan Hayden (Fizlo)</a></p></div></div></div>
<div class=hx><div class=hp>
<a class=tile href="https://github.com/RyanAHayden"><span class=tic style="background:#333"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M8 7l-5 5 5 5M16 7l5 5-5 5M13.5 5l-3 14"/></svg></span>GitHub</a>
<a class=tile href=#ifizbox onclick="go('ifizbox');return false"><span class=tic style="background:#1a82fb"><svg viewBox="0 0 30 30" fill="#fff"><path d="M15 3l11 5.5-11 5.5L4 8.5zM4 10.7l10 5v11.1l-10-5zM16 15.7l10-5v11.1l-10 5z"/></svg></span>iFizBox</a></div>
<div class=hw><a class=tile href=/help onclick="return helpOpen()"><span class=tic style="background:#8a929c"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round"><path d="M8.8 9a3.3 3.3 0 1 1 4.6 3c-.9.4-1.4 1.1-1.4 2.2"/><path d="M12 18.3v.2"/></svg></span>Help</a></div>
{% if enrolled %}<a class="tile reg" href=#settings onclick="go('settings');return false"><span class=tic style="background:#34a84a"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><path d="M5.5 12.5l4.5 4.5 8.5-10"/></svg></span>Registered{% if stats and stats[1] %}<span class=hdt>until {{ stats[1].strftime('%b %-d, %Y') }}</span>{% endif %}</a>
{% else %}<button type=button class="tile todo" id=setupT aria-expanded=false aria-controls=setup onclick="setupOpen(setup.hidden)"><span class=tic style="background:#f08a12"><svg viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2" fill="#fff"/><rect x="8.5" y="5" width="7" height="12" fill="#f08a12"/></svg></span><div>Set up this iPhone<small>2 steps, then every app unlocks</small></div></button>{% endif %}</div>
<p class=ftr id=tagline>Sideload apps on your iPhone with a friend's Apple developer account.</p>
{% if not enrolled %}<div id=setup hidden>
<details class=c id=sdp open><summary><span class=num>1</span><div>Turn off Stolen Device Protection</div></summary>
{{ sdp_steps }}
<button type=button class=gbtn onclick="sdpDone(true)">I turned it off</button></details>
<div class=c id=reg><div class=sh><span class=num>2</span><div>Register this iPhone<small>In Safari on this iPhone</small></div></div>
<fieldset id=regf disabled>{{ enroll_form }}</fieldset><small>This adds your iPhone to the shared developer account, so the apps here can be signed for it. Registered before but the apps are locked? Register again, it's instant.</small></div></div>{% endif %}
{% if ifz %}<h3 class=hdr>iFizBox</h3><div class="g{{ '' if enrolled else ' locked' }}"><div class="row ifzr{{ ' up' if ifz.name in mine and mine[ifz.name] != ifz.vkey }}">{{ ifz_icon(ifz) }}{{ ubadge(ifz) }}
<div>{{ ifz.title }}<span class=ifv>{{ ifz.short }}</span></div><small class=rec>Recommended: get update alerts and install more apps</small>
{% if enrolled %}<a class="get{{ ' done' if mine.get(ifz.name) == ifz.vkey else ' go' }}" data-app="{{ ifz.name }}" aria-label="Install {{ ifz.title }}" href=#ifizbox onclick="return ifzGo(this)">{{ 'INSTALL' if ifz.name not in mine else 'INSTALLED' if mine[ifz.name] == ifz.vkey else 'UPDATE' }}</a>
{% else %}<a class=get aria-label="Register first" href=#apps onclick="return nudge()">🔒</a>{% endif %}</div></div>{% endif %}
<h3 class=hdr>Apps</h3>{% if apps %}{{ install_list(apps) }}{% else %}<p class="c m">No apps yet.</p>{% endif %}
{% if third %}<h3 class=hdr>Third-party apps</h3>{{ install_list(third) }}<p class=ftr>Made by other people, mirrored from their sources.</p>{% endif %}
{{ vfoot }}
</section>
{% if files %}<section class=page id=t-files data-title=Files>{# target=_blank: in the Home Screen app a file link opened a blank Quick Look page; Safari downloads it #}
<h3 class=hdr>Files</h3><div class=g>{% for f in files %}<a class=row href="{{ fdl(f) }}" target=_blank download><div>{{ f.name }}<small>{{ f.stat().st_size|filesizeformat }}</small></div></a>{% endfor %}</div>
<p class=ftr>The links work without signing in for 7 days, so wget and curl can use them.</p>
</section>{% endif %}

<section class=page id=t-ifizbox data-title=iFizBox>
{% if ifz %}<div class=splash>{% if ifz.icon %}<img src="{{ ifz.icon }}" alt="">{% else %}<div class=ico style="width:76px;height:76px;border-radius:15px;background:hsl({{ ifz.name|hue }} 65% 50%)">{{ ifz.title[:1] }}</div>{% endif %}
<div><h2>{{ ifz.title }}</h2><p>A package manager for your iPhone</p></div></div>
<div class=c style="margin-top:16px">{% if enrolled %}<button type=button class=gbtn id=ifzb data-app="{{ ifz.name }}" data-m="{{ ifz_m }}" data-title="{{ ifz.title }}" data-v="{{ ifz.short }}" data-n="{{ n_sources }}" onclick="ifzRun()">Install {{ ifz.title }}</button>
{% else %}<button type=button class=gbtn onclick="nudge()">Register This iPhone First</button>{% endif %}
<small>Version {{ ifz.short }}, signed for this iPhone. Your certificate and {{ n_sources }} sources come with it.</small></div>
<h3 class=hdr>Why {{ ifz.title }}</h3><div class="g why">
<div class=row><span class=tic style="background:#f08b1d"><svg viewBox="0 0 24 24"><path d="M8 11V8a4 4 0 0 1 8 0v3" fill="none" stroke="#fff" stroke-width="2.4"/><rect x="5" y="11" width="14" height="10" rx="2" fill="#fff"/></svg></span><div><b>Your certificate, already in it</b><small>No .p12 to find and no password to type: it signs with this site's certificate from the first launch.</small></div></div>
<div class=row><span class=tic style="background:#3f80e0"><svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="4" rx="1.5" fill="#fff"/><rect x="4" y="10" width="16" height="4" rx="1.5" fill="#fff"/><rect x="4" y="16" width="16" height="4" rx="1.5" fill="#fff"/></svg></span><div><b>Comes with the sources</b><small>{{ n_sources }} sources, ready the first time it opens.</small></div></div>
<div class=row><span class=tic style="background:#40ae4c"><svg viewBox="0 0 24 24"><rect x="7" y="2" width="10" height="20" rx="2" fill="#fff"/><path d="M12 7v7m-3-3 3 3 3-3" fill="none" stroke="#3c9a1d" stroke-width="2"/></svg></span><div><b>Signs on your iPhone</b><small>Install any IPA or AltStore app right on the phone: no computer, nothing uploaded.</small></div></div>
<div class=row><span class=tic style="background:#e2382f"><svg viewBox="0 0 24 24"><path fill-rule="evenodd" d="M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18zm0 2.5a6.5 6.5 0 1 1 0 13 6.5 6.5 0 1 1 0-13z" fill="#fff"/><path d="M11 7.5h2.2v4.4l3 2-1.2 1.8-4-2.7z" fill="#fff"/></svg></span><div><b>Updates in one tap</b><small>New versions of what you installed, ready to install.</small></div></div>
<div class=row><span class=tic style="background:#8c9097"><svg viewBox="0 0 24 24"><path d="M12 3 21 7.5v9L12 21l-9-4.5v-9z" fill="#fff"/></svg></span><div><b>The iOS 6 look, at 120 Hz</b><small>A package manager with the classic look, smooth on today's iPhones.</small></div></div></div>
<p class=ftr>iOS 27 asks for Developer Mode once to open it, as for every app here. <a href="https://ifizbox.com">ifizbox.com</a></p>
{% else %}<p class="c m">iFizBox isn't here yet. Tap Reload in a minute.</p>{% endif %}
</section>

<section class=page id=t-settings data-title=Settings>
{# F26, the user's concept (2026-11-19): iOS 6 Settings' grouped rows, each with its 29pt icon, a chevron where it pushes a page, a footer
   under its group. This iPhone; Manage (the admin's); Theme and Update Alerts; Add to Home Screen; Help; Sign Out and the version line.
   No iFizBox row (the tab bar has it) and no About. #}
<h3 class=hdr>This iPhone</h3><div class="g sg" id=sThis>
{% if enrolled %}<div class="row irow">{{ row_icon('status') }}<div>Status</div><span class=val>Registered</span></div>
{% else %}<a class="row mrow" href=#apps onclick="return nudge()">{{ row_icon('device') }}<div>Status</div><span class=val>Not registered</span></a>{% endif %}
{% if stats and stats[1] %}<div class="row irow">{{ row_icon('calendar') }}<div>Apps Work Until</div><span class=val>{{ stats[1].strftime('%b %-d, %Y') }}</span></div>{% endif %}</div>
<p class=ftr>{% if enrolled %}Every app on the Apps tab can install on this iPhone.{% else %}Register this iPhone on the Apps tab, then every app there can install on it.{% endif %}</p>
{% if is_admin %}<div class="g grp sg" id=sManage><a class="row mrow" href=/admin data-push>{{ row_icon('manage') }}<div>Manage</div><span class=val>{{ n_iphones }} iPhone{{ '' if n_iphones == 1 else 's' }}</span></a></div>
<p class=ftr>Only you see this: you run this SideDrop.</p>{% endif %}
<div class="g grp sg" id=sTheme><a class="row mrow" href=/theme data-push>{{ row_icon('theme') }}<div>Theme</div><span class=val id=themeV>{{ theme_name }}</span></a>
{% if enrolled %}<div class="row irow">{{ row_icon('notifications') }}<div>Update Alerts</div><label class=sw><input type=checkbox id=pushSw aria-label="Update Alerts"
 onchange="pushSet(this.checked)"><i></i><span class=k></span></label></div>{% endif %}</div>
{% if enrolled %}<p class=ftr id=pushNote>Tells you when an app you installed has a new version.</p>{% endif %}
<div class="g grp sg" id=sHome><a class="row mrow" href=/home-screen data-push>{{ row_icon('homeScreen') }}<div>Add to Home Screen</div></a></div>
<p class=ftr>Open SideDrop from your Home Screen like an app.</p>
<div class="g grp sg" id=sHelp><a class="row mrow" href=/help data-push id=helpRow>{{ row_icon('help') }}<div>Help</div></a></div>
<a class="b grey out" href=/logout>Sign Out</a>
<script>/* F26: the Theme row's detail, the theme showing now (THEME_BOOT's themeState); again after Settings > Theme pops, or the iPhone flips */
const THEME_NAMES={{ theme_names|tojson }};
function themeVal(){let s=themeState(),dk=s.mode=="dark"||s.mode=="auto"&&matchMedia("(prefers-color-scheme: dark)").matches,e=document.getElementById("themeV");if(e)e.textContent=THEME_NAMES[dk?s.dark:s.light]}
themeVal();addEventListener("popstate",themeVal);addEventListener("pageshow",themeVal);matchMedia("(prefers-color-scheme: dark)").addEventListener("change",themeVal)</script>
{{ vfoot }}
</section>
</div>
{% if just_enrolled %}<div class=scrim id=welcome><div class=alert role=alertdialog aria-modal=true aria-labelledby=welT>
<h3 id=welT>Setup Complete</h3><p>This iPhone is registered. Enjoy!</p><p>Tap GET to install apps.</p>
<div class=abtns style="grid-template-columns:1fr"><button type=button class=ok onclick="welcomeOk()">OK</button></div></div></div>
<script>function welcomeOk(){welcome.hidden=true;history.replaceState(null,"","/")}</script>{% endif %}

{% if enrolled %}<div class=scrim id=devAsk hidden><div class=alert role=alertdialog aria-modal=true aria-labelledby=devT>
<h3 id=devT>Developer Mode Required</h3><p>{{ dev_why }}</p>
<p>Opening the app after it installs takes you there.</p>
<div class=abtns><button type=button onclick="devDone(1)">Show Me</button><button type=button class=ok onclick="devDone()">OK</button></div></div></div>{% endif %}
{% if first_run %}<div class=fl id=firstRun hidden data-due=1 role=dialog aria-modal=true aria-labelledby=frT><header class=nav><button type=button class=bar onclick="firstRunGo()">Cancel</button><h1 id=frT>Before You Install</h1>
<button type=button class="bar r" onclick="firstRunGo(1)">Install</button></header><div class=lscroll>
<p class=lead>{{ dev_why }}</p>{# F26: Stolen Device Protection left this sheet; it's in Help, under Register iPhone Didn't Work #}
<div class=c><div class=sh><div>Turn on Developer Mode<small>After the app installs</small></div></div>{{ dev_steps }}</div>
<button type=button class=gbtn onclick="firstRunGo(1)">Got It, Install</button></div></div>{% endif %}
{% if enrolled %}<div class=scrim id=pushAsk hidden><div class=alert role=alertdialog aria-modal=true aria-labelledby=pushT>
<h3 id=pushT>Get Notified of Updates?</h3><p>SideDrop can tell you when an app you installed has a new version.</p>
<div id=pushWeb hidden><div><p class=a2l><span>1. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M8 9H6.5A1.5 1.5 0 0 0 5 10.5v9A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 17.5 9H16M12 3v12M8 7l4-4 4 4"/></svg><b>Share</b></span></span><span>2. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><rect x=4 y=4 width=16 height=16 rx=4 /><path d="M12 8v8M8 12h8"/></svg><b>Add to Home Screen</b></span></span><span>3. Open SideDrop from there</span></p></div></div>
<div class=abtns><button type=button onclick="pushAsk.hidden=true">Not Now</button><button type=button class=ok id=pushOk>Allow</button></div></div></div>{% endif %}
{% if enrolled %}<div class=mks id=mkSheet hidden data-csrf="{{ mk }}" onclick="if(event.target==this)mkClose()"><div class=mkp role=dialog aria-modal=true aria-labelledby=mkH>
<p id=mkH></p><div id=mkB></div><button type=button class=mkc onclick="mkClose()">Cancel</button></div></div>{% endif %}
<div class=con id=con hidden role=dialog aria-modal=true aria-labelledby=conT><header class=nav><span></span><h1 id=conT>Running</h1>
<button type=button class="bar r" id=conX onclick="conClose()">Cancel</button></header><div class=conlog id=conL aria-live=polite><span class=concur id=conCur></span></div>
<div class=confoot><div class=cons id=conS></div><button type=button class=confin id=conF hidden></button></div></div>
<nav class=tabs aria-label=Sections>
<a href=#apps><svg viewBox="0 0 30 30"><path d="M4 4h9v9H4zm13 0h9v9h-9zM4 17h9v9H4zm13 0h9v9h-9z"/></svg>Apps<span class=badge id=badge{% if not updates %} hidden{% endif %}>{{ updates|length }}</span></a>
<a href=#ifizbox><svg viewBox="0 0 30 30"><path d="M15 3l11 5.5-11 5.5L4 8.5zM4 10.7l10 5v11.1l-10-5zM16 15.7l10-5v11.1l-10 5z"/></svg>iFizBox</a>
{% if files %}<a href=#files><svg viewBox="0 0 30 30"><path d="M3 8a1.5 1.5 0 0 1 1.5-1.5h7.2l2.6 3h11.2A1.5 1.5 0 0 1 27 11v13.5a1.5 1.5 0 0 1-1.5 1.5h-21A1.5 1.5 0 0 1 3 24.5z"/></svg>Files</a>{% endif %}
<a href=#settings><svg viewBox="0 0 30 30"><path fill-rule=evenodd d="M15 7.5a7.5 7.5 0 1 0 0 15a7.5 7.5 0 1 0 0-15zm0 4.3a3.2 3.2 0 1 1 0 6.4a3.2 3.2 0 1 1 0-6.4z"/>{% for r in range(0, 360, 45) %}<rect x="12.8" y="3" width="4.4" height="6" rx="1" transform="rotate({{ r }} 15 15)"/>{% endfor %}</svg>Settings</a></nav>
<svg width=0 height=0 style="position:absolute" aria-hidden=true><linearGradient id=taboff x1=0 y1=0 x2=0 y2=1><stop offset=0 stop-color="#9d9d9d"/><stop offset=1 stop-color="#595959"/></linearGradient><linearGradient id=tabglow x1=.37 y1=0 x2=.63 y2=1><stop offset=0 stop-color="#d9e5f9"/><stop offset=.473 stop-color="#77b5eb"/><stop offset=.488 stop-color="#0091e5"/><stop offset=1 stop-color="#0fbff7"/></linearGradient></svg>
<script>
/* tabs keep their place (scroll, and a page pushed on Settings) and add no history, as in an iOS app; tapping the open tab pops its page, then scrolls to the top */
let cur=null,pos={},L=null,LS=[],cache={},STAMP={{ stamp }};  // LS: the pushed pages, bottom first; L is the top one
function go(t){history.replaceState(history.state,"","#"+t);dispatchEvent(new HashChangeEvent("hashchange"))}  // replaceState fires no hashchange of its own
function show(){let t=location.hash.slice(1);if(t=="more")t="settings";/* more: Home Screen links from before */if(!document.getElementById("t-"+t))t="apps";if(cur&&cur!=t)pos[cur]=scr.scrollTop;
 document.querySelectorAll("#scr>.page").forEach(p=>p.hidden=p.id!="t-"+t);
 document.querySelectorAll(".tabs a").forEach(a=>a.getAttribute("href")=="#"+t?a.setAttribute("aria-current","page"):a.removeAttribute("aria-current"));
 navT.textContent=document.getElementById("t-"+t).dataset.title;if(cur!=t)scr.scrollTo(0,pos[t]||0);cur=t;LS.forEach(l=>l.hidden=l.dataset.tab!=t);navR()}
document.querySelectorAll(".tabs a").forEach(a=>a.addEventListener("click",e=>{e.preventDefault();let t=a.getAttribute("href").slice(1);
 if(t!=cur)return go(t);if(L)history.back();else scr.scrollTo({top:0,behavior:"smooth"})}));
/* a pushed page: fetched and drawn over the tab (its own nav with Back), one history entry, so Back, iOS's edge swipe and forward all work.
   The server still serves each page whole (a reload, or no JS, gets the old full-page screen); anything unexpected falls back to that. */
function parsePage(r,h){if(!r.ok||new URL(r.url).pathname=="/")return null;let d=new DOMParser().parseFromString(h,"text/html"),s=d.querySelector("section.page"),n=d.querySelector(".nav h1");return s&&n?{title:n.textContent,body:s.innerHTML,url:r.url}:null}
function fetchPage(url,init){return fetch(url,Object.assign({credentials:"same-origin"},init)).then(r=>r.text().then(h=>parsePage(r,h))).catch(()=>null)}
function fill(p){L.url=p.url;L.querySelector("h1").textContent=p.title;L.querySelector(".page").innerHTML=p.body;L.querySelector(".lscroll").scrollTop=0;
 L.querySelectorAll(".page script").forEach(s=>{let n=document.createElement("script");n.textContent=s.textContent;s.replaceWith(n)})}  // innerHTML leaves scripts dead; a page's own script (Manage → iPhones' refresh) runs as on a full load
const EASE="cubic-bezier(.36,.66,.04,1)";
function slide(l,from,to,done,under){  /* p: 0 the tab (or the pushed page under) alone, 1 the pushed page l in place */
 let o={duration:350,easing:EASE,fill:"forwards"},base=under?[under]:[document.querySelector(".nav"),document.getElementById("t-"+cur)],sh=document.createElement("div");sh.className="shade";l.before(sh);
 let an=[l.animate([{transform:`translate3d(${(1-from)*100}%,0,0)`},{transform:`translate3d(${(1-to)*100}%,0,0)`}],o),sh.animate([{opacity:.1*from},{opacity:.1*to}],o),
  ...base.map(b=>b.animate([{transform:`translate3d(${-30*from}%,0,0)`},{transform:`translate3d(${-30*to}%,0,0)`}],o))];
 an[0].finished.then(()=>{an.forEach(a=>a.cancel());sh.remove();done&&done()})}
function open(p,from,anim,id){let under=L;
 L=document.createElement("div");L.className="layer";L.dataset.tab=cur;L.pid=id;LS.push(L);
 L.innerHTML='<header class=nav><button type=button class="bar back"></button><h1></h1><span></span></header><div class=lscroll><section class=page></section></div>';
 L.querySelector(".back").textContent=(under?under.querySelector("h1"):navT).textContent;L.querySelector(".back").onclick=()=>history.back();L.sel=from;fill(p);document.body.append(L);
 if(anim)slide(L,0,1,()=>from&&from.classList.remove("sel"),under);else if(from)from.classList.remove("sel")}
function close(anim){let l=LS.pop();L=LS[LS.length-1]||null;if(!l)return;if(!anim||l.hidden)return l.remove();
 /* the row that opened it fades from blue as the page slides off (a copy over it, so only opacity animates) */
 let el=l.sel,g=null;if(el&&el.offsetParent){g=el.cloneNode(true);g.removeAttribute("href");g.classList.add("sel","ghost");
  Object.assign(g.style,{left:el.offsetLeft+"px",top:el.offsetTop+"px",width:el.offsetWidth+"px",height:el.offsetHeight+"px"});el.parentElement.style.position="relative";el.parentElement.append(g);
  g.animate([{opacity:1},{opacity:0}],{duration:350,easing:EASE,fill:"forwards"})}
 slide(l,1,0,()=>{l.remove();g&&g.remove()},L)}
function push(url,init,from,nest){return fetchPage(url,init).then(p=>{if(!p)return false;let id=Date.now();cache[id]=p;
 if(L&&!nest){fill(p);L.pid=id;history.replaceState({push:id},"");return true}  // a form on the pushed page: its answer replaces it (the server redirects back to the same page)
 history.pushState({push:id},"");open(p,from,true,id);return true})}  // nest: a row on a pushed page pushes another over it (Manage → iPhones → an iPhone)
if(history.state&&history.state.push)history.replaceState(null,"");  // a reload forgets pushed pages
addEventListener("popstate",e=>{let id=e.state&&e.state.push,anim=!e.hasUAVisualTransition,i=id?LS.findIndex(l=>l.pid==id):-1;  // iOS's edge swipe animates it already
 if(id&&i<0){if(cache[id])open(cache[id],null,anim,id)}else for(let n=LS.length-i-1;n>0;n--)close(anim&&n==1)});  // back pops down to that page (the last one slides); forward opens it again
document.addEventListener("click",e=>{let a=e.target.closest("a[data-push]");if(!a||e.defaultPrevented)return;e.preventDefault();if(L&&!L.contains(a)||a.classList.contains("sel"))return;
 a.classList.add("sel");push(a.href,{},a,!!L).then(ok=>{if(!ok)location.href=a.href})});
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
 conLine("step","Installing "+a+" "+b.dataset.v);conLine("raw","Signed for this iPhone by SideDrop");conLine("raw","Certificate: inside, imported on first launch");conLine("raw",b.dataset.n+" sources: inside, added on first launch");
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
 if(!d.getElementById("t-files")!=!document.getElementById("t-files"))return location.reload();  // the Files tab came or went: the tab bar changes
 if(d.getElementById("t-files"))document.getElementById("t-files").innerHTML=d.getElementById("t-files").innerHTML;
 if(newBuild((d.querySelector("meta[name=build]")||{}).content))return;  // a new deploy: newBuild reloads the whole page
 ["t-apps","t-ifizbox"].forEach(i=>document.getElementById(i).innerHTML=d.getElementById(i).innerHTML);STAMP=+d.getElementById("stamp").dataset.v;
 try{if(localStorage.sdp)sdpDone()}catch(e){}document.querySelectorAll("input[name=name]").forEach(i=>i.oninput());navR()}).catch(()=>{})}
let held=0,pulled=0;addEventListener("touchstart",()=>{held=1;pulled=0},{passive:true});
scr.addEventListener("scroll",()=>{if(held&&!pulled&&scr.scrollTop<-70){pulled=1;hap()}},{passive:true});  // the tick as it arms, like UIRefreshControl
addEventListener("touchend",()=>{held=0;if(pulled){pulled=0;reloadData()}},{passive:true});
/* the Apps tab's badge counts its rows with an update (.row.up) */
function navR(){let n=document.querySelectorAll("#t-apps .row.up").length;badge.textContent=n;badge.hidden=!n&&!badge.classList.contains("busy")}
function mark(b,quiet){let n=b.dataset.app;if(!n)return;navigator.sendBeacon("/installed",new URLSearchParams({name:n}));
 document.querySelectorAll('.row .get[data-app="'+n+'"]').forEach(x=>{x.classList.add("done");if(x.dataset.arm)x.dataset.arm="INSTALLED";if(!x.classList.contains("go"))x.textContent="INSTALLED"});if(!quiet)setTimeout(devMaybe,1500);  // after iOS's install prompt
 document.querySelectorAll("#t-apps .row.up").forEach(r=>{if(r.querySelector('[data-app="'+n+'"]')){r.classList.remove("up");r.querySelectorAll(".upn,.ub").forEach(s=>s.remove());r.querySelectorAll(".get.upd").forEach(x=>x.classList.remove("upd"))}});navR()}  // installed now: no longer an update
addEventListener("hashchange",show);
/* Home's iFizBox card (F25): its INSTALL opens the iFizBox page and starts the install in the same tap (still a tap for Safari's itms-services),
   as its Install button would. The flag is read once, so coming back to the page later doesn't run it again; then the card reads INSTALLED. */
let ifzAuto=0;
addEventListener("hashchange",()=>{if(ifzAuto&&cur=="ifizbox"){ifzAuto=0;ifzRun()}});
function ifzGo(c){ifzAuto=1;go("ifizbox");ifzAuto=0;if(c&&document.getElementById("ifzb")){c.classList.remove("go");c.classList.add("done");c.textContent="INSTALLED"}return false}
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
/* asked once per phone: after the first INSTALL tap */
/* first INSTALL on this phone: warn that opening the app will ask for Developer Mode; then the notifications ask */
function devMaybe(){let a=null;try{a=localStorage.devTold}catch(e){}if(a||!window.devAsk)return pushMaybe();try{localStorage.devTold=1}catch(e){}devAsk.hidden=false}
function devDone(show){devAsk.hidden=true;if(show)helpOpen("dev");else setTimeout(pushMaybe,400)}
/* F26: Help is a page pushed on Settings (/help); helpOpen(id) goes there from anywhere and opens that item (Developer Mode from the alert) */
function helpOpen(id){go("settings");let a=document.getElementById("helpRow");
 if(L&&L.url&&new URL(L.url).pathname=="/help")return helpItem(id),false;
 push("/help",{},a,!!L).then(ok=>{if(!ok)location.href="/help"+(id?"#"+id:"");else helpItem(id)});return false}
function helpItem(id){let d=id&&L&&L.querySelector("details#"+id);if(!d)return;d.open=true;
 setTimeout(()=>{let s=L.querySelector(".lscroll");s.scrollTo({top:s.scrollTop+d.getBoundingClientRect().top-56,behavior:"smooth"})},400)}
function pushMaybe(){let a=null;try{a=localStorage.pushAsked}catch(e){}if(a||!window.pushAsk||(pushOK&&Notification.permission!="default"))return;
 try{localStorage.pushAsked=1}catch(e){}pushShow()}
function pushShow(){pushWeb.hidden=pushOK;pushOk.textContent=pushOK?"Allow":"OK";let bs=pushOk.parentNode;bs.style.gridTemplateColumns=pushOK?"":"1fr";bs.firstElementChild.style.display=pushOK?"":"none";
 pushOk.onclick=()=>{pushAsk.hidden=true;if(pushOK){pushSet(true);if(window.pushSw)pushSw.checked=true}};pushAsk.hidden=false}
if(pushOK&&window.pushSw)pushSub().then(([r,s])=>pushSw.checked=!!s&&Notification.permission=="granted").catch(()=>{});
/* change a GET button's label and colour with its width animating, like the App Store (a label swap alone jumps the width) */
function morph(b,f){let w0=b.offsetWidth;f();let w1=b.offsetWidth;if(w0==w1)return;b.style.width=w0+"px";b.offsetWidth;b.style.width=w1+"px";clearTimeout(b.mt);b.mt=setTimeout(()=>b.style.width="",300)}
function disarm(keep){document.querySelectorAll(".get.go[data-arm]").forEach(b=>{if(b!=keep)morph(b,()=>{b.classList.remove("go");b.textContent=b.dataset.arm})})}
/* F27: GET arms as INSTALL and an installed app's button as REINSTALL (green, a second tap installs); UPDATE installs on its first tap */
function arm(b){if(b.classList.contains("go")||b.dataset.arm=="UPDATE"){mark(b);setTimeout(()=>disarm(),1500);return true}disarm(b);morph(b,()=>{b.classList.add("go");b.textContent=b.dataset.arm=="INSTALLED"?"REINSTALL":"INSTALL"});return false}
/* F27: hold an Apps row (iFizBox's card too) about half a second without moving it for an iOS 6 action sheet: Mark as Updated, Installed or
   Not Installed, by what this iPhone has recorded. The row highlights while held; the click that ends the hold is eaten, so it installs nothing. */
function mkState(r){return r.classList.contains("up")?"up":r.querySelector(".get.done")?"inst":"none"}
function mkItems(st){return st=="up"?[["Mark as Updated","installed"],["Mark as Not Installed","forget"]]:st=="inst"?[["Mark as Not Installed","forget"]]:[["Mark as Installed","installed"]]}
let mkTm=null,mkRow=null,mkXY=null,mkEat=0;
function mkCancel(){clearTimeout(mkTm);mkTm=null;if(mkRow&&mkSheet.hidden)mkRow.classList.remove("held");if(mkSheet.hidden)mkRow=null}
function mkRowAt(t){let r=t.closest&&t.closest("#t-apps .g:not(.locked) .row");return r&&r.querySelector(".get[data-app]")&&window.mkSheet?r:null}
addEventListener("pointerdown",e=>{if(e.button||!window.mkSheet||!mkSheet.hidden)return;mkCancel();let r=mkRowAt(e.target);if(!r)return;mkRow=r;mkXY=[e.clientX,e.clientY];
 if(!e.target.closest(".get"))setTimeout(()=>{if(mkRow==r&&mkTm)r.classList.add("held")},100);  // a cell highlights on touch; a button in it doesn't
 mkTm=setTimeout(()=>{mkTm=null;mkEat=1;r.classList.add("held");if(window.hap)hap();mkOpen(r)},500)},true);
addEventListener("pointermove",e=>{if(mkTm&&mkXY&&Math.hypot(e.clientX-mkXY[0],e.clientY-mkXY[1])>10)mkCancel()},true);
["pointerup","pointercancel"].forEach(t=>addEventListener(t,()=>{if(mkTm)mkCancel()},true));
addEventListener("scroll",()=>{if(mkTm)mkCancel()},{passive:true,capture:true});
addEventListener("click",e=>{if(mkEat){mkEat=0;e.preventDefault();e.stopImmediatePropagation()}},true);  // capture: before the row's links and the first-run hook
addEventListener("contextmenu",e=>{if(mkRow)e.preventDefault()});
function mkOpen(r){let b=r.querySelector(".get[data-app]"),t=r.querySelector(":scope>div:not(.ico)");mkH.textContent=t?t.childNodes[0].textContent.trim():b.dataset.app;mkB.textContent="";
 mkItems(mkState(r)).forEach(([l,d])=>{let x=document.createElement("button");x.type="button";x.textContent=l;x.onclick=()=>mkDo(b.dataset.app,d);mkB.append(x)});
 setTimeout(()=>mkEat=0,700);mkSheet.hidden=false}
function mkClose(){mkSheet.hidden=true;if(mkRow)mkRow.classList.remove("held");mkRow=null}
function mkDo(n,d){mkClose();fetch("/installed/mark",{method:"POST",body:new URLSearchParams({name:n,do:d,csrf:mkSheet.dataset.csrf})}).then(r=>{if(!r.ok)throw 0;return refreshIn()}).catch(()=>location.reload())}
addEventListener("click",e=>{if(!e.target.closest("[data-arm]"))disarm()});
function steps(b){let open=b.getAttribute("aria-expanded")!="true";b.setAttribute("aria-expanded",open);b.closest(".row").nextElementSibling.classList.toggle("open",open)}
function sdpDone(save){let d=document.getElementById("sdp");if(!d)return;d.classList.add("ok");d.open=false;regf.disabled=false;
 if(save){try{localStorage.sdp=1}catch(e){}regf.querySelector("input").focus()}}
try{if(localStorage.sdp)sdpDone()}catch(e){}
function setupOpen(on){let s=document.getElementById("setup");if(!s)return;s.hidden=!on;setupT.setAttribute("aria-expanded",on)}  // the Apps header's 'Set up this iPhone' tile unfolds the steps
function nudge(){go("apps");setupOpen(true);let r=document.querySelector("#sdp:not(.ok)")||document.getElementById("reg");if(r.open===false)r.open=true;r.classList.remove("nudge");void r.offsetWidth;r.classList.add("nudge");if(r.id=="reg")r.querySelector("input").focus();return false}
/* the first install tap on this iPhone opens the splash (Developer Mode) instead; Install there carries the held tap on, and the
   server remembers the phone (/first-run), so Safari and the Home Screen app show it once between them. Cancel keeps it for the next tap. */
let frNext=null;
document.addEventListener("click",e=>{let f=window.firstRun,b=f&&f.dataset.due&&e.target.closest('a[href^="itms-services:"],#ifzb');if(!b)return;
 e.preventDefault();e.stopImmediatePropagation();frNext=b;f.hidden=false;f.querySelector(".lscroll").scrollTop=0},true);  // capture: before the link's own onclick
function firstRunGo(ok){let b=frNext;frNext=null;firstRun.hidden=true;if(!ok)return;delete firstRun.dataset.due;
 try{localStorage.devTold=1}catch(e){}fetch("/first-run",{method:"POST"}).catch(()=>{});  // it covered Developer Mode: no second alert after the install
 if(b){if(b.dataset.arm)b.classList.add("go");b.click()}}  // an armed GET installs on click
show();
addEventListener("pageshow",()=>{document.querySelectorAll("input[name=name]").forEach(i=>i.oninput());theme();if(window.themeMarks)themeMarks()});  // themeMarks exists only once Settings > Theme was pushed
</script>""", error=error, enrolled=enrolled, mine=mine, stamp=signed_stamp(), vapid=vapid_public() if enrolled else "", admin_on=admin_enabled(), updates=updates, just_enrolled=enrolled and bool(request.args.get("enrolled")) and request.cookies.get("device") != tok, apps=apps, ifz=ifz, third=third, n_sources=len(read_urls(IFIZBOX_SOURCES)),
        ifz_m=signed_url(f"/m/{ifz['name']}.plist") if ifz else "",
        manifest=lambda n: quote(signed_url(f"/m/{n}.plist"), safe=""),
        adl=lambda f: signed_url(f"/af/{f.relative_to(APP_FILES)}"),
        file_labels=file_labels, is_admin=is_admin(), n_iphones=manage_iphone_count() if is_admin() else 0, theme_names={n: p[1] for n, p in PALETTES.items()},
        theme_name=PALETTES[THEMES["light"][0]][1], files=shared_files(), inv_name=invite_name(), fdl=lambda f: signed_url(f"/f/{f.name}"),
        first_run=enrolled and first_run_due(token_udid(tok)), mk=mark_csrf(token_udid(tok)) if enrolled else ""))
    if enrolled and request.args.get("enrolled"):  # survives sign-out; re-checked against the profile on every load
        resp.set_cookie("device", tok, max_age=10 * 365 * 86400, secure=True, httponly=True, samesite="Lax")
    return resp


@app.get("/apple-touch-icon.png")
def touch_icon():
    return send_from_directory(HERE, "icon.png", max_age=86400)  # source: icon.svg (rsvg-convert -w 180 icon.svg -o icon.png)


@app.post("/login")
def login():
    pw = request.values.get("password", "")
    if needs_setup() and hmac.compare_digest(pw.encode(), DEFAULT_PASSWORD.encode()):  # first run: only the setup splash
        session.permanent, session["setup"] = True, True
        return redirect("/setup")
    if password_ok(pw):
        session.permanent, session["ok"], session["pv"] = True, True, ["f", password_ver()]
        session.pop("admin", None)  # a friend's login on a shared browser drops an earlier admin one
    elif not needs_setup() and admin_enabled() and password_ok(pw, admin=True):  # the same form and ?password= link sign the admin in
        session.permanent, session["ok"], session["admin"], session["csrf"] = True, True, time.time(), secrets.token_urlsafe(32)
        session["pv"] = ["a", password_ver(True)]
    else:
        time.sleep(2)  # ponytail: slows guessing per request, add per-IP lockout if this ever gets hammered
        return redirect("/?err=1")
    return redirect("/")


@app.get("/sw.js")
def service_worker():
    """Shows pushes; tapping one opens the Apps tab, where the update waits. Served from / so its scope is the whole site."""
    return """self.addEventListener("push",e=>{let d=e.data.json();e.waitUntil(self.registration.showNotification(d.title,{body:d.body,icon:"/apple-touch-icon.png",data:d.url}))});
self.addEventListener("notificationclick",e=>{e.notification.close();e.waitUntil(clients.openWindow(e.notification.data||"/"))});""", 200, {
        "Content-Type": "text/javascript", "Cache-Control": "no-cache"}


@app.get("/manifest.webmanifest")
def manifest_json():  # iOS only offers web push to Home Screen apps with display: standalone
    # as iFizBox's: an opaque black status bar (capable + status-bar-style black above; a translucent one put the nav under it, where iOS 26 blurs
    # it and taps near the top go to the status bar) and portrait only (rotating left the page offset). iOS reads these when the icon is added.
    return {"name": "SideDrop", "short_name": "SideDrop", "description": "Share an Apple developer account with friends and sideload apps.", "id": "/", "scope": "/", "display": "standalone", "orientation": "portrait",
            "start_url": "/", "background_color": "#c8cfd6", "theme_color": "#597498",
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
    """INSTALL tapped: remember this phone has the current version, so its Apps row can offer later ones as updates."""
    udid, p = token_udid(request.cookies.get("device", "")), SIGNED / f"{request.form.get('name', '')}.ipa"
    if not logged_in() or not udid or p.parent != SIGNED or not p.is_file():
        abort(403)
    i = ipa_info(p)
    with installed_lock:
        data = installed()
        data.setdefault(udid, {})[p.stem] = f"{i['short']}/{i['version']}"
        save_json(INSTALLED, data)
    return "", 204


def mark_csrf(udid):
    """F27: the hold sheet's CSRF token, tied to this iPhone (friends' sessions carry no csrf): a page drawn for one phone can't mark another's."""
    return hmac.new(SECRET, b"mark:" + udid.encode(), "sha256").hexdigest()[:32] if udid else ""


@app.post("/installed/mark")
def mark_app():
    """F27: an Apps row's hold sheet. do=installed (Mark as Installed, and Mark as Updated: both record the current version) or
    do=forget (Mark as Not Installed), for this registered iPhone's device token only."""
    udid, p, do = token_udid(request.cookies.get("device", "")), SIGNED / f"{request.form.get('name', '')}.ipa", request.form.get("do", "")
    if (not logged_in() or not udid or udid not in profile_udids() or do not in ("installed", "forget")
            or not hmac.compare_digest(request.form.get("csrf", ""), mark_csrf(udid)) or p.parent != SIGNED or not p.is_file()):
        abort(403)
    with installed_lock:
        data = installed()
        if do == "forget":
            data.get(udid, {}).pop(p.stem, None)
        else:
            i = ipa_info(p)
            data.setdefault(udid, {})[p.stem] = f"{i['short']}/{i['version']}"
        save_json(INSTALLED, data)
    return "", 204


FIRST_RUN = DATA / "first_run.json"  # {udid: unix time} phones that went through the first-install splash (SDP + Developer Mode)
first_run_due = lambda udid: bool(udid) and udid not in load_json(FIRST_RUN)


@app.post("/first-run")
def first_run_seen():
    """The splash's Install: this phone has seen it, so later install taps go straight to iOS."""
    udid = token_udid(request.cookies.get("device", ""))
    if not logged_in() or not udid:
        abort(403)
    with installed_lock:
        data = load_json(FIRST_RUN)
        data.setdefault(udid, int(time.time()))
        save_json(FIRST_RUN, data)
    return "", 204


# --- first-run setup: with no PASSWORD in .env, the first sign-in uses DEFAULT_PASSWORD and lands on a splash that sets the passwords
# and takes the signing files. Saved in the data folder (passwords hashed); anything set in .env still wins. ---

SETUP = DATA / "setup.json"  # {password, admin_password: pbkdf2 hashes; p12_password, asc_key_id, asc_issuer_id, bundle_id}
DEFAULT_PASSWORD = "sidedrop"  # documented in the README; signs in only while setup is pending, and only to /setup
SETUP_KEYS = ("PASSWORD", "ADMIN_PASSWORD", "P12_PASSWORD", "ASC_KEY_ID", "ASC_ISSUER_ID", "BUNDLE_ID")
ENV_SET = {k for k in SETUP_KEYS if os.environ.get(k)}  # what .env set at start; the splash leaves these alone


def hash_password(pw, salt=None, n=200_000):
    salt = salt or secrets.token_hex(16)
    return f"pbkdf2_sha256${n}${salt}${hashlib.pbkdf2_hmac('sha256', pw.encode(), bytes.fromhex(salt), n).hex()}"


def hash_ok(pw, saved):
    try:
        _, n, salt, _ = saved.split("$")
        return bool(pw) and hmac.compare_digest(hash_password(pw, salt, int(n)), saved)
    except ValueError:
        return False


def password_ok(pw, admin=False):
    """The password Manage set over .env's (F12: an override, while .env still holds the value it replaced), else the .env
    password if set, else the hash the splash or Manage saved."""
    env, p = (ADMIN_PASSWORD, "admin_") if admin else (PASSWORD, "")
    s = load_json(SETUP)
    if env and not s.get(f"{p}password_override"):
        return hmac.compare_digest(pw.encode(), env.encode())
    return hash_ok(pw, s.get(f"{p}password_override" if env else f"{p}password", ""))


def password_ver(admin=False):
    """Bumped by each change of that password; logged_in() signs out sessions made before it."""
    return load_json(SETUP).get("admin_password_ver" if admin else "password_ver", 0)


def env_overridden(admin=False):
    return bool((ADMIN_PASSWORD if admin else PASSWORD) and load_json(SETUP).get(("admin_" if admin else "") + "password_override"))


def drop_stale_overrides():
    """An override replaced one .env value: once .env holds a different one, .env wins again and the override goes."""
    s, changed = load_json(SETUP), False
    for p, env in (("", PASSWORD), ("admin_", ADMIN_PASSWORD)):
        if f"{p}password_override" in s and not (env and hash_ok(env, s.get(f"{p}password_env", ""))):
            s.pop(f"{p}password_override"), s.pop(f"{p}password_env", None)
            changed = True
    if changed:
        save_json(SETUP, s)


def needs_setup():
    return not PASSWORD and not load_json(SETUP).get("password")


def admin_enabled():
    return bool(ADMIN_PASSWORD or load_json(SETUP).get("admin_password"))


def apply_setup():
    """Fill in what .env left empty from the saved setup (.env wins)."""
    global P12_PASSWORD, BUNDLE_ID
    s = load_json(SETUP)
    if "P12_PASSWORD" not in ENV_SET and "p12_password" in s:
        P12_PASSWORD = s["p12_password"]
    if "BUNDLE_ID" not in ENV_SET and s.get("bundle_id"):
        BUNDLE_ID = s["bundle_id"]
    for k in ("ASC_KEY_ID", "ASC_ISSUER_ID"):  # asc() reads these from the environment
        if k not in ENV_SET and s.get(k.lower()):
            os.environ[k] = s[k.lower()]


apply_setup()
drop_stale_overrides()


def p12_opens(blob, pw):
    try:
        pkcs12.load_key_and_certificates(blob, pw.encode() or None)
        return True
    except Exception:
        return False


# PKCS#12 PBE algorithms (1.2.840.113549.1.12.1.x, DER-encoded) the image's static musl zsign 1.1.2 can't open: RC4-128/40,
# 2-key DES, RC2-128/40 (Keychain exports carry RC2-40). Only 3DES (.3) of the family loads without OpenSSL's legacy provider.
LEGACY_PBES = [bytes.fromhex("060a2a864886f70d010c01") + bytes([n]) for n in (1, 2, 4, 5, 6)]


def p12_repacked(blob, pw):
    """A .p12 zsign can't load (bags under RC2 or RC4) written again with the same key, certificates and password as 3DES/SHA1,
    as make_certificate writes it; None when it needs nothing (or doesn't open)."""
    if not any(oid in blob for oid in LEGACY_PBES):
        return None
    try:
        got = pkcs12.load_pkcs12(blob, pw.encode() or None)
    except Exception:
        return None
    if got.cert is None or got.key is None:
        return None
    enc = serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000).hmac_hash(hashes.SHA1()) \
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).build(pw.encode()) if pw \
        else serialization.NoEncryption()  # no password: nothing to encrypt with, and nothing for zsign to decrypt
    return pkcs12.serialize_key_and_certificates(got.cert.friendly_name or b"sidedrop", got.key, got.cert.certificate,
                                                 [c.certificate for c in got.additional_certs] or None, enc)


def save_p12(blob, pw):
    """Writes cert.p12, repacked when zsign couldn't load it as it is; the file as given is kept beside it as cert.p12.bak."""
    if (new := p12_repacked(blob, pw)) is not None:
        P12.with_suffix(".p12.bak").write_bytes(blob)
        P12.with_suffix(".p12.bak").chmod(0o600)
        print("cert.p12 used RC2/RC4, which zsign can't load: saved it again as 3DES (the original is cert.p12.bak)", flush=True)
        blob = new
    P12.write_bytes(blob)
    P12.chmod(0o600)


def repack_p12():
    """At start: a cert.p12 saved before uploads were repacked (or copied in by hand) gets the same treatment."""
    try:
        if P12.exists() and p12_repacked(blob := P12.read_bytes(), P12_PASSWORD) is not None:
            save_p12(blob, P12_PASSWORD)
    except Exception as e:
        print("couldn't repack cert.p12:", e, flush=True)


def password_guesses(text, name=""):
    """Lines of a text file as p12 password guesses, as iFizBox's certfiles.js: "password: x" first, then a password file's
    first line, then every short line without spaces."""
    lines = [l.strip() for l in text.splitlines() if l.strip() and len(l.strip()) <= 128]
    labelled = [m.group(1).strip() for l in lines if (m := re.match(r"(?i)^(?:p12\s*)?(?:password|pass|pwd|密码)\s*[:=：-]\s*(.+)$", l))]
    first = lines[:1] if re.search(r"(?i)pass(word)?", name) else []
    plain = [l for l in lines if not re.search(r"\s", l) or len(lines) == 1]
    return list(dict.fromkeys(labelled + first + plain))


def sort_signing_files(files):
    """files: [(name, bytes)], loose or in .zips (as iFizBox takes them). Returns the .p12, the .p8 and guesses: p12 passwords
    from .txt files, the key ID from AuthKey_<ID>.p8, the issuer ID from a UUID in a text file."""
    import io
    out = {"p12": None, "p8": None, "passwords": [], "key_id": "", "issuer_id": ""}
    queue = list(files)
    while queue:
        name, data = queue.pop(0)
        base = name.rsplit("/", 1)[-1]
        ext = base.lower().rsplit(".", 1)[-1] if "." in base else ""
        if name.startswith("__MACOSX/") or base.startswith("._") or not base:
            continue
        if ext == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:  # ponytail: certificate zips are tiny; 4 MB cap per entry
                    queue += [(i.filename, z.read(i)) for i in z.infolist() if not i.is_dir() and i.file_size <= 4 << 20]
            except zipfile.BadZipFile:
                pass
        elif ext in ("p12", "pfx") and not out["p12"]:
            out["p12"] = data
        elif ext == "p8" and not out["p8"]:
            out["p8"] = data
            if m := re.match(r"AuthKey_([A-Z0-9]{10})\.p8$", base):
                out["key_id"] = m.group(1)
        elif ext in ("txt", "md", ""):
            text = data.decode("utf-8", "replace")
            out["passwords"] += password_guesses(text, base)
            if not out["issuer_id"] and (m := re.search(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", text, re.I)):
                out["issuer_id"] = m.group(0).lower()
    return out


def take_signing_files(f, uploads, s):
    """The setup splash's and Manage's Choose Signing Files: writes a working cert.p12 and .p8 into the data folder and the
    p12 password, Key ID, Issuer ID and App ID into s (the caller saves it). Returns an error or None."""
    err = None
    got = sort_signing_files([(u.filename or "", u.read()) for u in uploads if u.filename])
    if got["p12"]:  # a working certificate is kept even if something else is wrong, so a retry needn't pick it again
        typed = [f["p12_password"]] if f.get("p12_password") else []
        tries = [P12_PASSWORD] if "P12_PASSWORD" in ENV_SET else typed + got["passwords"] + [""]  # "" too: many have none
        p12_pw = next((g for g in tries if p12_opens(got["p12"], g)), None)
        if p12_pw is None:
            err = "The P12_PASSWORD in .env doesn't open this cert.p12." if "P12_PASSWORD" in ENV_SET else \
                "The certificate's password didn't open cert.p12. Type it in P12 Password."
        elif bad := [t for lvl, t in cert_problems(got["p12"], p12_pw) if lvl == "error"]:
            err = " ".join(bad)  # kept out: a certificate that can't sign would break every app on the next re-sign
        else:
            save_p12(got["p12"], p12_pw)
            s["p12_password"] = p12_pw
    elif f.get("p12_password") and P12.exists() and "P12_PASSWORD" not in ENV_SET:
        if p12_opens(P12.read_bytes(), f["p12_password"]):
            s["p12_password"] = f["p12_password"]
        else:
            err = "That password doesn't open cert.p12."
    if got["p8"]:
        try:
            serialization.load_pem_private_key(got["p8"], None)
            ASC_KEY.write_bytes(got["p8"])
        except (ValueError, TypeError):
            err = err or "The .p8 isn't an App Store Connect API key."
    for k, guess in (("asc_key_id", got["key_id"]), ("asc_issuer_id", got["issuer_id"]), ("bundle_id", "")):
        if k.upper() not in ENV_SET and (v := f.get(k, "").strip() or guess):
            s[k] = v
    return err


# --- certificate checks, the ones iFizBox makes: errors stop an upload, Manage shows a banner, startup logs them ---

CERT_WARN_DAYS = 30  # warn this long before the certificate expires
DIST_NAMES = ("Apple Distribution:", "iPhone Distribution:")  # the common name of a distribution certificate, new and old
cert_cache = {}  # {"key": (p12 mtime, password, BUNDLE_ID), "at": time, "problems": [...]}: Manage asks Apple once an hour


def cert_problems(blob, pw, now=None):
    """What's wrong with a .p12 by itself, no network: [(level, text)], level "error" (it can't sign) or "warning"."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(blob, pw.encode() or None)
    except Exception:
        return [("error", "The password doesn't open cert.p12.")]
    if cert is None and not extra:
        return [("error", "cert.p12 has no certificate in it.")]
    if key is None:  # a .p12 of only the certificate loads it among the extras
        return [("error", "cert.p12 has the certificate but not its private key. Export it again from Keychain Access "
                          "with the private key under it selected too.")]
    if cert is None:  # a key, and certificates none of which it pairs with
        return [("error", "cert.p12's private key doesn't belong to its certificate.")]
    out = []
    spki = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if spki(key.public_key()) != spki(cert.public_key()):
        out.append(("error", "cert.p12's private key doesn't belong to its certificate."))
    cn = ", ".join(a.value for a in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME))
    if not cn.startswith(DIST_NAMES):
        kind = "a development certificate" if cn.startswith(("Apple Development", "iPhone Developer")) else "not an Apple Distribution certificate"
        out.append(("error", f"cert.p12 is {kind} ({cn or 'no name'}). Ad hoc signing needs an Apple Distribution certificate."))
    now = now or datetime.datetime.now(datetime.timezone.utc)
    ends, day = cert.not_valid_after_utc, lambda t: f"{t:%b} {t.day}, {t.year}"
    left = ends - now
    if left.total_seconds() <= 0:
        out.append(("error", f"The certificate expired on {day(ends)}. Make a new Apple Distribution certificate."))
    elif left.days < CERT_WARN_DAYS:
        n = "less than a day" if left.days < 1 else f"{left.days} day{'s' * (left.days != 1)}"
        out.append(("warning", f"The certificate expires in {n} ({day(ends)}); apps signed with it stop opening then. "
                               "Make a new one and upload it on Manage before that."))
    return out


def ocsp_revoked(cert, extra=()):
    """Ask the certificate's OCSP responder (Apple's) about it: when it was revoked, or None (good, unknown, no responder)."""
    from cryptography.x509 import ocsp
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    where = lambda m: next((d.access_location.value for d in aia if d.access_method == m), None)
    responder, issuer_url = where(x509.oid.AuthorityInformationAccessOID.OCSP), where(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS)
    if not responder:
        return None
    issuer = next((c for c in extra or () if c.subject == cert.issuer), None)  # most .p12s don't carry the WWDR intermediate
    if issuer is None and issuer_url:
        data = requests.get(issuer_url, timeout=15).content
        issuer = x509.load_pem_x509_certificate(data) if data.startswith(b"-----") else x509.load_der_x509_certificate(data)
    if issuer is None:
        return None
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    r = requests.post(responder, data=req.public_bytes(serialization.Encoding.DER),
                      headers={"Content-Type": "application/ocsp-request"}, timeout=15)
    resp = ocsp.load_der_ocsp_response(r.content)
    if resp.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL and resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
        return resp.revocation_time_utc
    return None


def cert_account_problems():
    """The checks that need Apple: the certificate not revoked and in the account, the ad hoc profile made for it, the App ID
    there and, when explicit, with Push Notifications. [(level, text)] like cert_problems."""
    try:
        key, cert, extra = pkcs12.load_key_and_certificates(P12.read_bytes(), P12_PASSWORD.encode() or None)
    except Exception:
        return []  # cert_problems says why
    if key is None or cert is None:
        return []
    out = []
    try:
        if at := ocsp_revoked(cert, extra):
            out.append(("error", f"Apple revoked this certificate on {at:%b} {at.day}, {at.year}. Apps signed with it won't open; "
                                 "make a new Apple Distribution certificate."))
    except Exception as e:
        print("certificate revocation check failed:", e, flush=True)  # Apple's OCSP down: say nothing rather than guess
    if PROFILE.exists():
        made_for = embedded_plist(PROFILE.read_bytes()).get("DeveloperCertificates")
        if made_for and cert.public_bytes(serialization.Encoding.DER) not in made_for:
            out.append(("error", "The ad hoc profile was made for another certificate, so apps signed now won't install. "
                                 "Save the signing files on Manage again to make a new profile."))
    try:
        serial = f"{cert.serial_number:X}".lstrip("0")
        if not any(c["attributes"]["serialNumber"].upper().lstrip("0") == serial
                   for c in asc("GET", "/certificates", params={"limit": 200})["data"]):
            if not any("revoked" in t for _, t in out):
                out.append(("error", "cert.p12 isn't in your developer account: it was revoked, or the API key is another team's. "
                                     "Make a new Apple Distribution certificate, or use that team's API key."))
        if BUNDLE_ID:
            found = [b for b in asc("GET", "/bundleIds", params={"filter[identifier]": BUNDLE_ID, "limit": 200})["data"]
                     if b["attributes"]["identifier"] == BUNDLE_ID]  # the filter is a prefix match
            if not found:
                out.append(("error", f"The App ID {BUNDLE_ID} isn't in your developer account. Add it at developer.apple.com → "
                                     f"Identifiers{' as a wildcard App ID' if BUNDLE_ID.endswith('*') else ''}, or change BUNDLE_ID."))
            elif not BUNDLE_ID.endswith("*"):
                caps = asc("GET", f"/bundleIds/{found[0]['id']}/bundleIdCapabilities")["data"]
                if not any(c["attributes"].get("capabilityType") == "PUSH_NOTIFICATIONS" for c in caps):
                    out.append(("warning", f"The App ID {BUNDLE_ID} doesn't have Push Notifications, so apps signed with it get no "
                                           "notifications. Turn it on at developer.apple.com → Identifiers."))
    except Exception as e:
        out.append(("warning", f"Couldn't ask Apple about the certificate and App ID: {str(e)[:160]}"))
    return out


def cert_status(max_age=3600):
    """Every certificate problem, Apple's answers kept for max_age seconds or until the signing files change."""
    if not P12.exists():
        return []
    key = (P12.stat().st_mtime, P12_PASSWORD, BUNDLE_ID)
    if cert_cache.get("key") != key or time.time() - cert_cache.get("at", 0) > max_age:
        local = cert_problems(P12.read_bytes(), P12_PASSWORD)
        ok = not any(lvl == "error" and ("password" in t or "private key" in t) for lvl, t in local)
        cert_cache.update(key=key, at=time.time(), problems=local + (cert_account_problems() if ok else []))
    return cert_cache["problems"]


def log_cert_problems(problems):
    for lvl, text in problems:
        print(f"certificate {lvl}: {text}", flush=True)


if P12.exists() and not needs_setup():  # ponytail: once per worker; Apple's checks in the background so startup isn't held up
    log_cert_problems(cert_problems(P12.read_bytes(), P12_PASSWORD))
    threading.Thread(target=lambda: log_cert_problems(cert_account_problems()), daemon=True).start()


# --- setup with just the API key: sidedrop makes the Apple Distribution certificate and the App ID through the API ---

DIST_TYPES = ("DISTRIBUTION", "IOS_DISTRIBUTION")  # Apple Distribution, and the older iOS Distribution, which share the limit
opt = lambda key, option: [{"key": key, "options": [{"key": option, "enabled": True}]}]
# An explicit App ID gets every capability Apple's API takes for one (tried on a real team), so an app finds what it asks for in
# the profile; Push must work, the rest may be refused. Not in the API, so never in the profile: time-sensitive and communication
# notifications, WeatherKit, App Attest, fonts, memory limits, multitasking camera. {capabilityType: settings or None}
APP_ID_CAPS = {"PUSH_NOTIFICATIONS": None, "APP_GROUPS": None, "ASSOCIATED_DOMAINS": None,
               "ICLOUD": opt("ICLOUD_VERSION", "XCODE_6"), "GAME_CENTER": None, "HEALTHKIT": None, "HOMEKIT": None, "SIRIKIT": None,
               "NETWORK_EXTENSIONS": None, "PERSONAL_VPN": None, "MULTIPATH": None, "HOT_SPOT": None, "NFC_TAG_READING": None,
               "CLASSKIT": None, "AUTOFILL_CREDENTIAL_PROVIDER": None, "ACCESS_WIFI_INFORMATION": None, "COREMEDIA_HLS_LOW_LATENCY": None,
               "APPLE_ID_AUTH": opt("APPLE_ID_AUTH_APP_CONSENT", "PRIMARY_APP_CONSENT"), "WALLET": None, "IN_APP_PURCHASE": None,
               "INTER_APP_AUDIO": None, "WIRELESS_ACCESSORY_CONFIGURATION": None,
               "DATA_PROTECTION": opt("DATA_PROTECTION_PERMISSION_LEVEL", "COMPLETE_PROTECTION"), "MAPS": None, "APPLE_PAY": None}
# the manual certificate steps, shown where cert.p12 is picked (setup splash, Manage > Signing) instead of a link out
MANUAL_STEPS = """<style>.msteps{margin:0;padding-left:20px;font-size:14px;color:var(--sub);display:flex;flex-direction:column;gap:6px}
.msteps b{color:var(--fg,inherit)} .msteps code{display:block;margin-top:3px;font-size:12px;white-space:pre-wrap;overflow-wrap:anywhere;-webkit-user-select:text;user-select:text}</style>
<ol class=msteps>
<li><b>Make a certificate request.</b> On a Mac: Keychain Access → Certificate Assistant → Request a Certificate From a Certificate Authority, Saved to disk. Or with OpenSSL:
<code>openssl genrsa -out key.pem 2048
openssl req -new -key key.pem -out request.csr -subj "/CN=sidedrop"</code></li>
<li><b>Have Apple issue it.</b> <a href="https://developer.apple.com/account/resources/certificates/add">developer.apple.com → Certificates → +</a> → Apple Distribution → upload the request → download distribution.cer.</li>
<li><b>Make cert.p12.</b> On a Mac: open distribution.cer, then in Keychain Access → My Certificates right-click it → Export, with a password. Or with OpenSSL:
<code>openssl x509 -inform der -in distribution.cer -out cert.pem
openssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -out cert.p12</code></li>
<li><b>Pick cert.p12 here</b> and type its password (or add a password.txt). SideDrop makes the App ID with Push if your account doesn't have it.</li>
</ol>"""
KEY_ROLE_ERR = ("Apple refused: making certificates needs an API key with the Admin role (App Manager keys can register iPhones "
                "but not make certificates). Make an Admin key in App Store Connect → Users and Access → Integrations, or use "
                "Manual setup with your own cert.p12.")
LIMIT_ERR = ("Your account already has as many Apple Distribution certificates as Apple allows. Pick one to revoke and SideDrop "
             "makes a new one in its place. Apps signed with the revoked one stop opening, on every iPhone, wherever they were "
             "signed (another signing service, Xcode ad hoc builds); App Store and TestFlight apps aren't affected.")


def asc_status(e):
    """The HTTP status in asc()'s error, or 0 (network error)."""
    m = re.match(r"App Store Connect \w+ \S+: (\d{3})", str(e))
    return int(m.group(1)) if m else 0


def ensure_app_id(bid):
    """Make the App ID if the account lacks it, and give an explicit one every capability in APP_ID_CAPS it lacks (Push must
    succeed; another Apple refuses is skipped with a log line). A wildcard gets none: Apple gives wildcards no Push. Returns
    True when it made the App ID or added a capability, so the profile, which holds the capabilities it was made with, is stale."""
    found = [b for b in asc("GET", "/bundleIds", params={"filter[identifier]": bid, "limit": 200})["data"]
             if b["attributes"]["identifier"] == bid]  # the filter is a prefix match
    if found:
        if bid.endswith("*"):
            return False
        bundle = found[0]["id"]  # Apple refuses a limit on this list (400)
        have = {c["attributes"].get("capabilityType") for c in asc("GET", f"/bundleIds/{bundle}/bundleIdCapabilities")["data"]}
    else:
        bundle = asc("POST", "/bundleIds", json={"data": {"type": "bundleIds", "attributes": {
            "identifier": bid, "name": "SideDrop", "platform": "IOS"}}})["data"]["id"]
        have = set()
    changed = not found
    for cap, settings in APP_ID_CAPS.items() if not bid.endswith("*") else ():
        if cap in have:
            continue
        try:
            asc("POST", "/bundleIdCapabilities", json={"data": {"type": "bundleIdCapabilities",
                "attributes": {"capabilityType": cap, **({"settings": settings} if settings else {})},
                "relationships": {"bundleId": {"data": {"type": "bundleIds", "id": bundle}}}}})
            changed = True
        except RuntimeError as e:
            if cap == "PUSH_NOTIFICATIONS":
                raise
            print(f"App ID {bid}: couldn't turn on {cap}:", e, flush=True)
    return changed


def dist_certs():
    """The account's distribution certificates for the revoke picker, newest first: [{id, name, kind, created, expires, ours}]."""
    day = lambda t: f"{t:%b} {t.day}, {t.year}" if t else "?"
    try:
        _, mine, _ = pkcs12.load_key_and_certificates(P12.read_bytes(), P12_PASSWORD.encode() or None)
        ours = f"{mine.serial_number:X}".lstrip("0")
    except Exception:
        ours = None
    out = []
    for c in asc("GET", "/certificates", params={"filter[certificateType]": ",".join(DIST_TYPES), "limit": 200})["data"]:
        a = c["attributes"]
        if a.get("certificateType", "DISTRIBUTION") not in DIST_TYPES:
            continue
        try:  # Apple lists no creation date; the certificate itself has it
            created = x509.load_der_x509_certificate(base64.b64decode(a["certificateContent"])).not_valid_before_utc
        except Exception:
            created = None
        try:
            expires = datetime.datetime.fromisoformat(a["expirationDate"])
        except (KeyError, TypeError, ValueError):
            expires = None
        out.append(dict(id=c["id"], name=a.get("displayName") or a.get("name") or c["id"], created=day(created), expires=day(expires),
                        kind="iOS Distribution" if a.get("certificateType") == "IOS_DISTRIBUTION" else "Apple Distribution",
                        ours=bool(ours) and a.get("serialNumber", "").upper().lstrip("0") == ours,
                        at=created.timestamp() if created else 0))
    return sorted(out, key=lambda c: -c["at"])


def make_certificate(s, revoke=""):
    """A new Apple Distribution certificate through the API: a private key and CSR made here, POST /certificates, then cert.p12
    saved with a random password (into s, which the caller saves). revoke: the id of a certificate the admin picked to revoke
    first, never chosen here. Returns (error or None, the certificates to pick from when the account is full)."""
    if revoke:
        listed = dist_certs()
        if revoke not in [c["id"] for c in listed]:
            return "That certificate isn't in your account any more. Pick another.", listed
        asc("DELETE", f"/certificates/{revoke}")
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Apple signs only RSA 2048 requests
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "sidedrop")])).sign(key, hashes.SHA256())  # Apple sets its own subject
    try:
        made = asc("POST", "/certificates", json={"data": {"type": "certificates", "attributes": {
            "certificateType": "DISTRIBUTION", "csrContent": csr.public_bytes(serialization.Encoding.PEM).decode()}}})
    except RuntimeError as e:
        status = asc_status(e)
        if status == 403:
            return KEY_ROLE_ERR, []
        if status == 401:
            return "Apple didn't accept the API key: check the Key ID and Issuer ID belong to this .p8.", []
        if status == 409 and (listed := dist_certs()):
            return LIMIT_ERR, listed
        return f"Apple didn't make the certificate: {str(e)[:200]}", []
    cert = x509.load_der_x509_certificate(base64.b64decode(made["data"]["attributes"]["certificateContent"]))
    pw = P12_PASSWORD if "P12_PASSWORD" in ENV_SET else secrets.token_urlsafe(18)
    enc = serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000).hmac_hash(hashes.SHA1()) \
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).build(pw.encode())  # openssl -legacy: every iOS opens it (iFizBox carries it)
    P12.write_bytes(pkcs12.serialize_key_and_certificates(b"sidedrop", key, cert, None, enc))
    P12.chmod(0o600)
    s["p12_password"] = pw
    s["asc_role"] = "admin"  # the key made a certificate: Manage → Signing shows its role
    print(f"made Apple Distribution certificate {made['data'].get('id')} through the API", flush=True)
    return None, []


def api_signing(s, revoke=""):
    """The API-key path of the setup splash and Manage: the App ID if missing, then a certificate. (error, certificates to pick)."""
    try:
        if ensure_app_id(BUNDLE_ID):
            print(f"made App ID {BUNDLE_ID} (or gave it capabilities) through the API", flush=True)
    except Exception as e:
        if asc_status(e) == 403:
            return f"Apple refused to make the App ID {BUNDLE_ID}: the API key needs the Admin role. {str(e)[:160]}", []
        return f"Couldn't make the App ID {BUNDLE_ID}: {str(e)[:200]}", []
    try:
        return make_certificate(s, revoke)
    except Exception as e:
        return f"Couldn't make the certificate: {str(e)[:200]}", []


CERT_PICKER = """{% if certs %}<div class=g>{% for c in certs %}<label class=row style="flex-direction:row;align-items:center;font-weight:400">
<input type=radio name=revoke value="{{ c.id }}" data-name="{{ c.name }}" style="flex:none;width:22px;height:22px;margin:0;padding:0;box-shadow:none;accent-color:#d43a3a"><div style="flex:1;min-width:0"><b>{{ c.name }}</b>{% if c.ours %} · SideDrop's certificate{% endif %}
<small>{{ c.kind }} · made {{ c.created }} · expires {{ c.expires }}</small></div></label>{% endfor %}</div>{% endif %}"""
REVOKE_CONFIRM = "var r=this.querySelector('input[name=revoke]:checked');if(r&&!confirm('Revoke '+r.dataset.name+'? Apps signed with it stop opening, wherever they were signed.'))return false;"


@app.route("/setup", methods=["GET", "POST"])
def setup():
    """The first-run splash: only after signing in with DEFAULT_PASSWORD, only until it's saved."""
    if not needs_setup() or not session.get("setup"):
        return redirect("/")
    s, err, certs = load_json(SETUP), None, []
    if request.method == "POST":
        f = request.form
        pw, admin_pw = f.get("password", ""), f.get("admin_password", "")
        err = take_signing_files(f, request.files.getlist("files"), s)
        save_json(SETUP, {k: v for k, v in s.items() if k not in ("password", "admin_password")})
        apply_setup()
        need = lambda k: k not in ENV_SET and not s.get(k.lower())
        if err:
            pass
        elif len(pw) < 8 or (not ADMIN_PASSWORD and len(admin_pw) < 8):
            err = "Passwords need at least 8 characters."
        elif pw == DEFAULT_PASSWORD or admin_pw == DEFAULT_PASSWORD or pw == admin_pw:
            err = "Choose new passwords, and different ones for friends and for the admin."
        elif P12.exists() and need("P12_PASSWORD") and "p12_password" not in s:
            err = "Add the certificate's password (Manual setup → P12 Password)."
        elif not ASC_KEY.exists():
            err = "Add the App Store Connect API key (AuthKey_….p8)."
        elif need("ASC_KEY_ID") or need("ASC_ISSUER_ID"):
            err = "Fill in the API key's Key ID and Issuer ID."
        elif need("BUNDLE_ID") or "BUNDLE_ID" not in ENV_SET and not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(\.\*)?", BUNDLE_ID):
            err = "Fill in the App ID (BUNDLE_ID), such as com.you.sideload (or a wildcard, com.you.*, which gets no notifications)."
        elif not P12.exists() and (got := api_signing(s, f.get("revoke", "")))[0]:  # no cert.p12 uploaded: make one, and the App ID
            err, certs = got
        else:
            s["password"] = hash_password(pw)
            if not ADMIN_PASSWORD:
                s["admin_password"] = hash_password(admin_pw)
            save_json(SETUP, s)
            apply_setup()
            session.pop("setup")
            session.permanent, session["ok"], session["pv"] = True, True, ["f", password_ver()]
            return redirect("/")
    return page("""<style>.setup label{display:flex;flex-direction:column;gap:4px;font-weight:700} .setup small{font-weight:400}
.setup summary{color:var(--acc);font-weight:700} .setup details[open]{display:flex;flex-direction:column;gap:10px}</style>
<p class=ftr>Welcome to SideDrop. Share your Apple developer account and help your friends sideload apps. Set the passwords and add your App Store Connect API key; SideDrop makes the certificate and App ID with it. Everything is kept on the server.</p>
<form class="c setup" method=post action=/setup enctype=multipart/form-data onsubmit="{{ confirm }}this.querySelector('button').textContent='Saving…'">
{% if err %}<p class=err>{{ err }}</p>{% endif %}""" + CERT_PICKER + """
{% if 'PASSWORD' not in env %}<label>Password for friends<input type=password name=password autocomplete=new-password minlength=8 required></label>{% endif %}
{% if 'ADMIN_PASSWORD' not in env %}<label>Admin password<input type=password name=admin_password autocomplete=new-password minlength=8 required>
<small>Unlocks Settings → Manage. Keep it different from the friends' one.</small></label>{% endif %}
<input type=file name=files id=keyf multiple class=vh onchange="keyl.textContent=this.files.length?[...this.files].map(f=>f.name).join(', '):'Choose API Key'">
<label class="b grey" for=keyf id=keyl>Choose API Key</label>
<small>AuthKey_….p8 from App Store Connect → Users and Access → Integrations, role Admin, loose or in a .zip with a text file holding the Issuer ID.{% if p8 %} The .p8 is saved.{% endif %}</small>
{% if 'ASC_KEY_ID' not in env %}<label>Key ID<input name=asc_key_id value="{{ s.asc_key_id or '' }}" autocapitalize=characters autocomplete=off><small>Read from AuthKey_&lt;Key ID&gt;.p8 if empty.</small></label>{% endif %}
{% if 'ASC_ISSUER_ID' not in env %}<label>Issuer ID<input name=asc_issuer_id value="{{ s.asc_issuer_id or '' }}" autocapitalize=none autocomplete=off></label>{% endif %}
{% if 'BUNDLE_ID' not in env %}<label>App ID (BUNDLE_ID)<input name=bundle_id value="{{ s.bundle_id or '' }}" placeholder="com.you.sideload" autocapitalize=none autocomplete=off>
<small>Made with Push if your account doesn't have it yet.</small></label>{% endif %}
<details{% if p12 %} open{% endif %}><summary>Manual setup</summary>
<small>Rather not give SideDrop a key that can make certificates? Make the certificate yourself and pick it here; the API key then only registers iPhones.</small>""" + MANUAL_STEPS + """
<input type=file name=files id=sigf multiple class=vh onchange="sigl.textContent=this.files.length?[...this.files].map(f=>f.name).join(', '):'Choose Signing Files'">
<label class="b grey" for=sigf id=sigl>Choose Signing Files</label>
<small>cert.p12 and a password.txt, loose or in a .zip.{% if p12 %} cert.p12 is saved.{% endif %}</small>
{% if 'P12_PASSWORD' not in env %}<label>P12 Password<input type=password name=p12_password autocomplete=off><small>Leave empty to try a password.txt, or none.</small></label>{% endif %}
</details>
<button>Save</button></form>""", title="Set Up SideDrop", err=err, s=s, env=ENV_SET, p12=P12.exists(), p8=ASC_KEY.exists(),
                certs=certs, confirm=REVOKE_CONFIRM)


# --- admin: list the developer account's iPhones, disable the ones that shouldn't have apps any more ---

admin_fails = []  # times of recent wrong admin passwords; a right one unlocks admin on that device for as long as its login lasts


def is_admin():
    return admin_enabled() and logged_in() and bool(session.get("admin")) and bool(session.get("csrf"))


MORE = ("Settings", "/#settings")  # back button for screens pushed from the Settings tab
ADMIN_CSS = """<style>.act{flex:none;width:auto;min-width:76px;padding:5px 10px;font-size:12px;border-radius:4px;letter-spacing:.02em}
.act.red{border-color:#8a1c1c;background:linear-gradient(#f58b8b,#d43a3a 50%,#c22424 51%,#d23333)} .off>div{opacity:.5} .row b{font-weight:700}</style>"""


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not admin_enabled():
        abort(404)
    if not logged_in():
        return redirect("/")
    err = None
    if request.method == "POST":
        admin_fails[:] = [t for t in admin_fails if time.time() - t < 900]
        if len(admin_fails) >= 5:  # ponytail: global lockout, not per IP; friends could lock the admin out for 15 min at worst
            err = "Too many wrong passwords. Try again in 15 minutes."
        elif password_ok(request.form.get("password", ""), admin=True):
            session["admin"], session["csrf"], session["pv"] = time.time(), secrets.token_urlsafe(32), ["a", password_ver(True)]
            return redirect("/admin")
        else:
            admin_fails.append(time.time())
            time.sleep(2)
            err = "Wrong admin password."
    if not is_admin():
        return page(ADMIN_CSS + """
<form class=c method=post><input type=password name=password placeholder="Admin password" aria-label="Admin password" autofocus required
 oninput="this.form.querySelector('button').disabled=!this.value"><script>addEventListener("pageshow",()=>{let i=document.querySelector("input[name=password]");i.oninput()})</script>
{% if err %}<p class=err>{{ err }}</p>{% endif %}<button disabled>Unlock</button></form>""", back=MORE, title="Manage", err=err)
    return manage_menu()


@app.post("/admin/device")
def admin_device():
    """Turn an iPhone on or off at Apple. The new profile and the re-signing run in the background, so the switch answers as soon
    as Apple does; json=1 (the iPhones page's switch) gets the list drawn again."""
    if not is_admin() or not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]):
        abort(403)
    did, status = request.form.get("id", ""), request.form.get("status")
    if not re.fullmatch(r"[A-Za-z0-9]{1,40}", did) or status not in ("ENABLED", "DISABLED"):
        abort(400)
    try:
        asc("PATCH", f"/devices/{did}", json={"data": {"type": "devices", "id": did, "attributes": {"status": status}}})
    except Exception as e:
        if request.form.get("json"):
            return {"ok": False, "error": str(e)[:200]}, 502
        raise
    update_cached_device(did, status=status)
    threading.Thread(target=resign_all, daemon=True).start()  # a profile without (or with) it, then every app signed with that
    if request.form.get("json"):
        return {"ok": True, "html": device_list_html(device_rows(cached_devices()[0]))}
    return redirect("/admin/iphones")


# --- Manage, beyond the iPhones: signing files, sources and iFizBox settings (overrides in DATA/config), files for friends ---

EDITABLE = {"mirror-sources.txt": "Sources", "third-party-sources.txt": "Third-party sources",
            IFIZBOX_SOURCES: "iFizBox's starting sources", IFIZBOX_SETTINGS: "iFizBox settings"}
DONE = {"signing": "Saved. Apps are being signed with the new files.", "sources": "Saved.", "default": "Back to the default.",
        "files": "Uploaded.", "deleted": "Deleted.", "renamed": "Renamed.", "passwords": "Saved.",
        "env": "The password from .env works again."}


def shared_files():
    return sorted((p for p in FILES.iterdir() if p.is_file() and not p.name.startswith(".")), key=lambda p: p.name.lower()) if FILES.exists() else []


def admin_check():
    if not is_admin() or not hmac.compare_digest(request.form.get("csrf", ""), session["csrf"]):
        abort(403)


# --- Manage (F10): a menu of grouped rows that asks Apple nothing, so it opens at once; each row pushes its own page. Apple's
# answers are kept in the data folder (devices.json) or in memory (cert_cache) and refreshed in the background ---

DEVICES, devices_lock = DATA / "devices.json", threading.Lock()  # {"at": time, "data": [...]}: Apple's last /devices answer
ADMIN_BACK = ("Manage", "/admin")  # back button for Manage's pages
SLOTS = 100  # iPhones Apple lets an account register per membership year
cert_bg = {}  # {"t": the thread refreshing cert_status in the background}


def _rowicon_gear():
    import math
    pts = []
    for i in range(32):  # 8 teeth of 4 points, as rowicons.js gear()
        a = i / 32 * math.pi * 2 - math.pi / 2 + math.pi / 32
        r = 10.5 if i % 4 < 2 else 7.9
        pts.append(f"{12 + r * math.cos(a):.2f} {12 + r * math.sin(a):.2f}")
    return "M" + "L".join(pts) + "zM12 8.4a3.6 3.6 0 1 0 0 7.2a3.6 3.6 0 0 0 0-7.2z"


# iOS 6 Settings' 29pt row icons as iFizBox draws them (its web/app/icons/rowicons.js, F205): a flat tile in one colour, 6pt corners,
# a white glyph on a 24-unit square drawn 19pt across. Copied from that file's ROW_ICONS/GLYPHS and tileSvg into this one; nothing
# is loaded from iFizBox. Parts: ("f", d) filled, ("e", d) filled even-odd, ("s", d, width) stroked.
ROW_ICONS = {
    "device": ("#8c9097", [("e", "M7.6 1.5h8.8a2.1 2.1 0 0 1 2.1 2.1v16.8a2.1 2.1 0 0 1-2.1 2.1H7.6a2.1 2.1 0 0 1-2.1-2.1V3.6a2.1 2.1 0 0 1 2.1-2.1z"
                                   "M7.7 4.3v13.6h8.6V4.3zM12 18.9a1.2 1.2 0 1 0 0 2.4a1.2 1.2 0 0 0 0-2.4z")]),
    "syncCert": ("#f08b1d", [("f", "M7.8 13.6 5.4 22l3.3-1.5 2.2 2.3 1.2-7.1zM16.2 13.6l2.4 8.4-3.3-1.5-2.2 2.3-1.2-7.1z"),
                             ("e", "M12 1.6a7 7 0 1 1 0 14a7 7 0 0 1 0-14zM12 4.6a4 4 0 1 0 0 8a4 4 0 0 0 0-8z")]),
    "signInKey": ("#e8ad1a", [("e", "M14.6 2.6a6.2 6.2 0 1 1-2.2 12l-1.6 1.6H8.4v2.4H6v2.4H2.6v-3.6l6.9-6.9a6.2 6.2 0 0 1 5.1-7.9z"
                                    "M16 6.2a1.8 1.8 0 1 0 0 3.6a1.8 1.8 0 0 0 0-3.6z")]),
    "fromFile": ("#22a6b5", [("e", "M5 2.5h9.2L19 7.3v14.2H5zM13.2 4.2v4.1h4.1z")]),
    "sources": ("#3f80e0", [("f", "M3.3 5.5a1.9 1.9 0 1 0 3.8 0a1.9 1.9 0 1 0-3.8 0zM9.3 4.2h11.6v2.6H9.3z"
                                  "M3.3 12a1.9 1.9 0 1 0 3.8 0a1.9 1.9 0 1 0-3.8 0zM9.3 10.7h11.6v2.6H9.3z"
                                  "M3.3 18.5a1.9 1.9 0 1 0 3.8 0a1.9 1.9 0 1 0-3.8 0zM9.3 17.2h11.6v2.6H9.3z")]),
    "general": ("#8c9097", [("e", _rowicon_gear())]),
}


def tile_svg(name):
    """rowicons.js tileSvg: the 29pt tile as SVG text."""
    colour, parts = ROW_ICONS[name]
    glyph = "".join(f'<path d="{p[1]}" fill="none" stroke="#fff" stroke-width="{p[2]}" stroke-linecap="round" stroke-linejoin="round"/>'
                    if p[0] == "s" else f'<path d="{p[1]}" fill="#fff"' + (' fill-rule="evenodd"' if p[0] == "e" else "") + "/>" for p in parts)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="29" height="29" viewBox="0 0 29 29"><rect width="29" height="29" rx="6" fill="{colour}"/>'
            f'<g transform="translate(5 5) scale({19 / 24})">{glyph}</g></svg>')


def row_icon(name):
    from markupsafe import Markup
    return Markup('<img class=rico src="data:image/svg+xml,%s" alt="" width=29 height=29>' % quote(tile_svg(name), safe=""))


# F20: the Settings tab's rows each get their tile, from iFizBox's icons/rowicons.js ROW_ICONS and GLYPHS (theme: PAGE_ICONS.theme, indigo
# "contrast"; notifications: red "bell"; help: blue "question"; device, calendar, checkCircle, lock, home and info as named there), and
# devMode, our own pick of its glyphs (dark "terminal"). Copied here; nothing is loaded from iFizBox.
_DISC = "M12 2.5a9.5 9.5 0 1 1 0 19a9.5 9.5 0 0 1 0-19z"
ROW_ICONS.update({
    "theme": ("#4650b4", [("e", _DISC + "M12 4.8a7.2 7.2 0 0 0 0 14.4z")]),
    "notifications": ("#e2382f", [("f", "M12 2.4c.9 0 1.6.7 1.6 1.6v.6c2.9.7 4.8 3.3 4.8 6.4v4.4l2.1 2.6v1.1H3.5V18l2.1-2.6V11c0-3.1 1.9-5.7 4.8-6.4V4"
                                         "c0-.9.7-1.6 1.6-1.6zM9.5 20h5a2.5 2.5 0 0 1-5 0z")]),
    "help": ("#3f80e0", [("s", "M8.4 8.8a3.6 3.6 0 1 1 5.2 3.3c-1.1.6-1.6 1.4-1.6 2.6v.8", 3), ("f", "M12 17.4a1.9 1.9 0 1 0 0 3.8a1.9 1.9 0 0 0 0-3.8z")]),
    "status": ("#40ae4c", [("s", "M4 12.6l5.2 5.2L20 6.6", 3.4)]),
    "slots": ("#22a6b5", [("s", "M12 3a9 9 0 1 1 0 18a9 9 0 0 1 0-18z", 2), ("s", "M7.2 12.4l3.3 3.3 6.3-6.6", 2.6)]),
    "calendar": ("#e2382f", [("e", "M3 4.6h18V21H3zM5.2 9.2v9.6h13.6V9.2z"), ("f", "M6.8 2.4h2.4v4.4H6.8zM14.8 2.4h2.4v4.4h-2.4zM7.2 11.2h3.4v3.2H7.2z")]),
    "lock": ("#55595f", [("e", "M6.8 10.4V8a5.2 5.2 0 0 1 10.4 0v2.4h1.6v11.2H5.2V10.4zM9.5 10.4h5V8a2.5 2.5 0 0 0-5 0z")]),
    "devMode": ("#55595f", [("s", "M4.5 7l5.5 5-5.5 5", 3), ("s", "M12 18h7.5", 3)]),
    "homeScreen": ("#3f80e0", [("f", "M12 2.6l10.2 9.2H19v9.4h-5.2v-6.4h-3.6v6.4H5v-9.4H1.8z")]),
})
app.jinja_env.globals["row_icon"] = row_icon

# Settings > Theme (iFizBox's Settings > Theme, screens/settings.js groupPage and modeControl, core/settings.js 'appearance'): Mode, an iOS 6
# segmented control (Automatic / Light / Dark), then Themes: Light and Dark, each pushing its checklist (listPage) with the theme showing
# sampled under it (themePreview). The choices stay in this browser (localStorage mode / lightTheme / darkTheme, read by THEME_BOOT), so
# the server draws the defaults and themeMarks() puts the checks where the stored choice is, at once.
MODES = [("auto", "Automatic"), ("light", "Light"), ("dark", "Dark")]  # iFizBox's order
THEME_FOOTERS = {"mode": "Automatic switches between your Light and Dark themes with the iPhone's own setting.",
                 "light": "The theme in Light mode, and in Automatic while the iPhone is light.",
                 "dark": "The theme in Dark mode, and in Automatic while the iPhone is dark."}
THEME_JS = """<script>/* F20 Settings > Theme. Pushed pages run their scripts again on every push: functions and var only */
var THEME_LABELS=%s;
function themeShown(){let s=themeState();return s.mode=="dark"||s.mode=="auto"&&matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"}
/* the checks, the selected segment and the Light / Dark rows' details follow themeState() (THEME_BOOT) on every page open */
function themeMarks(){let s=themeState(),v={mode:s.mode,lightTheme:s.light,darkTheme:s.dark};
 document.querySelectorAll("[data-tk]").forEach(g=>{if(g.dataset.tk in v)g.querySelectorAll("[data-v]").forEach(r=>r.setAttribute("aria-checked",r.dataset.v==v[g.dataset.tk]))});
 document.querySelectorAll("[data-tv]").forEach(e=>e.textContent=THEME_LABELS[v[e.dataset.tv]])}
/* a pick stores it and repaints. A theme of the tone not showing also switches Mode to that tone (iFizBox's pick()), so it shows once back */
function themeSet(k,val){let tone=k=="lightTheme"?"light":k=="darkTheme"?"dark":null;
 try{if(tone&&themeShown()!=tone)localStorage.mode=tone;localStorage[k]=val;if(tone||k=="mode")localStorage.removeItem("dark")}catch(e){}
 theme();themeMarks()}
/* Light / Dark's live preview: the page shows that tone while its list is open, and Mode's again once it's popped (iFizBox's F199) */
function themePreview(tone){themeTone=tone;theme();let l=typeof L!="undefined"&&L&&L.contains(document.currentScript)?L:null;if(!l)return;
 addEventListener("popstate",function f(){if(LS.includes(l))return;removeEventListener("popstate",f);themeTone=null;theme();themeMarks()})}
%s
themeMarks()</script>""" % (json.dumps({n: p[1] for n, p in PALETTES.items()} | dict(MODES)), "%s")


def theme_segmented(key, options, current, small=False, label="Mode"):
    """The segmented control as role=radiogroup (iFizBox's modeControl): one button a value, the current one aria-checked."""
    btns = "".join(f'<button type=button role=radio data-v={v} aria-checked={"true" if v == current else "false"} '
                   f'onclick="themeSet(\'{key}\',this.dataset.v)">{label}</button>' for v, label in options)
    return f'<div class="seg{" sm" if small else ""}" role=radiogroup aria-label="{label}" data-tk={key}>{btns}</div>'


def theme_preview():
    """iFizBox's themePreview, with SideDrop's own controls: a nav bar with Back and a bar button, a segmented control, the App Store
    buttons and the badge, a group of rows (an icon and a value, a switch, a check, a subtitle) and its footer. Inert."""
    return ('<h3 class=hdr>Preview</h3><div class=tpv aria-hidden=true inert><header class=nav><span class="bar back">Back</span><h1>Preview</h1>'
            '<span class="bar r">Edit</span></header>' + theme_segmented("sample", [("a", "Details"), ("b", "Reviews"), ("c", "Related")], "a", small=True, label="Sample")
            + '<div class=tpb><span class=get>GET</span><span class="get go">INSTALL</span><span class="get blue">UPDATE</span><span class=badge>3</span></div>'
            '<h3 class=hdr>Sample</h3><div class=g>'
            f'<div class="row mrow">{row_icon("sources")}<div>Sources</div><span class=val>12</span></div>'
            f'<div class="row irow">{row_icon("notifications")}<div>Switch</div><label class=sw><input type=checkbox checked tabindex=-1><i></i><span class=k></span></label></div>'
            '<div class="row ck" aria-checked=true><div>Checked</div></div>'
            '<div class=row><div>Package<small>A row with a subtitle</small></div><span class=val>1.0</span></div></div>'
            '<p class=ftr>A group footer reads like this.</p></div>')


def theme_page(tone=None):
    if tone is None:  # Settings > Theme
        themes = "".join(f'<a class="row mrow" href=/theme/{t} data-push><div>{t.title()}</div><span class=val data-tv={t}Theme>{PALETTES[THEMES[t][0]][1]}</span></a>'
                         for t in ("light", "dark"))
        body = (f"<h3 class=hdr>Mode</h3>{theme_segmented('mode', MODES, 'auto')}<p class=ftr>{THEME_FOOTERS['mode']}</p>"
                f"<h3 class=hdr>Themes</h3><div class=g>{themes}</div>" + THEME_JS % "")
        return page(body, back=MORE, title="Theme")
    key = f"{tone}Theme"
    rows = "".join(f'<a class="row ck" role=radio data-v={n} aria-checked={"true" if n == THEMES[tone][0] else "false"} onclick="themeSet(\'{key}\',this.dataset.v)">'
                   f'<span class=sws style="background:linear-gradient({SWATCH[n][0]} 0 45%,{SWATCH[n][1]} 45%)"></span><div>{PALETTES[n][1]}</div></a>'
                   for n in THEMES[tone])
    body = (f'<div class="g thm" role=radiogroup aria-label="{tone.title()} Theme" data-tk={key}>{rows}</div><p class=ftr>{THEME_FOOTERS[tone]}</p>'
            + theme_preview() + THEME_JS % f'themePreview("{tone}");')
    return page(body, back=("Theme", "/theme"), title=tone.title())


@app.get("/theme")
@app.get("/display")  # Settings > Display, its name before F20
def theme_root():
    return theme_page() if logged_in() else redirect("/")


@app.get("/theme/<tone>")
def theme_list(tone):
    if tone not in THEMES:
        abort(404)
    return theme_page(tone) if logged_in() else redirect("/")


# ---- F26: Settings as the user's concept (2026-11-19). The Help page and Add to Home Screen, pushed from Settings (back: Settings), and
# the steps they share with the Apps tab's setup and the first-install sheet (Jinja globals, so every template can draw them) ----
from markupsafe import Markup as _Markup

SDP_STEPS = _Markup("""<figure class=shot><figcaption><span class=num>a</span><span>Settings → <b>Face ID &amp; Passcode</b></span></figcaption>
<img src=/static/sdp1.jpg alt="Settings with Face ID and Passcode circled" width=640 height=277></figure>
<figure class=shot><figcaption><span class=num>b</span><span>Tap <b>Stolen Device Protection</b></span></figcaption>
<img src=/static/sdp2.jpg alt="The Stolen Device Protection row circled" width=640 height=167></figure>
<figure class=shot><figcaption><span class=num>c</span><span>Turn it <b>off</b></span></figcaption>
<img src=/static/sdp3.jpg alt="The Stolen Device Protection switch turned off, circled" width=640 height=291></figure>
<div class=warn><span aria-hidden=true>⏳</span><div>Asked to wait an hour? Do this at home, where there's no wait.</div></div>
""")
DEV_STEPS = _Markup("""<figure class=shot><figcaption><span class=num>a</span><span>Settings → <b>Privacy &amp; Security</b></span></figcaption>
<img src=/static/dev1.jpg alt="Settings with Privacy and Security circled" width=640 height=243></figure>
<figure class=shot><figcaption><span class=num>b</span><span>Scroll down, tap <b>Developer Mode</b></span></figcaption>
<img src=/static/dev2.jpg alt="The Developer Mode row circled" width=640 height=215></figure>
<figure class=shot><figcaption><span class=num>c</span><span>Turn it <b>on</b>, tap <b>Restart</b>, then <b>Turn On</b> after the restart</span></figcaption>
<img src=/static/dev3.jpg alt="The Developer Mode switch turned on, circled" width=640 height=305></figure>
<div class=warn><span aria-hidden=true>💡</span><div>Don't see it? Install an app first, then look again.</div></div>""")
A2HS_STEPS = _Markup("""<p class=a2l><span>1. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M8 9H6.5A1.5 1.5 0 0 0 5 10.5v9A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 17.5 9H16M12 3v12M8 7l4-4 4 4"/></svg><b>Share</b></span></span><span>2. Tap <span class=nw><svg class=ic viewBox="0 0 24 24" aria-hidden=true fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><rect x=4 y=4 width=16 height=16 rx=4 /><path d="M12 8v8M8 12h8"/></svg><b>Add to Home Screen</b></span></span><span>3. Open SideDrop from there</span></p>""")
app.jinja_env.globals.update(sdp_steps=SDP_STEPS, dev_steps=DEV_STEPS, a2hs_steps=A2HS_STEPS)
# F23: why Developer Mode, said the same in the first-install sheet, the Developer Mode Required alert and Help. The user's iPhone 18 Pro
# (iOS 27) asked for it opening Ad Hoc apps from here (get-task-allow false), though Apple documents it only for development-signed
# apps; so it's shown for every profile kind, with no iOS-version check (Safari's user agent freezes the iOS version)
DEV_WHY = "iOS 27 asks for Developer Mode once for apps installed outside the App Store. Turn it on, restart, then the app opens."
app.jinja_env.globals["dev_why"] = DEV_WHY

# row icons for Settings > Manage, Help and Manage > Signing (in the rowicons.js style: one colour, a white glyph on a 24-unit square)
ROW_ICONS.update({
    "manage": ("#f08b1d", [("f", "M12 4a4 4 0 1 0 0 8a4 4 0 0 0 0-8zM4 21c0-4.4 3.6-7 8-7s8 2.6 8 7z")]),  # the old Manage tile's person
    "alert": ("#e2382f", [("e", "M12 2.6l10.2 18.2H1.8zM10.8 8.6v6.2h2.4V8.6zM12 16.2a1.3 1.3 0 1 0 0 2.6a1.3 1.3 0 0 0 0-2.6z")]),
    "profile": ("#7a5cc4", [("e", "M5 2.5h14v19H5zM8 6.2v2.2h8V6.2zM8 10.6v2.2h8v-2.2zM8 15v2.2h5V15z")]),
})

# the step screenshots' look, for these pages opened on their own (pushed, they sit in the main page, which has the same rules)
HELP_CSS = """<style>.num{flex:none;width:24px;height:24px;border-radius:50%;display:grid;place-items:center;font-size:13px;font-weight:700;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);
 background:var(--gloss),linear-gradient(#7f8a99,#5b6573);border:1px solid #4a525d}
.shot{display:flex;flex-direction:column;gap:6px} .shot figcaption{display:flex;gap:8px;align-items:center;font-size:15px} .shot .num{width:20px;height:20px;font-size:11px}
.shot img{display:block;width:100%;height:auto;border-radius:8px;border:1px solid var(--line);box-shadow:0 1px 3px rgba(0,0,0,.3)}
.warn{display:flex;gap:10px;align-items:flex-start;padding:10px;border-radius:8px;background:#fff8e1;border:1px solid #e6cf7a;font-size:14px} .dark .warn{background:var(--warnbg);border-color:var(--warnedge)}
.hlp details>.shot+.shot{margin-top:18px} .hlp details>ol{padding-left:1.5rem} .hlp details>p{line-height:1.4}</style>"""
HELP = """<h3 class=hdr>Problems</h3><div class="g hlp">
<details id=register><summary>{{ icon('device') }}<span>Register iPhone Didn't Work</span></summary>
<ol><li>Tap <b>Register iPhone</b> again, then <b>Allow</b>.</li>
<li>Open the <b>Settings</b> app, tap <b>Profile Downloaded</b> just under your name, then <b>Install</b> in the top-right corner. No such row? It's under <b>General</b> › <b>VPN &amp; Device Management</b>; after 8 minutes iOS deletes it, so register again.</li>
<li>Stuck on a wait timer? That's <b>Stolen Device Protection</b>: turn it off as below, or do it at home, where there's no wait.</li></ol>
{{ sdp_steps }}</details>
<details id=install><summary>{{ icon('alert') }}<span>An App Won't Install</span></summary>
<ol><li>An app stuck half-installed (a grey icon): delete it from the Home Screen, then tap GET again.</li>
<li>Installed but it won't open? Turn on Developer Mode, below.</li></ol></details>
<details id=dev><summary>{{ icon('devMode') }}<span>Turn on Developer Mode</span></summary><p>{{ dev_why }}</p>{{ dev_steps }}</details></div>
<p class=ftr>Apps here are signed with a friend's developer certificate for each registered iPhone. iOS asks for Developer Mode once, then they open like any other app.</p>
<h3 class=hdr>Getting Started</h3><div class="g hlp">
<details id=a2hs><summary>{{ icon('homeScreen') }}<span>Add to Home Screen</span></summary>{{ a2hs_steps }}</details>
<details id=notify><summary>{{ icon('notifications') }}<span>Notifications in Apps</span></summary>
<p>Apps from here keep their notifications: allow them when an app asks, as you would for one from the App Store.</p>
<p>SideDrop's own Update Alerts (in Settings) tell you when an app you installed has a new version. iOS offers them only to SideDrop on your Home Screen.</p></details>
<details id=more><summary>{{ icon('sources') }}<span>More Apps with iFizBox</span></summary>
<p>SideDrop serves the apps listed on its Apps tab; for your own IPAs and other sources, use <a href=/#ifizbox onclick="if(window.go){go('ifizbox');return false}">iFizBox</a>.
It signs apps right on your iPhone, with this site's certificate already inside it.</p></details></div>
<script>/* opened on its own as /help#dev (no JS push): that item starts open */
(function(){if(location.pathname!="/help")return;let d=document.getElementById(location.hash.slice(1));if(d&&d.tagName=="DETAILS")d.open=true})()</script>"""
HOME_SCREEN = """<div class=c>{{ a2hs_steps }}</div>
<p class=ftr>SideDrop gets its own icon and opens full screen, like an app. On the Home Screen it can also send Update Alerts.</p>"""


@app.get("/help")
def help_page():
    return page(HELP_CSS + HELP, back=MORE, title="Help", icon=row_icon) if logged_in() else redirect("/")


@app.get("/home-screen")
def home_screen_page():
    return page(HELP_CSS + HOME_SCREEN, back=MORE, title="Add to Home Screen") if logged_in() else redirect("/")


def manage_iphone_count():
    """iPhones registered, as Manage counts them without asking Apple: the saved list's, else the profile's."""
    listed, _ = cached_devices()
    try:
        return len(listed) if listed is not None else len(profile_udids())
    except Exception:
        return 0


PROFILE_BASE_ENTS = {"application-identifier", "com.apple.developer.team-identifier", "keychain-access-groups", "get-task-allow", "beta-reports-active"}


def profile_info():
    """Manage > Signing's Profile row, read from the ad hoc profile: {n iPhones, push, caps (capabilities beyond the base entitlements),
    app_id (without the team)} or None."""
    if not PROFILE.exists():
        return None
    try:
        p = embedded_plist(PROFILE.read_bytes())
    except Exception:
        return None
    ents = p.get("Entitlements", {})
    return dict(n=len(p.get("ProvisionedDevices", [])), push="aps-environment" in ents, caps=len([k for k in ents if k not in PROFILE_BASE_ENTS]),
                app_id=str(ents.get("application-identifier", "")).partition(".")[2])


def ifizbox_served():
    """The iFizBox version SideDrop serves (Manage > Apps), or None."""
    p = SIGNED / f"{IFIZBOX_ID}.ipa"
    try:
        return ipa_info(p)["short"] if p.exists() else None
    except Exception:
        return None


def fmt_day(t):
    return f"{t:%b} {t.day}, {t.year}" if t else ""


def ago(t):
    days = int((time.time() - t) // 86400)
    return "today" if days < 1 else "yesterday" if days < 2 else f"{days} days ago" if days < 60 else time.strftime("%b %-d, %Y", time.localtime(t))


def cached_devices():
    """Apple's last device list and when it came, or (None, None) before the first fetch."""
    d = load_json(DEVICES)
    return d.get("data"), d.get("at")


def fetch_devices():
    listed = asc("GET", "/devices", params={"filter[platform]": "IOS", "limit": 200})["data"]
    with devices_lock:
        save_json(DEVICES, {"at": time.time(), "data": listed})
    return listed


def update_cached_device(did, **attrs):
    """After a PATCH Apple accepted: the saved list says so too, without asking Apple for the whole list again."""
    with devices_lock:
        d = load_json(DEVICES)
        for x in d.get("data") or []:
            if x.get("id") == did:
                x.setdefault("attributes", {}).update(attrs)
        if d:
            save_json(DEVICES, d)


def device_rows(listed):
    seen, me = load_json(SEEN), token_udid(request.cookies.get("device", ""))
    out = []
    for d in listed or []:
        a = d.get("attributes") or {}
        added = datetime.datetime.strptime(a["addedDate"][:10], "%Y-%m-%d") if a.get("addedDate") else None
        out.append(dict(id=d["id"], name=a.get("name", ""), model=a.get("model") or a.get("deviceClass", ""), udid=a.get("udid", ""),
                        on=a.get("status") == "ENABLED", added=added, me=bool(me) and a.get("udid") == me,
                        last=ago(seen[a["udid"]]).capitalize() if a.get("udid") in seen else "Not seen yet"))
    out.sort(key=lambda d: -(d["added"].timestamp() if d["added"] else 0))  # one list: a turned-off iPhone keeps its place
    return out


def cert_status_cached():
    """cert_status without waiting on Apple: its last answer (any age) or, before the first, the local checks; a stale or missing
    answer is refreshed in the background, for the next page."""
    if not P12.exists():
        return []
    key = (P12.stat().st_mtime, P12_PASSWORD, BUNDLE_ID)
    fresh = cert_cache.get("key") == key and time.time() - cert_cache.get("at", 0) <= 3600
    if not fresh and not (cert_bg.get("t") and cert_bg["t"].is_alive()):
        cert_bg["t"] = threading.Thread(target=cert_status, daemon=True)
        cert_bg["t"].start()
    out = cert_cache["problems"] if cert_cache.get("key") == key else cert_problems(P12.read_bytes(), P12_PASSWORD)
    return sorted(out, key=lambda p: p[0] != "error")


def cert_info():
    """What Signing shows about cert.p12, read from the file: {kind, holder, team, expires} or None."""
    try:
        _, cert, _ = pkcs12.load_key_and_certificates(P12.read_bytes(), P12_PASSWORD.encode() or None)
    except Exception:
        return None
    if cert is None:
        return None
    name = lambda oid: ", ".join(a.value for a in cert.subject.get_attributes_for_oid(oid))
    cn, ou = name(x509.oid.NameOID.COMMON_NAME), name(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME)
    m = re.fullmatch(r"(.+?): (.*?)(?: \(([A-Z0-9]{10})\))?", cn)  # "Apple Distribution: Sam Test (TEAM123456)"
    team = ou or (m and m.group(3)) or ""
    holder = m.group(2) if m else ""
    return dict(kind=m.group(1) if m else cn or "Unknown", team=f"{holder} ({team})" if holder and team else holder or team,
                expires=cert.not_valid_after_utc)


def admin_gate():
    """Manage's pages: a redirect for anyone not unlocked as admin, else None."""
    if not admin_enabled():
        abort(404)
    if not logged_in():
        return redirect("/")
    if not is_admin():
        return redirect("/admin")
    return None


MANAGE_CSS = """<style>.mg label{display:flex;flex-direction:column;gap:4px;font-weight:700} .mg small{font-weight:400} .mg textarea{min-height:96px}
.done{color:#2f7d32;font-weight:700} .gap{margin-top:20px} .g a.row{color:inherit}
/* iFizBox's row icons (F205): the tile 7pt in from the row's edge, the label 11pt after it */
.rico{flex:none;display:block;width:29px;height:29px} .row:has(>.rico){padding-left:7px;gap:11px}
.mrow:after{content:"";flex:none;width:9px;height:13px;margin-right:.5px;background:var(--chev) center/contain no-repeat}
.mrow.is-pressed:after,.mrow.sel:after{filter:brightness(0) invert(1)}
.g a.row.sel,.dark .g a.row.sel{background:var(--select);color:#fff;text-shadow:none} .g a.row.sel *{color:#fff}
/* a row's value on the right, UITableViewCellStyleValue1's blue-grey */
.val{flex:none;max-width:60%;overflow:hidden;white-space:nowrap;text-overflow:ellipsis;color:var(--acc)} .dark .val{color:var(--sub)}
.kvr>div{flex:none!important} .kvr .val{flex:1;max-width:none;text-align:right;white-space:normal;overflow-wrap:anywhere}
.cw{display:flex;gap:10px;align-items:center;margin:0 0 6px;padding:10px 12px;border-radius:9.5px;background:#fff8e1;border:1px solid #e6cf7a;color:#7a4b00;font-size:15px;font-weight:700}
.cw.bad{background:#fdecec;border-color:#e3a1a1;color:#b00012} .cw>div{flex:1;min-width:0} .cw p{margin:0} .cw p+p{margin-top:6px}
a.cw:after{content:"";flex:none;width:9px;height:13px;background:var(--chev) center/contain no-repeat} .cw small{display:block;margin-top:4px;font-size:13px;font-weight:400;color:inherit}
.dark .cw{background:var(--warnbg);border-color:var(--warnedge);color:var(--warntext)} .dark .cw.bad{background:var(--badbg);border-color:var(--badedge);color:var(--badtext)}
.drow .dl{flex:1;min-width:0;display:block;color:inherit} .drow b{display:block;font-weight:700;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.drow.off .dl{opacity:.45}
.load{color:var(--sub);font-size:15px} .load .spin{width:20px;height:20px} [data-devs].busy{opacity:.6;pointer-events:none}
.udid{font:13px/1.4 ui-monospace,Menlo,monospace;-webkit-user-select:all;user-select:all}
.g details>summary{color:var(--acc)} .g details>form{display:flex;flex-direction:column;gap:10px}
/* the switch (as the Settings tab's; repeated here for Manage's pages opened on their own) */
.sw{position:relative;flex:none;width:77px;height:27px;--x:0px} .sw:has(input:checked){--x:50px}
.sw input{position:absolute;inset:0;width:100%;height:100%;margin:0;padding:0;opacity:0;cursor:pointer;z-index:2}
.sw i{position:absolute;inset:0;border:1px solid #a7a7a7;border-radius:13.5px;overflow:hidden;background:linear-gradient(#e6e6e6,#fefefe);box-shadow:inset 0 2px 3px rgba(0,0,0,.3);font-size:16px;font-weight:700;line-height:25px;font-style:normal}
.sw i:before{content:"ON";position:absolute;inset:0 auto 0 0;width:77px;padding-left:25.5px;box-sizing:border-box;color:#fff;text-shadow:0 -1px 0 rgba(0,0,0,.35);
 background:linear-gradient(#1b68d8,#3f8cf3 55%,#5da1f6);transform:translateX(calc(var(--x) - 63.5px));transition:transform .2s}
.sw i:after{content:"OFF";position:absolute;right:12px;color:#808080;transform:translateX(var(--x));transition:transform .2s}
.sw .k{position:absolute;top:1px;left:1px;width:25px;height:25px;border-radius:50%;background:linear-gradient(#cfcfcf,#fcfcfc);border:1px solid rgba(0,0,0,.42);box-sizing:border-box;
 box-shadow:0 1px 2px rgba(0,0,0,.3);transform:translateX(var(--x));transition:transform .2s;pointer-events:none}</style>
{% if done %}<p class="c done">{{ done }}</p>{% endif %}{% if err and not certs %}<p class="c err">{{ err }}</p>{% endif %}"""


def admin_page(body, title, back=ADMIN_BACK, **ctx):
    ctx.setdefault("err", None)
    ctx.setdefault("certs", [])
    return page(MANAGE_CSS + body, back=back, title=title, csrf=session["csrf"], done=DONE.get(request.args.get("done", "")),
                icon=row_icon, fmt_day=fmt_day, **ctx)


# F26 (the user's concept): a status banner (green when signing works, else the first problem), then Friends, Signing and Apps, each with
# its footer. Every row pushes the same page as before (routes unchanged); Certificate and Profile both open Signing.
MANAGE_MENU = """<style>.cw.ok{background:#e9f8e4;border-color:#9fd18f;color:#2f6b1f} .dark .cw.ok{background:var(--greenbg);border-color:var(--greenline);color:var(--text)}
.mg2 .mrow>div small{font-weight:400;font-size:13px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis} .mg2 .mrow .val{max-width:45%}</style>
{% if cert %}<a class="cw{{ ' bad' if cert[0][0] == 'error' }}" href=/admin/signing data-push><div><p>{{ cert[0][1] }}</p>
{% if cert|length > 1 %}<small>And {{ cert|length - 1 }} more on Signing.</small>{% endif %}</div></a>
{% elif info %}<a class="cw ok" href=/admin/signing data-push><div><p>Signing works: {{ info.kind }}, App ID {{ app_id }}{{ ' with Push' if prof and prof.push }}</p></div></a>{% endif %}
<h3 class=hdr>Friends</h3><div class="g mg2" id=mFriends>
<a class="row mrow" href=/admin/iphones data-push>{{ icon('device') }}<div>iPhones</div><span class=val>{{ n_dev }} of {{ slots }}</span></a>
<a class="row mrow" href=/admin/invites data-push>{{ icon('share') }}<div>Invite Friends</div></a>
<a class="row mrow" href=/admin/passwords data-push>{{ icon('signInKey') }}<div>Passwords</div></a></div>
<p class=ftr>Who can sign in, and the links that let a friend register one iPhone.</p>
<h3 class=hdr>Signing</h3><div class="g mg2" id=mSigning>
<a class="row mrow" href=/admin/signing data-push>{{ icon('syncCert') }}<div>Certificate{% if info %}<small>{{ info.kind }}{% if info.team %}: {{ info.team }}{% endif %}</small>{% endif %}</div><span class=val>{{ expiry }}</span></a>
<a class="row mrow" href=/admin/signing data-push>{{ icon('profile') }}<div>Profile<small>{% if prof %}Ad Hoc{{ ' · Push' if prof.push }} · {{ prof.caps }} capabilit{{ 'y' if prof.caps == 1 else 'ies' }}{% else %}Not made yet{% endif %}</small></div>{% if prof %}<span class=val>{{ prof.n }} iPhone{{ '' if prof.n == 1 else 's' }}</span>{% endif %}</a></div>
<p class=ftr>Made again by itself when an iPhone registers. Apps keep their own bundle IDs and notifications.</p>
<h3 class=hdr>Apps</h3><div class="g mg2" id=mApps>
<a class="row mrow" href=/admin/sources data-push>{{ icon('sources') }}<div>App Sources</div><span class=val>{{ n_sources }}</span></a>
<a class="row mrow" href=/admin/files data-push>{{ icon('fromFile') }}<div>Files for Friends</div><span class=val>{{ n_files }}</span></a>
<a class="row mrow" href=/admin/ifizbox data-push>{{ icon('general') }}<div>iFizBox</div><span class=val>{{ ifz_v or 'Not yet' }}</span></a></div>
<p class=ftr>The apps on the Apps tab come from these sources, signed for every registered iPhone.</p>"""


def manage_menu():
    """Manage's first page. Nothing here waits on Apple: the iPhone count is the saved list's (or the profile's), the
    certificate's date is read from cert.p12, and the banner is cert_status's last answer."""
    n_dev = manage_iphone_count()
    info = cert_info()
    expiry = ("Expired" if info["expires"] < datetime.datetime.now(datetime.timezone.utc) else fmt_day(info["expires"])) if info else "Not set up"
    prof = profile_info()
    return page(MANAGE_CSS + MANAGE_MENU, back=MORE, title="Manage", cert=cert_status_cached(), n_dev=n_dev, expiry=expiry,
                info=info, prof=prof, app_id=BUNDLE_ID or (prof and prof["app_id"]) or "not set", slots=SLOTS, ifz_v=ifizbox_served(),
                n_files=len(shared_files()), n_sources=len(read_sources("mirror-sources.txt")) + len(read_sources("third-party-sources.txt")),
                icon=row_icon, done=DONE.get(request.args.get("done", "")), err=None, certs=[])


SPINNER = """<svg class=spin viewBox="0 0 24 24" aria-hidden=true><g stroke="#7f7f7f" stroke-width="2.2" stroke-linecap="round">{% for i in range(12) %}
<line x1=12 y1=2.5 x2=12 y2=7 transform="rotate({{ i * 30 }} 12 12)" opacity="{{ '%.2f' % (1 - i * 0.07) }}" />{% endfor %}</g></svg>"""
DEVICE_LIST = """{% macro dev(d) %}<div class="row drow{{ '' if d.on else ' off' }}"><a class=dl href="/admin/iphone/{{ d.id }}" data-push><b>{{ d.name }}</b><small>{{ d.model }}{% if d.me %} · this iPhone{% endif %}</small></a>
<label class=sw><input type=checkbox{{ ' checked' if d.on }} data-id="{{ d.id }}" data-name="{{ d.name }}" aria-label="{{ d.name }}" onchange="devSw(this)"><i></i><span class=k></span></label></div>{% endmacro %}
{% if devices %}<div class=g>{% for d in devices %}{{ dev(d) }}{% endfor %}</div>{% endif %}
{% if failed %}<p class="c err">Apple's developer service didn't answer, so this is the list saved {{ saved }}. Try again in a few minutes.<small>{{ failed }}</small></p>{% endif %}
{% if devices %}<p class=ftr>{{ devices|length }} of {{ slots }} slots used. Disabled iPhones still count until your membership renews.</p>
{% elif not loading %}<p class=ftr>No iPhones registered yet.</p>{% endif %}"""


def device_list_html(rows, loading=False, failed=None):
    at = cached_devices()[1]
    return render_template_string(DEVICE_LIST, devices=rows, loading=loading, failed=failed, slots=SLOTS,
                                  saved=ago(at) if at else "never")


IPHONES = """<div data-devs data-csrf="{{ csrf }}">{{ list|safe }}</div>
<script>(function(){let box=document.currentScript.previousElementSibling;
/* each switch turns an iPhone on or off at Apple (POST /admin/device); the answer is the list drawn again */
window.devSw=function(i){let b=i.closest("[data-devs]"),on=i.checked;
 if(!on&&!confirm("Turn off "+i.dataset.name+"? Its apps stop opening.")){i.checked=true;return}
 let row=i.closest(".drow");row.classList.toggle("off",!on);
 let f=new FormData();f.append("csrf",b.dataset.csrf);f.append("id",i.dataset.id);f.append("status",on?"ENABLED":"DISABLED");f.append("json","1");b.classList.add("busy");
 fetch("/admin/device",{method:"POST",body:f,credentials:"same-origin"}).then(r=>r.json()).then(d=>{if(d.html==null)throw d.error;b.innerHTML=d.html})
  .catch(e=>{i.checked=!on;row.classList.toggle("off",on);alert("Apple didn't answer. Try again in a few minutes."+(e?"\\n\\n"+e:""))}).finally(()=>b.classList.remove("busy"))};
/* the saved list shows at once; Apple's answer replaces it when it comes. "Loading from Apple…" shows in the bottom reload bar, which
   slides over the page, so nothing in the list moves while it loads */
let h=document.documentElement,t=document.getElementById("rbarT"),was=t&&t.textContent;
if(t){t.textContent="Loading from Apple…";h.classList.add("reloading")}
fetch("/admin/devices.json",{credentials:"same-origin",cache:"no-store"}).then(r=>r.json()).then(d=>{if(d.html==null)throw 0;box.innerHTML=d.html})
 .catch(()=>{if(t)t.textContent="Couldn't reach SideDrop. Showing the saved list.";return new Promise(r=>setTimeout(r,2500))})
 .finally(()=>{if(t){h.classList.remove("reloading");setTimeout(()=>{t.textContent=was},300)}})})()</script>"""


@app.get("/admin/iphones")
def admin_iphones():
    if r := admin_gate():
        return r
    listed, _ = cached_devices()
    return admin_page(IPHONES, "iPhones", list=device_list_html(device_rows(listed), loading=True))


@app.get("/admin/devices.json")
def admin_devices_json():
    """Apple's device list, fetched now and saved for the next page: the iPhones page's background refresh."""
    if not is_admin():
        abort(403)
    try:
        listed, failed = fetch_devices(), None
    except Exception as e:
        listed, failed = cached_devices()[0] or [], str(e)[:200]
    rows = device_rows(listed)
    return {"ok": not failed, "error": failed, "html": device_list_html(rows, failed=failed),
            "devices": [dict(d, added=d["added"].strftime("%Y-%m-%d") if d["added"] else None) for d in rows]}


IPHONE = """<div class=g><div class="row kvr"><div>Model</div><span class=val>{{ d.model or 'Unknown' }}</span></div>
<div class="row kvr"><div>Added</div><span class=val>{{ d.added.strftime('%b %-d, %Y') if d.added else 'Unknown' }}</span></div>
<div class="row kvr"><div>Last Used</div><span class=val>{{ d.last }}{% if d.me %} · this iPhone{% endif %}</span></div>
<div class="row kvr"><div>Status</div><span class=val>{{ 'On' if d.on else 'Off' }}</span></div>
<div class=row><div>UDID<small class=udid>{{ d.udid }}</small></div></div></div>
<h3 class=hdr>Rename</h3>
<form class="c mg" method=post action="/admin/iphone/{{ d.id }}" onsubmit="this.querySelector('button').textContent='Renaming…'">
<input type=hidden name=csrf value="{{ csrf }}"><input name=name value="{{ d.name }}" maxlength=50 aria-label=Name autocomplete=off required>
<button>Rename</button><small>The name in your developer account, at developer.apple.com → Devices.</small></form>"""


@app.route("/admin/iphone/<did>", methods=["GET", "POST"])
def admin_iphone(did):
    """One iPhone's details from the saved list, and Rename (PATCH /v1/devices name)."""
    if r := admin_gate():
        return r
    if not re.fullmatch(r"[A-Za-z0-9]{1,40}", did):
        abort(404)
    err = None
    if request.method == "POST":
        admin_check()
        name = " ".join(request.form.get("name", "").split())
        if not 1 <= len(name) <= 50:
            err = "A name is 1 to 50 characters."
        else:
            try:
                asc("PATCH", f"/devices/{did}", json={"data": {"type": "devices", "id": did, "attributes": {"name": name}}})
                update_cached_device(did, name=name)
                return redirect(f"/admin/iphone/{did}?done=renamed")
            except Exception as e:
                err = f"Apple didn't rename it: {str(e)[:200]}"
    d = next((x for x in device_rows(cached_devices()[0]) if x["id"] == did), None)
    if not d:
        return admin_page('<p class="c m">This iPhone isn\'t in the saved list. Go back to iPhones to load it from Apple.</p>', "iPhone",
                          back=("iPhones", "/admin/iphones"), err=err)
    return admin_page(IPHONE, d["name"] or "iPhone", back=("iPhones", "/admin/iphones"), d=d, err=err)


SIGNING = """{% for lvl, t in cert %}<div class="cw{{ ' bad' if lvl == 'error' }}"><p>{{ t }}</p></div>{% endfor %}
<h3 class=hdr>Certificate</h3>
{% if info %}<div class=g><div class="row kvr"><div>Type</div><span class=val>{{ info.kind }}</span></div>
<div class="row kvr"><div>Expires</div><span class=val>{{ fmt_day(info.expires) }}</span></div>
{% if info.team %}<div class="row kvr"><div>Team</div><span class=val>{{ info.team }}</span></div>{% endif %}
<div class="row kvr"><div>App ID</div><span class=val>{{ bundle or 'Not set' }}</span></div></div>
{% else %}<p class="c m">No certificate yet. Make one with the API key, or upload a cert.p12 under Manual.</p>{% endif %}
<form class="c mg" method=post action=/admin/signing onsubmit="{{ confirm }}this.querySelector('button').textContent='Making…'" style="margin-top:12px">
<input type=hidden name=csrf value="{{ csrf }}">{% if certs %}<p class=err>{{ err }}</p>{% endif %}""" + CERT_PICKER + """
<button name=make value=1>Make New Certificate</button>
<small>Apple makes an Apple Distribution certificate with the API key (and the App ID, if missing). A new certificate makes a new profile and signs every app again; installed apps keep working until it does.</small></form>
<h3 class=hdr>API Key</h3>
<div class=g><div class="row kvr"><div>File</div><span class=val>{{ key_file or 'None' }}</span></div>
<div class="row kvr"><div>Role</div><span class=val>{{ role }}</span></div></div>
<form class="c mg" method=post action=/admin/signing enctype=multipart/form-data onsubmit="this.querySelector('button').textContent='Saving…'" style="margin-top:12px">
<input type=hidden name=csrf value="{{ csrf }}">
<input type=file name=files id=keyf multiple class=vh onchange="keyl.textContent=this.files.length?[...this.files].map(f=>f.name).join(', '):'Choose API Key'">
<label class="b grey" for=keyf id=keyl>Choose API Key</label>
<small>AuthKey_….p8 from App Store Connect → Users and Access → Integrations, loose or in a .zip. Role Admin to make certificates.</small>
{% if 'ASC_KEY_ID' not in env %}<label>Key ID<input name=asc_key_id value="{{ s.asc_key_id or '' }}" autocapitalize=characters autocomplete=off><small>Read from AuthKey_&lt;Key ID&gt;.p8 if empty.</small></label>{% endif %}
{% if 'ASC_ISSUER_ID' not in env %}<label>Issuer ID<input name=asc_issuer_id value="{{ s.asc_issuer_id or '' }}" autocapitalize=none autocomplete=off></label>{% endif %}
{% if 'BUNDLE_ID' not in env %}<label>App ID (BUNDLE_ID)<input name=bundle_id value="{{ s.bundle_id or '' }}" placeholder="com.you.sideload" autocapitalize=none autocomplete=off></label>{% endif %}
<button>Save</button></form>
<h3 class=hdr>Manual</h3>
<div class=g><details{% if p12_open %} open{% endif %}><summary>Upload cert.p12 Instead</summary>
<form class=mg method=post action=/admin/signing enctype=multipart/form-data onsubmit="this.querySelector('button').textContent='Uploading…'">
<input type=hidden name=csrf value="{{ csrf }}">
<small>A certificate you made yourself: cert.p12 and a password.txt, loose or in a .zip.</small>""" + MANUAL_STEPS + """
<input type=file name=files id=sigf multiple class=vh onchange="sigl.textContent=this.files.length?[...this.files].map(f=>f.name).join(', '):'Choose Signing Files'">
<label class="b grey" for=sigf id=sigl>Choose Signing Files</label>
{% if 'P12_PASSWORD' not in env %}<label>P12 Password<input type=password name=p12_password autocomplete=off><small>Leave empty to try a password.txt, or none.</small></label>{% endif %}
<button>Upload</button></form></details></div>"""


def signing_page(err=None, certs=None, manual=False):
    s, key_id = load_json(SETUP), os.environ.get("ASC_KEY_ID", "")
    key_file = (f"AuthKey_{key_id}.p8" if key_id else "asc.p8") if ASC_KEY.exists() else ""
    role = {"admin": "Admin", "limited": "Not Admin"}.get(s.get("asc_role", ""), "Not checked yet" if key_file else "")
    return admin_page(SIGNING, "Signing", err=err, certs=certs or [], cert=cert_status_cached(), info=cert_info(), bundle=BUNDLE_ID,
                      key_file=key_file, role=role, env=ENV_SET, s=s, confirm=REVOKE_CONFIRM, p12_open=manual)


@app.get("/admin/signing")
def admin_signing_page():
    if r := admin_gate():
        return r
    return signing_page()


# Save asks first whenever a password is typed: keep the signed-in iPhones or sign them out (and, over .env's, that it replaces it).
# The keyboard goes down first (blur), so the alert isn't half under it
PW_ASK = """if(this.signout.value===''&&(this.dataset.ask||[...this.querySelectorAll('input[type=password]')].some(i=>i.value))){document.activeElement&&document.activeElement.blur();let a=this.parentNode.querySelector('.ask-'+(this.dataset.ask||'env')),n=a.querySelector('.envnote');if(n)n.hidden=![...this.querySelectorAll('[data-env]')].some(i=>i.value);a.f=this;a.hidden=false;return false}this.querySelector('button').textContent='Saving…'"""
PW_GO = "let s=this.closest('.scrim'),f=s.f;s.hidden=true;f.replace_env.value='1';f.signout.value=this.dataset.v;f.requestSubmit?f.requestSubmit():f.submit()"
PW_BTNS = """<div class="abtns v"><button type=button class=ok data-v=1 onclick="{{ go }}">Sign Out Everyone</button><button type=button class=ok data-v=0 onclick="{{ go }}">Keep Signed In</button>
<button type=button onclick="this.closest('.scrim').hidden=true">Cancel</button></div>"""
# F12: both fields always show; one whose password comes from .env says so, and saving over it asks first (an iOS 6 alert in the page,
# not window.confirm) and stores an override in setup.json; 'Use .env Password' drops it
PASSWORDS = """{% macro note(k) %}{% if k in env %}<b>{{ 'Changed here, over the one in .env' if k in ov else 'Set in .env' }}</b>. {% endif %}{% endmacro %}
<form class="c mg" method=post action=/admin/passwords onsubmit="{{ ask }}">
<input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=replace_env><input type=hidden name=signout>
<label>Friends' Password<input type=password name=password autocomplete=new-password minlength=8{{ ' data-env=1' if 'PASSWORD' in env }}>
<small>{{ note('PASSWORD') }}What friends type to sign in. Old <span class=nw>?password=</span> links stop working; on Save you choose whether signed-in iPhones stay signed in.</small></label>
<label>Admin Password<input type=password name=admin_password autocomplete=new-password minlength=8{{ ' data-env=1' if 'ADMIN_PASSWORD' in env }}>
<small>{{ note('ADMIN_PASSWORD') }}Unlocks Manage. Keep it different from the friends' one. On Save you choose whether other admin iPhones stay signed in; this one always does.</small></label>
<button>Save</button><small>Leave one empty to keep it. At least 8 characters.</small></form>
{% for k, who in (('PASSWORD', "Friends'"), ('ADMIN_PASSWORD', 'Admin')) if k in ov %}
<form class="c mg" method=post action=/admin/passwords data-ask=use onsubmit="{{ ask }}"><input type=hidden name=csrf value="{{ csrf }}">
<input type=hidden name=replace_env><input type=hidden name=signout><input type=hidden name=use_env value={{ k }}>
<button class=grey>Use .env Password</button><small>{{ who }} password: drop the one set here and go back to the one in .env.</small></form>{% endfor %}
<div class="scrim ask-env" hidden><div class=alert role=alertdialog aria-modal=true><h3>Change the Password?</h3>
<p><span class=envnote>This replaces the password from .env on the server. </span>New sign-ins and old ?password= links need the new password. iPhones signed in now can stay signed in, or be signed out and need the new password.</p>
""" + PW_BTNS + """</div></div>
<div class="scrim ask-use" hidden><div class=alert role=alertdialog aria-modal=true><h3>Use the .env Password?</h3>
<p>The password in .env works again and the one set here stops. iPhones signed in with the one set here can stay signed in, or be signed out.</p>
""" + PW_BTNS + """</div></div>"""


@app.route("/admin/passwords", methods=["GET", "POST"])
def admin_passwords():
    """Change the friends' and the admin password (hashed in setup.json). One set in .env gets an override (F12) that password_ok()
    checks first, with a hash of the .env value it replaced, so a later edit of .env wins again. Each change bumps that password's
    version when the admin picks Sign Out Everyone, which signs out the sessions made with the old one; the admin making it stays signed in."""
    if r := admin_gate():
        return r
    env = {k for k in ("PASSWORD", "ADMIN_PASSWORD") if k in ENV_SET}
    err = None
    if request.method == "POST":
        admin_check()
        f, s = request.form, load_json(SETUP)
        out = f.get("signout") == "1"  # the alert's choice: Sign Out Everyone, or Keep Signed In (as before F12)
        bump = lambda p: out and s.__setitem__(f"{p}password_ver", s.get(f"{p}password_ver", 0) + 1)
        if f.get("use_env") in env:  # 'Use .env Password': drop the override
            p = "admin_" if f["use_env"] == "ADMIN_PASSWORD" else ""
            if s.pop(f"{p}password_override", None):
                s.pop(f"{p}password_env", None)
                bump(p)
                save_json(SETUP, s)
                if p and out:
                    session["pv"] = ["a", s["admin_password_ver"]]
            return redirect("/admin/passwords?done=env")
        pw, admin_pw = f.get("password", ""), f.get("admin_password", "")
        if not pw and not admin_pw:
            err = "Type a new password."
        elif any(0 < len(p) < 8 for p in (pw, admin_pw)):
            err = "Passwords need at least 8 characters."
        elif DEFAULT_PASSWORD in (pw, admin_pw) or (pw and pw == admin_pw) or (pw and password_ok(pw, admin=True)) or \
                (admin_pw and password_ok(admin_pw)):
            err = "Choose new passwords, and different ones for friends and for the admin."
        elif f.get("replace_env") != "1" and (pw and "PASSWORD" in env or admin_pw and "ADMIN_PASSWORD" in env):
            err = "Confirm replacing the password from .env."  # the page's alert sets replace_env; a post without it changes nothing
        else:
            for new, p, env_val in ((pw, "", PASSWORD), (admin_pw, "admin_", ADMIN_PASSWORD)):
                if not new:
                    continue
                if env_val:
                    s[f"{p}password_override"], s[f"{p}password_env"] = hash_password(new), hash_password(env_val)
                else:
                    s[f"{p}password"] = hash_password(new)
                bump(p)
            save_json(SETUP, s)
            if admin_pw and out:
                session["pv"] = ["a", s["admin_password_ver"]]
            return redirect("/admin/passwords?done=passwords")
    return admin_page(PASSWORDS, "Passwords", err=err, env=env, ov={k for k in env if env_overridden(k == "ADMIN_PASSWORD")},
                      ask=PW_ASK, go=PW_GO)


# --- F16: invite links (Manage → Invite Friends). 'Anyone with the link' (/join/<token>) signs in like the friends' password without
# holding it (only its hash is kept): an HMAC of the friends' password version and a generation that Make New Link bumps, so Sign Out
# Everyone (which bumps the version) or Make New Link kills old links. A 'One iPhone' invite (/invite/<token>, a random token in
# invites.json) signs a browser in as a guest who can register one iPhone: the first UDID uses it up (register() refuses a second), and
# from then on only that iPhone gets in: its device cookie, or the session that downloaded the registering profile (the Home Screen
# app is a copy of Safari's cookies when it was added, so it has one or the other, as a friend's does). ---

INVITES, invites_lock = DATA / "invites.json", threading.Lock()  # {token: {name, made, exp; once used: udid, device, used, sid}}
INVITE_TTL = 7 * 86400  # an unused one-iPhone invite expires after this
INVITE_USED = "This invite already registered an iPhone. Ask for a new one."
ROW_ICONS["share"] = ("#3f80e0", [("s", "M8.2 9.6H5.8v11h12.4v-11h-2.4", 2.4), ("s", "M12 15V5", 2.6), ("f", "M12 1.8l4.6 4.8H7.4z")])  # rowicons.js share
DONE.update(newlink="Made a new link. The old one no longer works.", revoked="Revoked.")


class InviteRefused(Exception):
    pass


def load_invites():
    return load_json(INVITES)


def invite_name():
    """The name the admin gave this guest's one-iPhone invite, or "" (not a guest, or an invite without a name)."""
    pv = session.get("pv") or ()
    return (load_invites().get(pv[1], {}).get("name") or "") if is_guest() and len(pv) > 2 else ""


def is_guest():
    return session.get("ok") is True and (session.get("pv") or ("",))[0] == "g"


def guest_ok(tok="", sid=""):
    """A guest session still gets in: its invite exists (not revoked) and is unused and unexpired, or was used and this is the iPhone
    it registered (device cookie) or the session that registered it."""
    inv = load_invites().get(tok) if tok else None
    if not inv:
        return False
    if inv.get("udid"):
        return token_udid(request.cookies.get("device", "")) == inv["udid"] or bool(sid) and hmac.compare_digest(sid.encode(), inv.get("sid", "").encode())
    return time.time() < inv.get("exp", 0)


def invite_check(tok, udid):
    """Raises InviteRefused unless this UDID may register through the invite (register() calls it under its lock)."""
    inv = load_invites().get(tok)
    if not inv:
        raise InviteRefused("This invite link doesn't work any more. Ask for a new one.")
    if inv.get("udid"):
        if inv["udid"] != udid:
            raise InviteRefused(INVITE_USED)
    elif time.time() >= inv.get("exp", 0):
        raise InviteRefused("This invite has expired. Ask for a new one.")


def invite_use(tok, sid, udid, device):
    with invites_lock:
        invs = load_invites()
        if tok in invs and not invs[tok].get("udid"):
            invs[tok].update(udid=udid, device=device, used=int(time.time()), sid=sid)
            save_json(INVITES, invs)


def join_token():
    return hmac.new(SECRET, f"join:{password_ver()}:{load_json(SETUP).get('join_gen', 0)}".encode(), hashlib.sha256).hexdigest()[:32]


@app.before_request
def guests_stay_out():
    if (request.path == "/admin" or request.path.startswith("/admin/")) and is_guest():
        abort(403)


INVITE_NO = """<div class="c"><p class=err>{{ msg }}</p></div>"""


@app.get("/join/<tok>")
def join(tok):
    if logged_in() and not is_guest():
        return redirect("/")  # a friend or the admin trying the link stays who they are
    if needs_setup() or not hmac.compare_digest(tok.encode(), join_token().encode()):
        return page(INVITE_NO, title="Invite", msg="This link doesn't work any more. Ask for a new one."), 403
    session.pop("admin", None)
    session.permanent, session["ok"], session["pv"] = True, True, ["f", password_ver()]
    return redirect("/")


@app.get("/invite/<tok>")
def invite_link(tok):
    if logged_in() and not is_guest():
        return redirect("/")
    inv = load_invites().get(tok)
    if inv and (inv["udid"] == token_udid(request.cookies.get("device", "")) if inv.get("udid") else time.time() < inv.get("exp", 0)):
        if not (is_guest() and session["pv"][1:2] == [tok] and logged_in()):  # a guest session already made with it keeps its id
            session.pop("admin", None)
            session.pop("csrf", None)
            session.permanent, session["ok"], session["pv"] = True, True, ["g", tok, secrets.token_urlsafe(12)]
        return redirect("/")
    try:
        invite_check(tok, None)
        msg = INVITE_USED
    except InviteRefused as e:
        msg = str(e)
    return page(INVITE_NO, title="Invite", msg=msg), 403


LINK_BTNS = """<div class=lbtn><button type=button class="{{ cls }}" onclick="lnkCopy(this)">{{ copy }}</button><button type=button class="{{ cls }} grey shr" onclick="lnkShare(this)">{{ share }}</button></div>"""
INVITES_PAGE = """<style>.lnk{font:13px/1.4 ui-monospace,Menlo,monospace;width:100%;box-sizing:border-box} .lbtn{display:flex;gap:8px} .lbtn button{flex:1}
.lbtn button[hidden]{display:none} .irow>div:first-child{flex:1;min-width:0} .irow .lbtn{flex:none;gap:4px} .irow form{flex:none;margin-left:4px} .irow b{font-weight:700}</style>
<h3 class=hdr>Anyone with the Link</h3>
<div class="c mg" data-link="{{ join }}"><input class=lnk readonly value="{{ join }}" aria-label=Link onfocus="this.select()">
""" + LINK_BTNS.replace("{{ cls }}", "").replace("{{ copy }}", "Copy Link").replace("{{ share }}", "Share") + """
<small>Signs in like the friends' password, without typing it. <b>Sign Out Everyone</b> on Passwords stops it, and so does Make New Link.</small></div>
<form class="c mg" method=post action=/admin/invites onsubmit="if(!confirm('Make a new link? The old one stops working.'))return false">
<input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=do value=rotate><button class=grey>Make New Link</button></form>
<h3 class=hdr>One iPhone</h3>
{% if new %}<div class="c mg" data-link="{{ new.url }}"><p class=done>New link{{ ' for ' + new.name if new.name }}:</p><input class=lnk readonly value="{{ new.url }}" aria-label=Link onfocus="this.select()">
""" + LINK_BTNS.replace("{{ cls }}", "").replace("{{ copy }}", "Copy Link").replace("{{ share }}", "Share") + """</div>{% endif %}
<form class="c mg" method=post action=/admin/invites><input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=do value=new>
<input name=name maxlength=30 placeholder="Name (optional), like Sam" aria-label=Name autocomplete=off>
<button>New One-iPhone Link</button><small>Each link registers one iPhone, then signs in again only on that iPhone. Unused links expire after 7 days. Guests install apps like friends but never see these links or the friends' password.</small></form>
{% if invites %}<div class=g>{% for i in invites %}<div class="row irow"{% if i.state == 'unused' %} data-link="{{ i.url }}"{% endif %}>
<div><b>{{ i.name or 'No name' }}</b><small>Made {{ fmt_day(i.made) }} · {{ i.status }}</small></div>
{% if i.state == 'unused' %}""" + LINK_BTNS.replace("{{ cls }}", "act").replace("{{ copy }}", "COPY").replace("{{ share }}", "SHARE") + """{% endif %}
<form method=post action=/admin/invites data-name="{{ i.name or 'this link' }}" onsubmit="if(!confirm('Revoke the link for '+this.dataset.name+'?'))return false">
<input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=do value=revoke><input type=hidden name=tok value="{{ i.tok }}"><button class="act red">REVOKE</button></form></div>{% endfor %}</div>
<p class=ftr>Revoking a used link signs its guest out and leaves the iPhone registered: turn it off on iPhones.</p>{% endif %}
<script>/* F16: Copy Link writes the clipboard in the tap; without the API (or refused) it selects the link's text, and tries execCommand */
window.lnkCopy=function(b){let w=b.closest("[data-link]"),u=w.dataset.link,t=b.textContent,ok=()=>{b.textContent=b.classList.contains("act")?"COPIED":"Copied";setTimeout(()=>b.textContent=t,1500)};
 let sel=()=>{let i=w.querySelector(".lnk"),tmp=!i;if(tmp){i=document.createElement("textarea");i.value=u;i.className="vh";document.body.append(i)}
  i.focus();i.select();i.setSelectionRange(0,u.length);let c=false;try{c=document.execCommand("copy")}catch(e){}if(tmp)i.remove();if(c)ok()};
 if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(u).then(ok,sel);else sel()};
window.lnkShare=function(b){navigator.share({url:b.closest("[data-link]").dataset.link}).catch(()=>{})};
document.querySelectorAll(".shr").forEach(b=>b.hidden=!navigator.share)</script>"""


def invite_rows():
    out, now = [], time.time()
    for tok, inv in sorted(load_invites().items(), key=lambda kv: -kv[1].get("made", 0)):
        made = datetime.datetime.fromtimestamp(inv.get("made", 0))
        if inv.get("udid"):
            state, status = "used", f"Used by {inv.get('device') or 'an iPhone'} on {fmt_day(datetime.datetime.fromtimestamp(inv.get('used', 0)))}"
        elif now >= inv.get("exp", 0):
            state, status = "expired", "Expired"
        else:
            state, status = "unused", "Not used"
        out.append(dict(tok=tok, name=inv.get("name", ""), made=made, state=state, status=status, url=f"{PUBLIC_URL}/invite/{tok}"))
    return out


@app.route("/admin/invites", methods=["GET", "POST"])
def admin_invites():
    if r := admin_gate():
        return r
    if request.method == "POST":
        admin_check()
        do = request.form.get("do")
        if do == "rotate":
            s = load_json(SETUP)
            s["join_gen"] = s.get("join_gen", 0) + 1
            save_json(SETUP, s)
            return redirect("/admin/invites?done=newlink")
        if do == "new":
            tok, now = secrets.token_urlsafe(16), int(time.time())
            name = re.sub(r"[^\w .'-]", "", request.form.get("name", "")).strip()[:30]
            with invites_lock:
                save_json(INVITES, {**load_invites(), tok: {"name": name, "made": now, "exp": now + INVITE_TTL}})
            return redirect(f"/admin/invites?new={tok}")
        if do == "revoke":
            with invites_lock:
                invs = load_invites()
                if invs.pop(request.form.get("tok", ""), None) is not None:
                    save_json(INVITES, invs)
            return redirect("/admin/invites?done=revoked")
        abort(400)
    rows = invite_rows()
    new = next((i for i in rows if i["tok"] == request.args.get("new") and i["state"] == "unused"), None)
    return admin_page(ADMIN_CSS + INVITES_PAGE, "Invite Friends", join=f"{PUBLIC_URL}/join/{join_token()}", invites=rows, new=new)


FILE_ROW ="""<div class=row data-file="{{ f.name }}"><div>{{ f.name }}<small>{{ f.stat().st_size|filesizeformat }}</small></div>
<form method=post action=/admin/files/delete data-name="{{ f.name }}" onsubmit="if(!confirm('Delete '+this.dataset.name+'?'))return false">
<input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=name value="{{ f.name }}"><button class="act red">DELETE</button></form></div>"""
# F13: picking files uploads them at once, one XMLHttpRequest each (upload.onprogress gives the bytes), as iFizBox's asynchronous
# installs: each file is a row with Cydia's progress bar (iFizBox progress.css's .progress-track/.progress-fill, drawn in the row's
# grey instead of the console's white) until the server's own row (json=1's answer) replaces it, or a red row with Retry. The queue
# lives on window (window.upQ), so leaving the page doesn't stop it and the page, opened again, shows its rows.
FILES_PAGE = """<style>.ptrack{height:12px;padding:3px;margin:5px 0 3px;border:1px solid var(--sub);border-radius:6px;box-sizing:border-box}
.pfill{height:4px;width:100%;border-radius:2px;background:var(--sub);transform-origin:left;transform:scaleX(0);transition:transform .2s linear}
.uprow.bad small{color:#d70015} .uprow .act{margin-left:4px} #flist[hidden],.uprow [hidden]{display:none}</style>
<div class=g id=flist{% if not files %} hidden{% endif %}>{% for f in files %}""" + FILE_ROW + """{% endfor %}</div>
<p class=ftr id=fnone{% if files %} hidden{% endif %}>No files yet.</p>
<form class="c mg" method=post action=/admin/files enctype=multipart/form-data data-csrf="{{ csrf }}" style="margin-top:12px">
<input type=hidden name=csrf value="{{ csrf }}">
<input type=file name=files id=upf multiple class=vh onchange="upAdd(this)">
<label class="b grey" for=upf id=upl>Choose Files</label><noscript><button>Upload</button></noscript>
<small>Listed on everyone's Files tab. A file with the same name is replaced. Uploads go on while you use the rest of SideDrop.</small></form>
<script>(function(){let Q=window.upQ=window.upQ||{jobs:[],n:0};
const list=()=>{let l=document.getElementById("flist");return l&&l.isConnected?l:null};
function unit(t){return t>=1e9?[1e9,"GB"]:t>=1e6?[1e6,"MB"]:[1e3,"KB"]}
function amt(b,u,t){let v=b/u[0];return t/u[0]>=10?Math.round(v):v.toFixed(1)}
function said(j){if(j.err)return j.err;let u=unit(j.size),p=j.size?Math.floor(100*j.loaded/j.size):100;
 return j.loaded>=j.size&&j.size?"Saving "+amt(j.size,u,j.size)+" "+u[1]+"…":"Uploading "+p+"% · "+amt(j.loaded,u,j.size)+" of "+amt(j.size,u,j.size)+" "+u[1]}
function row(j){let l=list();if(!l)return null;let r=l.querySelector('[data-up="'+j.id+'"]');
 if(!r){r=document.createElement("div");r.className="row uprow";r.dataset.up=j.id;r.innerHTML="<div><span></span><div class=ptrack><div class=pfill></div></div><small></small></div>";
  r.firstChild.firstChild.textContent=j.name;let b=document.createElement("button");b.type="button";b.className="act";b.textContent="RETRY";b.onclick=()=>send(j);
  let x=document.createElement("button");x.type="button";x.className="act grey";x.textContent="CLEAR";x.onclick=()=>{Q.jobs=Q.jobs.filter(o=>o!=j);r.remove();empty()};
  let c=document.createElement("button");c.type="button";c.className="act red";c.dataset.k="cancel";c.textContent="CANCEL";c.onclick=()=>{if(j.x)j.x.abort();x.onclick()};r.append(b,x,c);
  l.prepend(r);l.hidden=false;let n=document.getElementById("fnone");if(n)n.hidden=true}
 return r}
function draw(j){let r=row(j);if(!r)return;r.classList.toggle("bad",!!j.err);r.querySelector(".ptrack").hidden=!!j.err;
 r.querySelector(".pfill").style.transform="scaleX("+(j.size?j.loaded/j.size:1)+")";r.querySelector("small").textContent=said(j);r.querySelectorAll(".act").forEach(b=>b.hidden=b.dataset.k=="cancel"?!!j.err||j.size>0&&j.loaded>=j.size:!j.err)}  // CANCEL while it uploads, where DELETE goes; gone once the server is saving it
function empty(){let l=list(),n=document.getElementById("fnone");if(l&&!l.children.length){l.hidden=true;if(n)n.hidden=false}}
function finish(j,html){Q.jobs=Q.jobs.filter(o=>o!=j);let l=list();if(!l)return;let r=l.querySelector('[data-up="'+j.id+'"]');
 l.querySelectorAll(".row[data-file]").forEach(o=>{if(o.dataset.file==j.saved)o.remove()});  // a file with the same name was replaced
 let t=document.createElement("template");t.innerHTML=html;let n=t.content.firstElementChild;if(r)r.replaceWith(n);else l.prepend(n);l.hidden=false}
function send(j){j.err=null;j.loaded=0;draw(j);let f=new FormData();f.append("csrf",j.csrf);f.append("json","1");f.append("files",j.file,j.name);
 let x=j.x=new XMLHttpRequest();x.open("POST","/admin/files");x.withCredentials=true;
 x.upload.onprogress=e=>{if(e.total)j.loaded=Math.round(j.size*e.loaded/e.total);draw(j)};  // e.total counts the form's own bytes too: scaled to the file's
 x.onload=()=>{let d=null;try{d=JSON.parse(x.responseText)}catch(e){}
  if(x.status==200&&d&&d.html){j.saved=d.name;return finish(j,d.html)}
  j.err=d&&d.error||(x.status==403?"Signed out of Manage. Open Manage again, then Retry.":x.status==413?"Too big for the server.":"Upload failed (HTTP "+x.status+").");draw(j)};
 x.onerror=()=>{j.err="Couldn't reach SideDrop. Check the connection, then Retry.";draw(j)};x.onabort=()=>{Q.jobs=Q.jobs.filter(o=>o!=j)};x.send(f)}
window.upAdd=function(i){let csrf=i.form.dataset.csrf;[...i.files].forEach(file=>{let j={id:++Q.n,file,name:file.name,size:file.size,loaded:0,csrf};Q.jobs.push(j);send(j)});i.value=""};
Q.jobs.forEach(draw)})()</script>"""


@app.get("/admin/files")
def admin_files_page():
    if r := admin_gate():
        return r
    return admin_page(ADMIN_CSS + FILES_PAGE, "Files for Friends", files=shared_files())


CONFIG_FORMS = """{% for c in configs %}<form class="c mg" method=post action=/admin/config>
<input type=hidden name=csrf value="{{ csrf }}"><input type=hidden name=name value="{{ c.name }}">
<label>{{ c.label }}<textarea name=text autocapitalize=none autocorrect=off spellcheck=false>{{ c.text }}</textarea>
<small>{{ c.name }}{% if c.custom %}, changed here; the repo's copy is the default{% elif c.text %}, the repo's default{% else %}, not set{% endif %}.</small></label>
<button>Save</button>{% if c.custom %}<button class=grey name=reset value=1 onclick="return confirm('Go back to the default?')">Use Default</button>{% endif %}</form>{% endfor %}
<p class=ftr>{{ note }}</p>"""
CONFIG_PAGES = {  # Manage's pages of EDITABLE files: (path, title, files, footer)
    "sources": ("/admin/sources", "App Sources", ("mirror-sources.txt", "third-party-sources.txt"),
                "An AltStore source URL per line, then the bundle IDs to take from it (none = all). Third-party apps are listed apart. "
                "Lines that aren't URLs are ignored."),
    "ifizbox": ("/admin/ifizbox", "iFizBox", (IFIZBOX_SOURCES, IFIZBOX_SETTINGS),
                "Signed into iFizBox for new installs. Its sources: a URL per line. Its settings: a JSON object it imports on first launch."),
}


def config_page(which, err=None):
    _, title, names, note = CONFIG_PAGES[which]
    configs = [dict(name=n, label=EDITABLE[n], text=conf(n).read_text() if conf(n).exists() else "", custom=(CONFIG / n).exists()) for n in names]
    return admin_page(CONFIG_FORMS, title, configs=configs, note=note, err=err)


@app.get("/admin/sources")
def admin_sources_page():
    return admin_gate() or config_page("sources")


@app.get("/admin/ifizbox")
def admin_ifizbox_page():
    return admin_gate() or config_page("ifizbox")


def resign_all():
    """After new signing files: a profile for the new certificate, then every app signed with both."""
    try:
        with lock:
            if PROFILE.exists():  # none yet = nobody registered; the first registration makes it
                regen_profile()
                resign(force=True)
    except Exception as e:
        print("re-signing after new signing files failed:", e, flush=True)


def profile_stale():
    """Why the ad hoc profile no longer fits the signing files: made for another certificate or another App ID, or None."""
    p = embedded_plist(PROFILE.read_bytes())
    _, cert, _ = pkcs12.load_key_and_certificates(P12.read_bytes(), P12_PASSWORD.encode() or None)
    if cert.public_bytes(serialization.Encoding.DER) not in p.get("DeveloperCertificates", []):
        return "it was made for another certificate"
    ents = p.get("Entitlements", {})
    if ents.get("application-identifier") != f"{ents.get('com.apple.developer.team-identifier')}.{BUNDLE_ID}":
        return f"it was made for {ents.get('application-identifier')}, not {BUNDLE_ID}"
    return None


def heal_signing():
    """At start, after cert.p12, P12_PASSWORD or BUNDLE_ID changed on the server: the App ID gets the capabilities it lacks, and a
    profile that no longer fits (or predates those capabilities) is made again, with every app signed again."""
    repack_p12()  # B1: before anything signs with it
    if needs_setup() or not (PROFILE.exists() and P12.exists() and ASC_KEY.exists() and BUNDLE_ID
                             and os.environ.get("ASC_KEY_ID") and os.environ.get("ASC_ISSUER_ID")):
        return
    why = None
    try:
        if ensure_app_id(BUNDLE_ID):
            why = f"the App ID {BUNDLE_ID} was made or got capabilities"
    except Exception as e:
        print(f"couldn't check the App ID {BUNDLE_ID}'s capabilities:", e, flush=True)
    try:
        why = why or profile_stale()
    except Exception as e:
        print("couldn't read the ad hoc profile or cert.p12:", e, flush=True)
    if why:
        print(f"making the ad hoc profile again: {why}", flush=True)
        resign_all()


threading.Thread(target=heal_signing, daemon=True).start()  # ponytail: once per worker (one gunicorn worker)


@app.post("/admin/signing")
def admin_signing():
    admin_check()
    f, s = request.form, load_json(SETUP)
    bid = f.get("bundle_id", "").strip()
    if bid and "BUNDLE_ID" not in ENV_SET and not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*(\.\*)?", bid):
        return signing_page("That App ID doesn't look right: com.you.sideload, or a wildcard such as com.you.*.")
    old_bid, key_at = BUNDLE_ID, ASC_KEY.stat().st_mtime if ASC_KEY.exists() else None
    uploads = request.files.getlist("files")
    manual = bool(f.get("p12_password")) or any((u.filename or "").lower().endswith((".p12", ".pfx")) for u in uploads)
    err = take_signing_files(f, uploads, s)
    if (ASC_KEY.stat().st_mtime if ASC_KEY.exists() else None) != key_at:
        s.pop("asc_role", None)  # a new key: its role isn't known until it makes (or is refused) a certificate
    save_json(SETUP, s)
    apply_setup()
    if err:
        return signing_page(err, manual=manual)
    if BUNDLE_ID != old_bid and not f.get("make"):  # a new App ID: made if missing; the banner says so if Apple refused
        try:
            ensure_app_id(BUNDLE_ID)
        except Exception as e:
            print(f"couldn't make App ID {BUNDLE_ID}:", e, flush=True)
    if f.get("make") or f.get("revoke") or not P12.exists():  # Make New Certificate, or a pick from its revoke list
        if not ASC_KEY.exists() or not BUNDLE_ID or not (os.environ.get("ASC_KEY_ID") and os.environ.get("ASC_ISSUER_ID")):
            return signing_page("Add the API key, its Key ID and Issuer ID, and the App ID first.")
        err, certs = api_signing(s, f.get("revoke", ""))
        if err:
            if "Admin role" in err:  # Apple's 403: Signing's API Key group says so
                save_json(SETUP, dict(load_json(SETUP), asc_role="limited"))
            return signing_page(err, certs)
        save_json(SETUP, s)
        apply_setup()
        cert_cache.clear()
    threading.Thread(target=resign_all, daemon=True).start()
    return redirect("/admin/signing?done=signing")


@app.post("/admin/config")
def admin_config():
    global SOURCES
    admin_check()
    name, text = request.form.get("name", ""), request.form.get("text", "").replace("\r\n", "\n")
    if name not in EDITABLE or len(text) > 64 << 10:
        abort(400)
    CONFIG.mkdir(parents=True, exist_ok=True)
    if request.form.get("reset"):
        (CONFIG / name).unlink(missing_ok=True)
    else:
        if name.endswith(".json") and text.strip():
            try:
                if not isinstance(json.loads(text), dict):
                    raise ValueError
            except ValueError:
                return config_page(next(k for k, v in CONFIG_PAGES.items() if name in v[2]),
                                   f"{EDITABLE[name]}: that isn't a JSON object, like {{\"key\": \"value\"}}.")
        (CONFIG / name).write_text(text.strip() + "\n" if text.strip() else "")
    if name in (IFIZBOX_SOURCES, IFIZBOX_SETTINGS):  # they're inside iFizBox: sign it again (next page load) so new installs get them
        if (APPS / f"{IFIZBOX_ID}.ipa").exists():
            (SIGNED / f"{IFIZBOX_ID}.ipa").unlink(missing_ok=True)
    else:
        SOURCES = [(u, ids, False) for u, ids in read_sources("mirror-sources.txt")] + \
                  [(u, ids, True) for u, ids in read_sources("third-party-sources.txt")]
        threading.Thread(target=sync_if_stale, args=(0,), daemon=True).start()  # fetch the new sources' apps now
    page_url = next(v[0] for v in CONFIG_PAGES.values() if name in v[2])
    return redirect(page_url + "?done=" + ("default" if request.form.get("reset") else "sources"))


@app.post("/admin/files")
def admin_files():
    """The Files page's upload. json=1 (the page's background upload, one file per request) answers {"name", "size", "html": the
    file's row} or {"error"} with a 4xx/5xx status; without it, the old form post: back to the page."""
    admin_check()
    as_json = request.form.get("json") == "1"
    saved = None
    try:
        FILES.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass  # the save below says why
    for u in request.files.getlist("files"):
        name = re.sub(r"[/\\\x00-\x1f]", "", (u.filename or "").rsplit("/", 1)[-1]).strip().lstrip(".")
        if name:
            tmp = FILES / f".{name}.part"
            try:
                u.save(tmp)  # streamed to disk, so big files are fine
                tmp.replace(FILES / name)
                saved = FILES / name
            except OSError as e:  # e.g. a files/ folder made by another user: say so instead of a 500
                print("file upload failed:", e, flush=True)
                err = f"Couldn't save {name}: the server can't write to the data folder's files/ ({e.strerror})."
                if as_json:
                    return {"error": err}, 500
                return admin_page(ADMIN_CSS + FILES_PAGE, "Files for Friends", files=shared_files(), err=err)
    if as_json:
        if not saved:
            return {"error": "No file came with the upload."}, 400
        return {"name": saved.name, "size": saved.stat().st_size,
                "html": render_template_string(FILE_ROW, f=saved, csrf=session["csrf"])}
    return redirect("/admin/files?done=files")


@app.post("/admin/files/delete")
def admin_file_delete():
    admin_check()
    f = next((p for p in shared_files() if p.name == request.form.get("name")), None)  # only a listed file, never a path
    if not f:
        abort(404)
    f.unlink()
    return redirect("/admin/files?done=deleted")


@app.get("/f/<name>")
def shared_file(name):
    check_sig()
    if name.startswith("."):
        abort(404)
    return send_from_directory(FILES, name, as_attachment=True)  # handles Range, so downloads resume


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
    pv = session.get("pv") or ()
    guest = len(pv) > 2 and pv[0] == "g"
    name = re.sub(r"[^\w .'-]", "", invite_name() or request.form.get("name", ""))[:30] or "friend"  # a named invite's name wins over the form
    tail = f"{name}/g/{pv[1]}/{pv[2]}" if guest else name  # F16: a guest's goes through its invite
    # B2: answer with a signed GET link, not the profile itself: Safari's download manager on recent iOS fetches a
    # download again with GET, and a POST-only URL then shows "Method Not Allowed".
    return redirect(signed_url(f"/enroll/profile/{tail}", ttl=1800), 303)


@app.get("/enroll")
def enroll_get():
    return redirect("/")


@app.get("/enroll/profile/<path:tail>")
def enroll_profile(tail):
    """B2: the registration profile, behind a signed link (iOS may fetch it more than once, without a form)."""
    check_sig()
    url = signed_url(f"/udid/{tail}", ttl=1800)
    profile = plistlib.dumps({
        "PayloadContent": {"URL": url, "DeviceAttributes": ["UDID", "PRODUCT"]},
        "PayloadOrganization": "SideDrop", "PayloadDisplayName": "SideDrop device registration",
        "PayloadDescription": "Shares this iPhone's device ID so apps can be signed for it.",
        "PayloadIdentifier": "sidedrop.udid", "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadType": "Profile Service", "PayloadVersion": 1})
    return sign_profile(profile), 200, {"Content-Type": "application/x-apple-aspen-config",
                          "Content-Disposition": 'attachment; filename="SideDrop.mobileconfig"'}


@app.post("/udid/<name>")
def udid(name):
    check_sig()
    attrs = embedded_plist(request.get_data())
    save_product(attrs["UDID"], attrs.get("PRODUCT", ""))
    register(attrs["UDID"], f"{name} {attrs.get('PRODUCT', '')}".strip())
    return redirect(f"{PUBLIC_URL}/?enrolled={device_token(attrs['UDID'])}", 301)  # iOS requires a 301 here, then opens it in Safari


@app.post("/udid/<name>/g/<tok>/<sid>")
def udid_guest(name, tok, sid):
    """F16: a guest's registration, through its one-iPhone invite. A second UDID (or a revoked or expired invite) is refused:
    iOS opens the 301 in Safari, where /invite/<tok> says why."""
    check_sig()
    attrs = embedded_plist(request.get_data())
    try:
        register(attrs["UDID"], f"{name} {attrs.get('PRODUCT', '')}".strip(), invite=(tok, sid))
    except InviteRefused:
        return redirect(f"{PUBLIC_URL}/invite/{tok}", 301)
    save_product(attrs["UDID"], attrs.get("PRODUCT", ""))
    return redirect(f"{PUBLIC_URL}/?enrolled={device_token(attrs['UDID'])}", 301)


def drop_old_custom_signs():
    """At start: signed/custom/ held IPAs friends signed themselves, which SideDrop no longer does (iFizBox does). Their links
    are dead, so the files go."""
    old = SIGNED / "custom"
    if old.is_dir():
        for f in old.iterdir():
            if f.is_file():
                f.unlink(missing_ok=True)
        try:
            old.rmdir()
        except OSError:  # something else in it: leave it
            pass


drop_old_custom_signs()


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
