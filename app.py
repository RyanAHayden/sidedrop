"""sidedrop: password-gated UDID enrollment, ad hoc OTA installs and private file downloads."""
import base64, hashlib, hmac, os, plistlib, re, subprocess, threading, time, uuid, zipfile
from pathlib import Path
from urllib.parse import quote

import jwt, requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from flask import Flask, abort, redirect, render_template_string, request, send_from_directory, session, url_for

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
        for a in requests.get(url, timeout=30).json().get("apps", []):
            if ids and a["bundleIdentifier"] not in ids:
                continue
            v = (a.get("versions") or [a])[0]  # newer sources nest versions, older ones are flat
            slug = re.sub(r"[^\w.-]", "", a["bundleIdentifier"])
            (APPS / f".{slug}.third").touch() if third else (APPS / f".{slug}.third").unlink(missing_ok=True)
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

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>sidedrop</title><style>
:root{color-scheme:light dark;--fg:#111;--bg:#fafafa;--card:#fff;--mute:#666;--acc:#0a66ff}
@media(prefers-color-scheme:dark){:root{--fg:#eee;--bg:#111;--card:#1c1c1e;--mute:#999;--acc:#4c8dff}}
body{font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:34rem;margin:0 auto;padding:1.5rem 1rem}
.c{background:var(--card);border-radius:12px;padding:1rem 1.2rem;margin:1rem 0}
a.b,button{display:inline-block;background:var(--acc);color:#fff;border:0;border-radius:8px;padding:.6rem 1rem;font:inherit;text-decoration:none;cursor:pointer}
input{font:inherit;padding:.55rem;border-radius:8px;border:1px solid var(--mute);width:100%;box-sizing:border-box;margin:.3rem 0 .8rem;background:transparent;color:inherit}
label.drop{display:block;border:2px dashed var(--mute);border-radius:12px;padding:1.2rem;text-align:center;margin:.3rem 0 .8rem}
summary{cursor:pointer} small,.m{color:var(--mute)} li{margin:.5rem 0} .err{color:#d33}</style>
<h1>sidedrop</h1>{{ body|safe }}"""


def page(body, **ctx):
    return render_template_string(PAGE, body=render_template_string(body, **ctx))


@app.get("/")
def home():
    if "password" in request.args:  # shareable ?password= link; redirect drops it from the address bar
        return login()
    if not logged_in():
        return page("""<form class=c method=post action=/login>
<label>Password<input type=password name=password autofocus required></label>
{% if err %}<p class=err>Wrong password.</p>{% endif %}<button>Sign in</button></form>""", err=request.args.get("err"))
    if request.args.get("enrolled"):  # the 301 after the profile install lands here in Safari
        session["enrolled"] = True
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
    apps = [a for a in apps if a not in feather and a not in third]
    files = sorted(p for p in FILES.rglob("*") if p.is_file()) if FILES.exists() else []
    return page("""
{% if error %}<p class="c err">{{ error }}</p>{% endif %}
{% set enroll_form %}<form method=post action=/enroll onsubmit="document.getElementById('next').hidden=false">
<label>Your name<input name=name required maxlength=30></label><button>Register iPhone</button></form>
<ol id=next hidden><li>Tap <b>Allow</b>, then <b>Close</b>.</li><li>Open the <b>Settings</b> app.</li>
<li>Tap <b>Profile Downloaded</b> near the top.</li><li>Tap <b>Install</b>, enter your passcode, tap <b>Install</b> again.</li>
<li>You'll land back here automatically, registered.</li></ol>{% endset %}
{% if enrolled %}<div class=c><h3>✅ This iPhone is registered</h3>
<small>You can delete the "sidedrop" profile in Settings → General → VPN &amp; Device Management.</small>
<details><summary class=m>Register a different iPhone</summary>{{ enroll_form }}</details></div>
{% else %}<div class=c><h3>1. Register this iPhone</h3>
<p class=m>Do this in Safari on the iPhone. It takes about a minute, once per phone.</p>{{ enroll_form }}</div>{% endif %}
{% macro install_list(apps) %}<ul>{% for a in apps %}
<li><a class=b href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">Install {{ a.title }}</a>
<small>v{{ a.short }}</small>{% for f in a.files %}<br><a href="{{ adl(f) }}">{{ f.name }}</a>
<small>{{ '%.1f'|format(f.stat().st_size/1e6) }} MB</small>{% endfor %}</li>{% endfor %}</ul>{% endmacro %}
<div class=c><h3>2. Install apps</h3>{% if apps %}{{ install_list(apps) }}
<small>Tap Install, then Install again in the popup and check your home screen.</small>
{% else %}<p class=m>No apps yet.</p>{% endif %}
{% if third %}<h4>Third-party apps</h4><p class=m>Made by other people, mirrored from their sources.</p>{{ install_list(third) }}{% endif %}</div>
<div class=c><h3>3. Enable Developer Mode</h3><p class=m>Needed once per iPhone for apps not from the App Store.</p>
<ol><li>Install an app above first. The switch only shows up after that.</li>
<li>Open Settings → Privacy &amp; Security → <b>Developer Mode</b> (near the bottom) → turn it on → <b>Restart</b>.</li>
<li>After the restart, tap <b>Turn On</b> and enter your passcode. The apps open normally from then on.</li></ol></div>
<details class=c><summary><b>Feather</b> <small>on-device signer</small></summary>
<p class=m>Feather installs and re-signs IPAs right on the iPhone. It needs your own Apple certificate to sign;
the "Sign your own IPA" box below works without one.</p>
{% for a in feather %}<p><a class=b href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">Install Feather</a>
<small>v{{ a.short }}</small></p>{% endfor %}
{% if sources %}<p class=m>Sources to add in Feather:</p>
<textarea id=src readonly rows={{ sources|length }} style="width:100%;box-sizing:border-box;font:13px ui-monospace,monospace;background:transparent;color:inherit;border-radius:8px">{{ sources|join('\n') }}</textarea>
<button type=button onclick="navigator.clipboard.writeText(src.value).then(()=>this.textContent='Copied ✓')">Copy sources</button>{% endif %}
<p><a href="{{ FEATHER_REPO }}">Feather on GitHub</a> · <a href="{{ FEATHER_REPO }}/releases/latest">latest release</a></p></details>
<details class=c><summary><b>Sign your own IPA</b></summary>
<form method=post action=/sign enctype=multipart/form-data onsubmit="this.querySelector('button').textContent='Signing…'">
<label class=drop>Drop an .ipa here or tap to browse<input type=file name=ipa accept=.ipa></label>
<label>…or paste a link to one<input type=url name=url placeholder="https://…/App.ipa"></label>
<button>Sign</button></form><small>Signed for registered iPhones. The install link lasts 7 days.</small></details>
{% if files %}<div class=c><h3>Files</h3><ul>{% for f in files %}
<li><a href="{{ dl(f) }}">{{ f.relative_to(FILES) }}</a> <small>{{ '%.1f'|format(f.stat().st_size/1e6) }} MB · link works without login for 7 days</small></li>
{% endfor %}</ul></div>{% endif %}
<p><a href=/logout class=m>Sign out</a></p>""", error=error, enrolled=session.get("enrolled"), apps=apps, third=third, files=files, FILES=FILES, feather=feather, FEATHER_REPO=FEATHER_REPO,
        sources=read_urls("feather-sources.txt"),
        manifest=lambda n: quote(signed_url(f"/m/{n}.plist"), safe=""),
        dl=lambda f: signed_url(f"/f/{f.relative_to(FILES)}"), adl=lambda f: signed_url(f"/af/{f.relative_to(APP_FILES)}"))


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
    return redirect(f"{PUBLIC_URL}/?enrolled=1", 301)  # iOS requires a 301 here, then opens it in Safari


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
    return plistlib.dumps({"items": [{
        "assets": [{"kind": "software-package", "url": signed_url(f"/i/{name}.ipa", ttl=3600)}],
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
