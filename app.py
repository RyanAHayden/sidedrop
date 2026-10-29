"""sidedrop: password-gated UDID enrollment, ad hoc OTA installs and private file downloads."""
import base64, hashlib, hmac, os, plistlib, re, subprocess, threading, time, uuid, zipfile
from pathlib import Path
from urllib.parse import quote

import jwt, requests
from cryptography.hazmat.primitives.serialization import pkcs12
from flask import Flask, abort, redirect, render_template_string, request, send_from_directory, session, url_for

DATA = Path(os.environ.get("DATA", "/data"))
APPS, SIGNED, FILES = DATA / "apps", DATA / "signed", DATA / "files"
PROFILE = DATA / "adhoc.mobileprovision"
P12, ASC_KEY = DATA / "cert.p12", DATA / "asc.p8"
PASSWORD = os.environ["PASSWORD"]
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")  # must be https with a real cert, iOS refuses otherwise
SECRET = os.environ["SECRET_KEY"].encode()
P12_PASSWORD = os.environ.get("P12_PASSWORD", "")
BUNDLE_ID = os.environ.get("BUNDLE_ID", "")  # wildcard like com.you.* covers every app with one profile
PROFILE_NAME = os.environ.get("PROFILE_NAME", "sidedrop adhoc")
LINK_TTL = int(os.environ.get("LINK_TTL", 7 * 86400))

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
            "title": info.get("CFBundleDisplayName") or info.get("CFBundleName") or path.stem}


def resign(force=False):
    """Sign every apps/*.ipa whose signed copy is missing or older than the IPA or profile."""
    if not PROFILE.exists():
        return
    SIGNED.mkdir(exist_ok=True)
    for src in sorted(APPS.glob("*.ipa")):
        out = SIGNED / src.name
        if force or not out.exists() or out.stat().st_mtime < max(src.stat().st_mtime, PROFILE.stat().st_mtime):
            subprocess.run(["zsign", "-q", "-k", P12, "-p", P12_PASSWORD, "-m", PROFILE, "-o", out, src],
                           check=True, timeout=600)


# --- pages ---

PAGE = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>sidedrop</title><style>
:root{color-scheme:light dark;--fg:#111;--bg:#fafafa;--card:#fff;--mute:#666;--acc:#0a66ff}
@media(prefers-color-scheme:dark){:root{--fg:#eee;--bg:#111;--card:#1c1c1e;--mute:#999;--acc:#4c8dff}}
body{font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:34rem;margin:0 auto;padding:1.5rem 1rem}
.c{background:var(--card);border-radius:12px;padding:1rem 1.2rem;margin:1rem 0}
a.b,button{display:inline-block;background:var(--acc);color:#fff;border:0;border-radius:8px;padding:.6rem 1rem;font:inherit;text-decoration:none;cursor:pointer}
input{font:inherit;padding:.55rem;border-radius:8px;border:1px solid var(--mute);width:100%;box-sizing:border-box;margin:.3rem 0 .8rem;background:transparent;color:inherit}
small,.m{color:var(--mute)} li{margin:.5rem 0} .err{color:#d33}</style>
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
    error = None
    try:
        with lock:
            resign()  # ponytail: signs stale IPAs on page load; first visit after an upload waits for it
    except Exception as e:
        error = str(e)
    apps = [dict(ipa_info(p), name=p.stem) for p in sorted(SIGNED.glob("*.ipa"))] if SIGNED.exists() else []
    files = sorted(p for p in FILES.rglob("*") if p.is_file()) if FILES.exists() else []
    return page("""
{% if error %}<p class="c err">{{ error }}</p>{% endif %}
{% if request.args.get('enrolled') %}<p class=c>✅ Your iPhone is registered. Install below.
<br><small>You can delete the "sidedrop" profile in Settings → General → VPN &amp; Device Management.</small></p>{% endif %}
<div class=c><h3>1. Register this iPhone</h3>
<p class=m>Open this page in Safari on the iPhone. Tap the button, then go to Settings → Profile Downloaded → Install.</p>
<form method=post action=/enroll><label>Your name<input name=name required maxlength=30></label><button>Register iPhone</button></form></div>
<div class=c><h3>2. Install apps</h3>{% if apps %}<ul>{% for a in apps %}
<li><a class=b href="itms-services://?action=download-manifest&url={{ manifest(a.name) }}">Install {{ a.title }}</a>
<small>v{{ a.version }}</small></li>{% endfor %}</ul>
<small>Tap Install, then check your home screen. Not registered yet? Do step 1 first.</small>
{% else %}<p class=m>No apps yet.</p>{% endif %}</div>
{% if files %}<div class=c><h3>Files</h3><ul>{% for f in files %}
<li><a href="{{ dl(f) }}">{{ f.relative_to(FILES) }}</a> <small>{{ '%.1f'|format(f.stat().st_size/1e6) }} MB · link works without login for 7 days</small></li>
{% endfor %}</ul></div>{% endif %}
<p><a href=/logout class=m>Sign out</a></p>""", error=error, apps=apps, files=files, FILES=FILES,
        manifest=lambda n: quote(signed_url(f"/m/{n}.plist"), safe=""),
        dl=lambda f: signed_url(f"/f/{f.relative_to(FILES)}"))


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
    return profile, 200, {"Content-Type": "application/x-apple-aspen-config",
                          "Content-Disposition": 'attachment; filename="sidedrop.mobileconfig"'}


@app.post("/udid/<name>")
def udid(name):
    check_sig()
    attrs = embedded_plist(request.get_data())
    register(attrs["UDID"], f"{name} {attrs.get('PRODUCT', '')}".strip())
    return redirect(f"{PUBLIC_URL}/?enrolled=1", 301)  # iOS requires a 301 here, then opens it in Safari


@app.get("/m/<name>.plist")
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


@app.get("/i/<name>.ipa")
def ipa(name):
    check_sig()
    return send_from_directory(SIGNED, f"{name}.ipa", mimetype="application/octet-stream")


@app.get("/f/<path:rel>")
def file(rel):
    check_sig()
    return send_from_directory(FILES, rel, as_attachment=True)  # handles Range, so downloads resume


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
