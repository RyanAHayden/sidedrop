"""The README's screenshots: SideDrop run locally with demo data, shot at the iPhone 18 Pro's screen size and framed in
its bezel with the iOS 27 status bar and home indicator.

    uv run -q --no-project --with-requirements requirements.txt --with playwright --with pillow python docs/readme_shots.py \
        [--kit "PATH/Apple iOS 27 UI Kit.sketch"] [--finish Black|Silver|Glacier|Burgundy] [--plain]

Nothing comes from a real server: Apple's API and zsign are stubbed, the apps are tiny fake IPAs, and every name, UDID and
domain is made up (example.com). Uses the system Chromium (CHROMIUM, default /usr/bin/chromium).

Capture: headless Chromium at the 18 Pro's screen, 402x874 points at 3x (1206x2622), mobile, an iPhone user agent and
the 18 Pro's safe areas (62 points at the top, 34 at the bottom, CDP Emulation.setSafeAreaInsetsOverride), so the page
lays out around the status bar and home indicator as on the phone. The raw captures go to a temporary folder; only the
finished PNGs are written to docs/img:

- <name>.png: the screen with the kit's iOS 27 status bar (white, "Dark Background") and home indicator drawn on it,
  a soft diagonal sheen, in the iPhone 18 Pro bezel, scaled to 0.4 of the 3x bezel (540x1104) with 24 transparent
  pixels left and right, so phones side by side in the README don't touch, and its label from LABELS drawn under it
  (the name on an amber pill, a line in grey: readable on GitHub's light and dark), so captions can't drift;
- crop-<name>.png: a part of a page (the settings that matter), at the same scale as the phones' screens (0.4 of 3x),
  with rounded corners and no bezel.

The kit is Apple's iOS 27 UI Kit (a .sketch file: a zip with pages/*.json for the layers, images/ for the bitmaps, fonts/
for the embedded SF Pro), read in memory from --kit, by default iFizBox's checkout beside this one
(~/repos/iFizBox/ref/apple-ios27/). It is never copied into this repo. --plain skips the phone (rounded screen corners
only) for when the kit isn't at hand. This framing code is SideDrop's own copy of the approach in iFizBox's
tools/readme_shots.py; nothing is imported from iFizBox. The test gate doesn't run this file.
"""
import argparse, atexit, base64, datetime, io, json, os, plistlib, re, shutil, subprocess, sys, tempfile, threading, time, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "img"
SCREEN_PT = (402, 874)  # the iPhone 18 Pro's screen in points
K = 3  # captures and the bezel bitmap are 3x
SAFE = {"top": 62, "bottom": 34, "left": 0, "right": 0}
SCALE = 0.4  # of the 3x bezel: sharp at the README's ~200 px per phone on a 2x screen
PAD = 24
LABELS = {  # name: (the label's pill, the line under it), drawn under the phone (crops get none)
    "apps": ("Apps", "your apps and their updates"),
    "install": ("Install", "apps that bring their files"), "settings": ("Settings", "this iPhone's status"),
    "manage": ("Manage", "the admin's menu"), "iphones": ("iPhones", "switch one off any time"),
    "signing": ("Signing", "certificate and API key"), "passwords": ("Passwords", "change who gets in"),
    "invites": ("Invite Friends", "a link for one iPhone"), "files": ("Files", "share files with everyone"),
    "sources": ("App Sources", "mirror AltStore sources"),
}
font_file = lambda pattern: subprocess.run(["fc-match", "-f", "%{file}", pattern], capture_output=True, text=True, check=True).stdout  # Noto Sans
UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 27_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/27.0 "
      "Mobile/15E148 Safari/604.1")
IPHONE = dict(viewport={"width": SCREEN_PT[0], "height": SCREEN_PT[1]}, device_scale_factor=K, is_mobile=True, has_touch=True,
              user_agent=UA)

ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
ap.add_argument("--kit", type=Path, default=Path.home() / "repos/iFizBox/ref/apple-ios27/Apple iOS 27 UI Kit.sketch")
ap.add_argument("--finish", default="Black", choices=["Black", "Silver", "Glacier", "Burgundy"])
ap.add_argument("--plain", action="store_true", help="no phone: the screen with rounded corners only")
ap.add_argument("--setup", type=Path, help=argparse.SUPPRESS)  # internal: shoot the setup splash into this folder
ARGS = ap.parse_args()


# ============================================================ framing (from the kit, in memory)

def framing():
    """Pillow's imports and the framing functions, loaded only when needed (the capture process doesn't need them)."""
    from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont
    STATUS_SYMBOL = "Status Bars/iPhone 18 Pro/Dark Background"
    HOME_SYMBOL = "Home Indicators/Portrait - Dark - iPhone"
    SCREEN_RADIUS_PT, CROP_RADIUS_PT, SS = 55, 12, 4  # SS: supersampling for the vector status bar

    class Kit:
        def __init__(self, path):
            self.zip = zipfile.ZipFile(path)
            self.symbols = {}
            for name in self.zip.namelist():
                if name.startswith("pages/") and name.endswith(".json"):
                    self._collect(json.loads(self.zip.read(name)))
            self.doc = json.loads(self.zip.read("document.json"))

        def _collect(self, layer):
            if layer.get("_class") == "symbolMaster":
                self.symbols.setdefault(layer.get("name", ""), layer)
            for child in layer.get("layers") or []:
                self._collect(child)

        def symbol(self, name):
            if name not in self.symbols:
                sys.exit(f"readme_shots: the kit has no symbol {name!r}")
            return self.symbols[name]

        def bezel(self, finish):
            """The bezel bitmap (3x, see-through screen, Dynamic Island in it) and its offset from the screen in points."""
            sym = self.symbol(f"Bezels/iPhone 18 Pro/{finish} - Portrait")
            bmp = next(l for l in sym["layers"] if l["_class"] == "bitmap")
            ref = bmp["image"]["_ref"]
            img = Image.open(io.BytesIO(self.zip.read(ref if "." in ref.rsplit("/", 1)[-1] else ref + ".png"))).convert("RGBA")
            f = bmp["frame"]
            if (round(f["width"]) * K, round(f["height"]) * K) != img.size:
                sys.exit(f"readme_shots: {bmp['name']} is {img.size}, not 3x its {f['width']}x{f['height']} frame")
            return img, (f["x"], f["y"])

        def font(self, family, style, size):
            for f in self.doc.get("fontReferences", []):
                if f.get("fontFamilyName") == family and "fontData" in f:
                    font = ImageFont.truetype(io.BytesIO(self.zip.read(f["fontData"]["_ref"])), round(size * K * SS))
                    try:
                        font.set_variation_by_name(style)
                    except (OSError, ValueError):
                        pass
                    return font
            sys.exit(f"readme_shots: the kit has no embedded {family}")

    def pt(s):
        x, y = (float(v) for v in re.findall(r"-?[\d.e+-]+", s))
        return x, y

    def cubic(p0, c1, c2, p1, n=16):
        out = []
        for i in range(1, n + 1):
            t = i / n
            a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t * t, t ** 3
            out.append((a * p0[0] + b * c1[0] + c * c2[0] + d * p1[0], a * p0[1] + b * c1[1] + c * c2[1] + d * p1[1]))
        return out

    def path_polygon(layer, ox, oy, scale):
        """A shapePath's outline in pixels: its points are fractions of its frame."""
        f = layer["frame"]
        x0, y0, w, h = ox + f["x"], oy + f["y"], f["width"], f["height"]
        pts = layer.get("points", [])
        to = lambda p: ((x0 + p[0] * w) * scale, (y0 + p[1] * h) * scale)
        poly = [to(pt(pts[0]["point"]))]
        for i in range(len(pts) if layer.get("isClosed", True) else len(pts) - 1):
            a, b = pts[i], pts[(i + 1) % len(pts)]
            pa, pb = pt(a["point"]), pt(b["point"])
            if a.get("hasCurveFrom") or b.get("hasCurveTo"):
                c1 = pt(a["curveFrom"]) if a.get("hasCurveFrom") else pa
                c2 = pt(b["curveTo"]) if b.get("hasCurveTo") else pb
                poly += [to(p) for p in cubic(pa, c1, c2, pb)]
            else:
                poly.append(to(pb))
        return poly

    def draw_layer(draw, layer, ox, oy, scale):
        cls, f = layer.get("_class"), layer.get("frame", {})
        if layer.get("isVisible") is False or layer.get("name") == "Dynamic Island":  # the bezel has the island
            return
        if cls == "rectangle":
            r = (layer.get("points") or [{}])[0].get("cornerRadius", 0) or layer.get("fixedRadius", 0) or 0
            draw.rounded_rectangle([(ox + f["x"]) * scale, (oy + f["y"]) * scale, (ox + f["x"] + f["width"]) * scale,
                                    (oy + f["y"] + f["height"]) * scale], radius=r * scale, fill=255)
        elif cls == "shapePath":
            draw.polygon(path_polygon(layer, ox, oy, scale), fill=255)
        elif cls in ("group", "shapeGroup"):
            for child in layer.get("layers") or []:
                draw_layer(draw, child, ox + f["x"], oy + f["y"], scale)

    def white(mask):
        out = Image.new("RGBA", mask.size, (255, 255, 255, 0))
        out.putalpha(mask)
        return out

    def status_bar(kit):
        """The kit's 18 Pro status bar (time, cellular, wifi, battery), white on transparent, 402x62 points at 3x."""
        sym = kit.symbol(STATUS_SYMBOL)
        w, h, s = round(sym["frame"]["width"]), round(sym["frame"]["height"]), K * SS
        layer = Image.new("L", (w * s, h * s), 0)
        d = ImageDraw.Draw(layer)
        for child in sym["layers"]:
            draw_layer(d, child, 0, 0, s)

        def texts(l, ox, oy):
            for c in l.get("layers") or []:
                f = c["frame"]
                if c["_class"] == "text":
                    yield c, ox + f["x"], oy + f["y"]
                else:
                    yield from texts(c, ox + f["x"], oy + f["y"])
        for t, x, y in texts(sym, 0, 0):  # the Time, centred in its frame on one line
            attrs = t["attributedString"]["attributes"][0]["attributes"]
            desc = attrs["MSAttributedStringFontAttribute"]["attributes"]
            font = kit.font("SF Pro", desc["name"].split("-", 1)[-1], desc["size"])
            line = attrs.get("paragraphStyle", {}).get("maximumLineHeight") or t["frame"]["height"]
            ascent, descent = font.getmetrics()
            d.text(((x + t["frame"]["width"] / 2) * s, y * s + (line * s + ascent - descent) / 2),
                   t["attributedString"]["string"], font=font, fill=255, anchor="ms")
        return white(layer.resize((w * K, h * K), Image.LANCZOS))

    def home_indicator(kit):
        sym = kit.symbol(HOME_SYMBOL)
        rect = sym["layers"][0]["frame"]
        w, h, s = round(sym["frame"]["width"]), round(sym["frame"]["height"]), K * SS
        layer = Image.new("L", (w * s, h * s), 0)
        ImageDraw.Draw(layer).rounded_rectangle(
            [rect["x"] * s, rect["y"] * s, (rect["x"] + rect["width"]) * s, (rect["y"] + rect["height"]) * s],
            radius=rect["height"] / 2 * s, fill=255)
        return white(layer.resize((w * K, h * K), Image.LANCZOS))

    def screen_hole(bezel):
        """The bezel's see-through screen, grown a little under its soft inner edge so no gap shows."""
        clear = bezel.getchannel("A").point(lambda a: 255 if a < 128 else 0)
        ImageDraw.floodfill(clear, (bezel.width // 2, bezel.height // 2), 128)
        return clear.point(lambda v: 255 if v == 128 else 0).filter(ImageFilter.MaxFilter(5))

    def sheen(size, opacity=0.2):
        """A soft diagonal glare from the top right, fading out downwards (the bezel has none of its own)."""
        w, h = size
        shape = Image.new("L", size, 0)
        ImageDraw.Draw(shape).polygon([(w * 0.42, 0), (w, 0), (w, h * 0.8)], fill=255)
        shape = shape.filter(ImageFilter.GaussianBlur(w * 0.01))
        full, clear = 0.2, 0.55
        fade = Image.linear_gradient("L").resize(size).point(
            lambda v: round(255 * max(0.0, min(1.0, (clear - v / 255) / (clear - full)))))
        return white(ImageChops.multiply(shape, fade).point(lambda v: round(v * opacity)))

    def rounded(img, radius):
        mask = Image.new("L", (img.width * 2, img.height * 2), 0)
        ImageDraw.Draw(mask).rounded_rectangle([0, 0, mask.width - 1, mask.height - 1], radius=radius * 2, fill=255)
        out = img.convert("RGBA")
        out.putalpha(ImageChops.multiply(out.getchannel("A"), mask.resize(img.size, Image.LANCZOS)))
        return out

    def scaled(img):
        return img.resize((round(img.width * SCALE), round(img.height * SCALE)), Image.LANCZOS)

    def phone(src, dst, kit, finish):
        shot = Image.open(src).convert("RGBA")
        want = (SCREEN_PT[0] * K, SCREEN_PT[1] * K)
        if shot.size != want:
            sys.exit(f"readme_shots: {src} is {shot.size}, not the 18 Pro screen {want}")
        if kit:
            shot.alpha_composite(status_bar(kit), (0, 0))
            hi = home_indicator(kit)
            shot.alpha_composite(hi, ((want[0] - hi.width) // 2, want[1] - hi.height))
            bezel, (ox, oy) = kit.bezel(finish)
            at = (round(-ox * K), round(-oy * K))
            under = Image.new("RGBA", bezel.size, (0, 0, 0, 0))
            under.paste(shot, at)
            under.alpha_composite(sheen(shot.size), at)
            img = Image.new("RGBA", bezel.size, (0, 0, 0, 0))
            img.paste(under, (0, 0), ImageChops.multiply(screen_hole(bezel), under.getchannel("A")))
            img.alpha_composite(bezel)
        else:
            img = rounded(shot, SCREEN_RADIUS_PT * K)
        img = scaled(img)
        lab = label(*LABELS[src.stem], img.width + 2 * PAD) if src.stem in LABELS else None
        out = Image.new("RGBA", (img.width + 2 * PAD, img.height + (lab.height if lab else 0)), (0, 0, 0, 0))
        out.alpha_composite(img, (PAD, 0))
        if lab:
            out.alpha_composite(lab, (0, img.height))
        out.save(dst, optimize=True)
        print(f"wrote {dst} {out.width}x{out.height} {dst.stat().st_size // 1024} KB")

    def label(title, sub, width):
        """The caption under a phone, drawn into the PNG so it always sits under its own phone at the same size (a
        Markdown table sizes its columns by caption length). It has to read on GitHub's white and its near-black
        alike, so no plain dark text: the name in white on a SideDrop-amber pill, the line under it in a grey
        between the two backgrounds. Noto Sans (free to publish), sized for ~200 px per phone in the README."""
        lab = Image.new("RGBA", (width * SS, 150 * SS), (0, 0, 0, 0))  # drawn 4x, scaled down: smooth pill edges
        d, cx = ImageDraw.Draw(lab), width * SS // 2
        big = ImageFont.truetype(font_file("Noto Sans:bold"), 40 * SS)
        tw = d.textlength(title, font=big)
        top, ph = 18 * SS, 60 * SS
        pill = Image.new("RGBA", (int(tw + 52 * SS), ph))
        grad = Image.linear_gradient("L").resize(pill.size)  # amber, lighter at the top, as the icon's
        pill = Image.composite(Image.new("RGBA", pill.size, (184, 90, 7, 255)), Image.new("RGBA", pill.size, (232, 134, 36, 255)), grad)
        mask = Image.new("L", pill.size, 0)
        ImageDraw.Draw(mask).rounded_rectangle((0, 0, pill.width - 1, ph - 1), ph // 2, fill=255)
        lab.paste(pill, (cx - pill.width // 2, top), mask)
        d.text((cx, top + ph // 2), title, font=big, fill=(255, 255, 255, 255), anchor="mm")
        d.text((cx, top + ph + 34 * SS), sub, font=ImageFont.truetype(font_file("Noto Sans"), 30 * SS), fill=(140, 149, 159, 255), anchor="mm")
        return lab.resize((width, 150), Image.LANCZOS)

    def crop(src, dst):
        img = rounded(scaled(Image.open(src).convert("RGBA")), CROP_RADIUS_PT * K * SCALE)
        img.save(dst, optimize=True)
        print(f"wrote {dst} {img.width}x{img.height} {dst.stat().st_size // 1024} KB")

    return Kit, phone, crop


# ============================================================ capture

for k in ("PASSWORD", "ADMIN_PASSWORD", "BUNDLE_ID", "ASC_KEY_ID", "ASC_ISSUER_ID", "P12_PASSWORD", "SECRET_KEY", "SIDEDROP_COMMIT",
          "SYNC_TOKEN", "PROFILE_CERT_DIR"):
    os.environ.pop(k, None)
tmp = Path(tempfile.mkdtemp(prefix="sidedrop-shots-"))  # TMPDIR moves it
atexit.register(shutil.rmtree, tmp, True)  # gone on success, error or exit
os.environ.update(DATA=str(tmp), PUBLIC_URL="https://sidedrop.example.com")
if not ARGS.setup:
    os.environ.update(PASSWORD="demo-friends-pass", ADMIN_PASSWORD="demo-admin-pass", SECRET_KEY="d" * 32, BUNDLE_ID="com.example.sideload",
                      ASC_KEY_ID="DEMOKEY123", ASC_ISSUER_ID="00000000-0000-0000-0000-000000000000", P12_PASSWORD="demo")
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)  # the repo's ifizbox-sources.txt and friends

start, threading.Thread.start = threading.Thread.start, lambda self: None  # no background source sync at import
import app as A
threading.Thread.start, A.SOURCES = start, []
A.COMMIT = "a1b2c3d"


def serve():
    from werkzeug.serving import make_server
    srv = make_server("127.0.0.1", 0, A.app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://localhost:{srv.server_port}"


def browse(p):
    browser = p.chromium.launch(executable_path=os.environ.get("CHROMIUM", "/usr/bin/chromium"))
    ctx = browser.new_context(**IPHONE)
    ctx.add_init_script("try{localStorage.pushAsked=1}catch(e){}")  # no notifications prompt over the shots
    pg = ctx.new_page()
    ctx.new_cdp_session(pg).send("Emulation.setSafeAreaInsetsOverride", {"insets": SAFE})
    return browser, pg


def shot(page, raw, name):
    page.wait_for_timeout(700)  # tab and fold animations
    page.screenshot(path=str(raw / f"{name}.png"))


def part(page, raw, name, selectors, margin=8, across=None):
    """A crop of the page: the union of the selectors' boxes (the first scrolled into view), `margin` points around.
    `across`: a selector whose width the crop takes too (a card cut top and bottom, still with its sides)."""
    page.evaluate("s=>document.querySelector(s).scrollIntoView({block:'center'})", selectors[0])
    page.wait_for_timeout(400)
    boxes = [page.locator(s).first.bounding_box() for s in selectors]
    if across:
        b, y = page.locator(across).first.bounding_box(), boxes[0]["y"]
        boxes.append(dict(x=b["x"], y=y, width=b["width"], height=1))
    x0, y0 = min(b["x"] for b in boxes) - margin, min(b["y"] for b in boxes) - margin
    x1, y1 = max(b["x"] + b["width"] for b in boxes) + margin, max(b["y"] + b["height"] for b in boxes) + margin
    x0, y0, x1, y1 = max(0, x0), max(0, y0), min(SCREEN_PT[0], x1), min(SCREEN_PT[1], y1)
    page.screenshot(path=str(raw / f"crop-{name}.png"), clip=dict(x=x0, y=y0, width=x1 - x0, height=y1 - y0))


if ARGS.setup:  # a new server: nothing in .env, so the default password opens the setup splash
    from playwright.sync_api import sync_playwright
    srv, BASE = serve()
    with sync_playwright() as p:
        browser, pg = browse(p)
        pg.goto(f"{BASE}/?password={A.DEFAULT_PASSWORD}")
        assert pg.url.endswith("/setup"), pg.url
        pg.wait_for_timeout(700)
        # the form filled in, as on a new server: two passwords, the key (a made-up file name) and its IDs
        pg.fill("input[name=password]", "demo-friends-pass")
        pg.fill("input[name=admin_password]", "demo-admin-pass")
        pg.set_input_files("#keyf", files=[{"name": "AuthKey_DEMOKEY123.p8", "mimeType": "application/octet-stream", "buffer": b"demo"}])
        pg.fill("input[name=asc_issuer_id]", "00000000-0000-0000-0000-000000000000")
        pg.fill("input[name=bundle_id]", "com.example.sideload")
        pg.evaluate("document.activeElement.blur()")
        part(pg, ARGS.setup, "setup", ["label:has(input[name=password])", "label:has(input[name=bundle_id])"], across="form.setup")
        browser.close()
    srv.shutdown()
    sys.exit()

Kit, phone, crop = framing()
kit = None
if ARGS.kit.exists():
    kit = Kit(ARGS.kit)
elif not ARGS.plain:
    sys.exit(f"readme_shots: no iOS 27 UI Kit at {ARGS.kit}: pass --kit PATH, or --plain for no phone")

# --- a fake Apple Distribution certificate (self-signed, made up holder and team) ---
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = datetime.datetime.now(datetime.timezone.utc)
subj = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Apple Distribution: Demo Developer (DEMO123456)"),
                  x509.NameAttribute(x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME, "DEMO123456")])
cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key()).serial_number(7)
        .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=330)).sign(key, hashes.SHA256()))
A.P12.write_bytes(pkcs12.serialize_key_and_certificates(b"demo", key, cert, None, serialization.BestAvailableEncryption(b"demo")))
A.ASC_KEY.write_text("demo, never used: Apple's API is stubbed")
A.cert_status = A.cert_status_cached = lambda *a, **k: []  # no OCSP or Apple checks; the fake cert would trip them

# --- demo devices: what App Store Connect would list ---
UDID = "00008120-000DEMO0DEMO0001"
days_ago = lambda d: (now - datetime.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
DEVICES = [{"id": f"DEV{i}", "attributes": dict(name=n, model=m, udid=u, status=s, addedDate=days_ago(a), deviceClass="IPHONE")}
           for i, (n, m, u, s, a) in enumerate([
               ("Demo iPhone iPhone18,1", "iPhone 18 Pro", UDID, "ENABLED", 40),
               ("Alex iPhone16,1", "iPhone 15 Pro", "00008130-000DEMO0DEMO0002", "ENABLED", 21),
               ("Jordan iPhone17,3", "iPhone 16", "00008140-000DEMO0DEMO0003", "ENABLED", 9),
               ("Sam iPhone15,4", "iPhone 15", "00008120-000DEMO0DEMO0005", "ENABLED", 2),
               ("Old test phone", "iPhone 12", "00008101-000DEMO0DEMO0004", "DISABLED", 120)])]


def fake_asc(method, path, **kw):
    return {"data": DEVICES if path == "/devices" else []}


def fake_regen():
    A.PROFILE.write_bytes(plistlib.dumps({"ProvisionedDevices": [d["attributes"]["udid"] for d in DEVICES if d["attributes"]["status"] == "ENABLED"],
                                          "ExpirationDate": now + datetime.timedelta(days=330),
                                          "Entitlements": {"application-identifier": "DEMO123456.com.example.sideload"}}))


A.asc, A.regen_profile = fake_asc, fake_regen
A.sign_ipa = lambda src, out: shutil.copyfile(src, out)
A.save_json(A.DEVICES, {"at": time.time(), "data": DEVICES})
fake_regen()

# --- demo apps: tiny IPAs with an Info.plist, icons as inline SVG ---
ICON = lambda c1, c2, glyph: "data:image/svg+xml;base64," + base64.b64encode(f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 60 60">
<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient></defs>
<rect width="60" height="60" fill="url(#g)"/><text x="30" y="41" font-size="30" text-anchor="middle" fill="#fff" font-family="Helvetica, Arial, sans-serif"
 font-weight="bold">{glyph}</text></svg>""".encode()).decode()
ifz_png = Path.home() / "repos/iFizBox/web/app/icons/icon-glossy-152.png"  # iFizBox's public icon, if a checkout is beside this one
APPS = [  # name, bundle id, title, version, days ago, icon, description, third-party title
    ("com.ryha.ifizbox", "com.ryha.ifizbox", "iFizBox", "2.4", 2,
     "data:image/png;base64," + base64.b64encode(ifz_png.read_bytes()).decode() if ifz_png.exists() else ICON("#5aa0f0", "#1a62c0", "i"), "", ""),
    ("Notepad", "com.example.notepad", "Notepad", "3.1", 0, ICON("#ffd54a", "#e6a700", "N"), "Plain text notes that sync over iCloud Drive.", ""),
    ("PocketSynth", "com.example.synth", "Pocket Synth", "1.8", 0, ICON("#b36cf0", "#6a2bb5", "♪"), "A four-voice synth with a step sequencer.", ""),
    ("Trailhead", "com.example.trailhead", "Trailhead", "5.0", 3, ICON("#5cc35c", "#2a8a2a", "▲"), "Offline maps for hiking.", ""),
    ("RetroArcade", "com.example.retro", "Retro Arcade", "0.9.4", 6, ICON("#ff7a59", "#d23a1e", "★"), "Plays your own homebrew game files.", ""),
    ("Podcatch", "org.example.podcatch", "Podcatch", "2.2", 12, ICON("#ff5e8a", "#c2185b", "P"), "An open-source podcast player.", "Podcatch"),
]
A.APPS.mkdir()
for name, bid, title, ver, ago, icon, desc, third in APPS:
    with zipfile.ZipFile(A.APPS / f"{name}.ipa", "w") as z:
        z.writestr(f"Payload/{name}.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": bid, "CFBundleVersion": ver,
                                                                       "CFBundleShortVersionString": ver, "CFBundleName": title}))
    (A.APPS / f".{name}.icon").write_text(icon)
    (A.APPS / f".{name}.date").write_text((datetime.date.today() - datetime.timedelta(days=ago)).isoformat())
    (A.APPS / f".{name}.source").write_text("Example Source" if third else "SideDrop")
    if desc:
        (A.APPS / f".{name}.desc").write_text(desc)
    if third:
        (A.APPS / f".{name}.third").write_text(third)
(A.APP_FILES / "RetroArcade").mkdir(parents=True)  # an app with a file to download beside it
(A.APP_FILES / "RetroArcade" / "homebrew-pack.zip").write_bytes(b"\0" * 3_400_000)
(A.APP_FILES / "RetroArcade" / "labels.txt").write_text("homebrew-pack.zip = the homebrew pack\n")
A.FILES.mkdir()
(A.FILES / "Setup guide.pdf").write_bytes(b"%PDF-1.4 demo\n" * 1000)
# the source lists App Sources edits: made-up sources (Manage's edits in data/config win over the repo's files)
A.CONFIG.mkdir(exist_ok=True)
(A.CONFIG / "mirror-sources.txt").write_text("https://ifizbox.com/source.json\nhttps://github.com/example/notepad/releases/latest/download/altstore-source.json\n"
                                             "https://apps.example.com/source.json\n")
(A.CONFIG / "third-party-sources.txt").write_text("# Other people's apps: a source URL, then the bundle IDs to take from it (none = all its apps)\n"
                                                  "https://altstore.example.org/apps.json org.example.podcatch\n")
# invites: one used by Sam's iPhone, one expired; the screenshot makes a new one for Casey
t = time.time()
A.save_json(A.INVITES, {"demoUsedInvite0001": {"name": "Sam", "made": t - 3 * 86400, "exp": t + 4 * 86400, "udid": DEVICES[3]["attributes"]["udid"],
                                              "device": "iPhone 15", "used": t - 2 * 86400},
                        "demoExpiredInvite01": {"name": "Riley", "made": t - 10 * 86400, "exp": t - 3 * 86400}})
# the demo iPhone: installed an older Trailhead (so its Apps row shows an update), seen today, through the first-install splash
A.save_json(A.INSTALLED, {UDID: {"Notepad": "3.1/3.1", "Trailhead": "4.2/4.2"}})
A.save_json(A.SEEN, {UDID: time.time() - 3600, DEVICES[1]["attributes"]["udid"]: time.time() - 2 * 86400,
                     DEVICES[3]["attributes"]["udid"]: time.time() - 5 * 3600})
A.save_json(A.FIRST_RUN, {UDID: time.time()})
A.save_product(UDID, "iPhone18,1")

# A fake upload for Files for Friends: XMLHttpRequest reports part of each file sent and never finishes.
FAKE_UPLOADS = """(()=>{let n=0,P=[62,18];window.FormData=function(){this.append=()=>{}};
window.XMLHttpRequest=function(){let p=P[n++%P.length];this.upload={};this.open=()=>{};this.abort=()=>{};
 this.send=()=>setTimeout(()=>this.upload.onprogress&&this.upload.onprogress({total:100,loaded:p}),50)};
upAdd({form:{dataset:{csrf:"x"}},files:[{name:"Trailhead maps (Alps).zip",size:734003200},{name:"Retro Arcade homebrew pack 2.zip",size:268435456}],value:""})})()"""

raw = tmp / "raw"
raw.mkdir()
srv, BASE = serve()
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser, pg = browse(p)
    pg.goto(f"{BASE}/?password=demo-admin-pass")  # the admin's sign-in, so Settings shows Manage
    pg.goto(f"{BASE}/?enrolled={A.device_token(UDID)}")  # the 301 after the profile install: sets the device cookie
    pg.goto(f"{BASE}/#apps")
    pg.evaluate("scr.scrollTop+=document.querySelector('#t-apps .row.up').getBoundingClientRect().top-520")  # Trailhead's update in view
    shot(pg, raw, "apps")
    pg.click("button.get[data-app=RetroArcade]")  # an app with a file: GET opens its install steps
    pg.evaluate("scr.scrollTop+=document.querySelector('button.get[data-app=RetroArcade]').getBoundingClientRect().top-330")
    shot(pg, raw, "install")
    pg.goto(f"{BASE}/#settings")
    shot(pg, raw, "settings")
    for path, name in [("/admin", "manage"), ("/admin/iphones", "iphones"), ("/admin/signing", "signing"),
                       ("/admin/passwords", "passwords"), ("/admin/sources", "sources")]:
        pg.goto(BASE + path)
        pg.wait_for_load_state("networkidle")
        shot(pg, raw, name)
    pg.goto(BASE + "/admin/sources")
    pg.wait_for_load_state("networkidle")
    part(pg, raw, "sources", ["form.c"])
    pg.goto(BASE + "/admin/signing")
    pg.wait_for_load_state("networkidle")
    part(pg, raw, "signing", ["h3.hdr", "div.g"])  # the certificate and the App ID (BUNDLE_ID)
    pg.goto(BASE + "/admin/invites")
    pg.fill("input[name=name]", "Casey")
    pg.click("text=New One-iPhone Link")
    pg.wait_for_load_state("networkidle")
    pg.evaluate("(document.getElementById('scr')||document.scrollingElement).scrollTop=document.querySelector('p.done').getBoundingClientRect().top-185")
    shot(pg, raw, "invites")
    pg.goto(BASE + "/admin/files")
    pg.wait_for_load_state("networkidle")
    pg.evaluate(FAKE_UPLOADS)
    shot(pg, raw, "files")
    browser.close()
srv.shutdown()
subprocess.run([sys.executable, __file__, "--setup", str(raw)], check=True)

OUT.mkdir(parents=True, exist_ok=True)
for src in sorted(raw.glob("*.png")):
    if src.name.startswith("crop-"):
        crop(src, OUT / src.name)
    else:
        phone(src, OUT / src.name, kit, ARGS.finish)
