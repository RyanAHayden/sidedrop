"""B15: run Copy Link's script in headless Chromium: copies the box's own link over a stale clipboard, row COPY too, and says
Not Copied (never Copied) when both the copy event and writeText fail."""
import pathlib, sys
from playwright.sync_api import sync_playwright

here = pathlib.Path(__file__).parent
script = (here / "copy.js.html").read_text()
html = f"""<!doctype html><body>
<div id=box data-link="https://x.test/invite/NEW"><input class=lnk readonly value="https://x.test/invite/NEW">
<div class=lbtn><button id=b1 type=button onclick="lnkCopy(this)">Copy Link</button><button class=shr>Share</button></div></div>
<div class=g><div id=row class=row data-link="https://x.test/invite/ROW"><div>x</div><div class=lbtn><button id=b2 class=act type=button onclick="lnkCopy(this)">COPY</button></div></div></div>
{script}"""
(here / "page.html").write_text(html)
with sync_playwright() as p:
    br = p.chromium.launch(executable_path="/usr/bin/chromium")
    ctx = br.new_context(permissions=["clipboard-read", "clipboard-write"])
    pg = ctx.new_page(); pg.goto((here / "page.html").as_uri())
    clip = lambda: pg.evaluate("navigator.clipboard.readText()")
    pg.evaluate("navigator.clipboard.writeText('https://x.test/invite/ULHMz-OLD')")
    assert clip().endswith("OLD")
    pg.click("#b1"); assert clip() == "https://x.test/invite/NEW" and pg.text_content("#b1") == "Copied", (clip(), pg.text_content("#b1"))
    pg.click("#b2"); assert clip() == "https://x.test/invite/ROW" and pg.text_content("#b2") == "COPIED"
    # copy event path only (no writeText)
    pg.evaluate("navigator.clipboard.writeText('stale')"); pg.evaluate("Object.defineProperty(navigator,'clipboard',{value:undefined,configurable:true})")
    pg.click("#b1"); assert pg.text_content("#b1") == "Copied"
    # both fail: execCommand does nothing, writeText rejects -> Not Copied, link selected in an editable box
    pg.evaluate("document.execCommand=()=>true;Object.defineProperty(navigator,'clipboard',{value:{writeText:()=>Promise.reject(1)},configurable:true})")
    pg.click("#b1"); pg.wait_for_timeout(100)
    assert pg.text_content("#b1") == "Not Copied", pg.text_content("#b1")
    assert pg.evaluate("document.activeElement.className=='lnk'&&!document.activeElement.readOnly&&document.activeElement.selectionEnd==document.activeElement.value.length")
    pg.click("#b2"); pg.wait_for_timeout(100)
    assert pg.text_content("#b2") == "NOT COPIED" and pg.evaluate("document.querySelector('#row').nextElementSibling.value") == "https://x.test/invite/ROW"
    pg.click("#b2"); pg.wait_for_timeout(100); assert pg.evaluate("document.querySelectorAll('.g .lnk').length") == 1
    pg.wait_for_timeout(2100); assert pg.text_content("#b2") == "COPY" and pg.text_content("#b1") == "Copy Link"
    br.close()
print("copy ok")
