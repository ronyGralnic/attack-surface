#!/usr/bin/env python3
"""Open Graph cards (1200x630) from kit/og-template.html.
python3 tools/og.py            -> assets/og.png (site card) + every item
python3 tools/og.py <ID>       -> items/<ID>/og.png only
"""
import json, sys, pathlib
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHROME = "/usr/bin/google-chrome"
ACCENT = "#2ee6a0"
LEVEL = {5: "קריטי", 4: "גבוה", 3: "בינוני", 2: "נמוך-בינוני", 1: "נמוך"}


RISKC = {5: "#ff4d57", 4: "#ff8f40", 3: "#ffcc4d", 2: "#b6e35a", 1: "#2ee6a0"}
CATC = {"S": "#b18cff", "T": "#ffaa45", "R": "#9aa7b4", "I": "#5cc8ff", "D": "#ff5a64", "E": "#ff6fbf"}


def card(page, data, out):
    page.goto((ROOT / "kit" / "og-template.html").as_uri())
    page.evaluate("d => window.fill(d)", data)
    # identity v2: night dossier. Near-black, grid + scanlines, corner brackets, trust-boundary stripe.
    page.add_style_tag(content="""
      body{--bg:#05070a;--ink:#d7e0e6;--muted:#8794a1;--line:#1c2630;
        background:radial-gradient(900px 420px at 90% -10%,rgba(46,230,160,.12),transparent 60%),radial-gradient(700px 380px at 0% 110%,rgba(255,77,87,.10),transparent 60%),
          repeating-linear-gradient(180deg,rgba(255,255,255,.035) 0 1px,transparent 1px 3px),
          linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px) 0 0/40px 40px,linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px) 0 0/40px 40px,#05070a}
      .stripe{height:8px;background:repeating-linear-gradient(-45deg,#ff4d57 0 14px,transparent 14px 28px)}
      .frame{inset:56px 70px 50px}
      .frame::before{content:"";position:absolute;inset:-24px -30px;pointer-events:none;
        background:linear-gradient(#2ee6a0,#2ee6a0) top right/34px 3px no-repeat,linear-gradient(#2ee6a0,#2ee6a0) top right/3px 34px no-repeat,
        linear-gradient(#2ee6a0,#2ee6a0) top left/34px 3px no-repeat,linear-gradient(#2ee6a0,#2ee6a0) top left/3px 34px no-repeat,
        linear-gradient(#2ee6a0,#2ee6a0) bottom right/34px 3px no-repeat,linear-gradient(#2ee6a0,#2ee6a0) bottom right/3px 34px no-repeat,
        linear-gradient(#2ee6a0,#2ee6a0) bottom left/34px 3px no-repeat,linear-gradient(#2ee6a0,#2ee6a0) bottom left/3px 34px no-repeat}
      .top{font-size:21px;letter-spacing:.18em}
      .site{color:#2ee6a0}
      .badge{font-family:Heebo,sans-serif;letter-spacing:0;font-weight:800;border-radius:4px;border-color:var(--rc,#2ee6a0);color:var(--rc,#2ee6a0);box-shadow:0 0 24px color-mix(in srgb,var(--rc,#2ee6a0) 35%,transparent)}
      h1{font:800 70px/1.1 Heebo,Arial,sans-serif;text-shadow:0 0 30px rgba(46,230,160,.12)}
      h1 .hl{color:#2ee6a0}
      .sub{font-size:30px}
      .foot{border-top:1px dashed #2a3742;font-family:'IBM Plex Mono',monospace}
      .foot b{font-weight:700;margin:0 3px}
      #left{font-family:Heebo,Arial,sans-serif;font-size:24px}
    """)
    page.evaluate("""d => {
      if (d.rc) document.body.style.setProperty('--rc', d.rc);
      if (d.cats) document.getElementById('right').innerHTML = d.cats;
      if (d.hl) { const h = document.getElementById('title'); h.innerHTML = h.textContent.replace(d.hl, '<span class="hl">' + d.hl + '</span>'); }
    }""", data)
    page.wait_for_timeout(300)
    page.screenshot(path=str(out))
    print("og:", out.relative_to(ROOT))


def item_data(it):
    l, i = it["risk"]["l"], it["risk"]["i"]
    x = l * i
    n = 5 if x >= 15 else 4 if x >= 10 else 3 if x >= 6 else 2 if x >= 3 else 1
    have = {t["cat"] for t in it["threats"]}
    cats = " ".join("<b style='color:%s'>%s</b>" % (CATC[c] if c in have else "#2a3742", c) for c in "STRIDE")
    return {"site": f"CASE FILE · TM-{it['id']}", "badge": "סיכון " + LEVEL[n], "title": it["title"], "rc": RISKC[n],
            "sub": it["summary"], "left": f"{len(it['threats'])} איומים · {len(it['mitigations']['items'])} הגנות · {it['country']}", "right": "STRIDE", "cats": cats, "accent": ACCENT}


def main():
    ids = sys.argv[1:]
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = b.new_page(viewport={"width": 1200, "height": 630})
        if not ids:
            card(page, {"site": "ATTACK SURFACE · CASE FILES", "badge": "הגנתי בלבד", "title": "כל מערכת היא משטח תקיפה.",
                        "sub": "מודלים של איומים על מערכות מתוך החדשות: דיאגרמה, STRIDE, עץ תקיפה, מטריצת סיכון והגנות.",
                        "left": "TLP:CLEAR · defensive only", "right": "ronygralnic.github.io/attack-surface", "accent": ACCENT, "hl": "משטח תקיפה."}, ROOT / "assets" / "og.png")
            ids = [q.parent.name for q in (ROOT / "items").glob("*/item.json")]
        for i in ids:
            it = json.loads((ROOT / "items" / i / "item.json").read_text(encoding="utf-8"))
            card(page, item_data(it), ROOT / "items" / i / "og.png")
        b.close()


if __name__ == "__main__":
    main()
