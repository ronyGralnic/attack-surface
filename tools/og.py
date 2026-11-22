#!/usr/bin/env python3
"""Open Graph cards (1200x630) from kit/og-template.html.
python3 tools/og.py            -> assets/og.png (site card) + every item
python3 tools/og.py <ID>       -> items/<ID>/og.png only
"""
import json, sys, pathlib
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHROME = "/usr/bin/google-chrome"
ACCENT = "#3fd0c0"
LEVEL = {5: "קריטי", 4: "גבוה", 3: "בינוני", 2: "נמוך-בינוני", 1: "נמוך"}


def card(page, data, out):
    page.goto((ROOT / "kit" / "og-template.html").as_uri())
    page.evaluate("d => window.fill(d)", data)
    # identity: dashed trust boundary frame + blueprint dots
    page.add_style_tag(content="""
      body{background-image:radial-gradient(rgba(236,238,241,.07) 1.2px,transparent 1.4px);background-size:24px 24px}
      .frame::before{content:"";position:absolute;inset:-22px -30px;border:2px dashed #ff7b6e;border-radius:22px;pointer-events:none}
      h1{font-size:66px}
      .badge{font-family:Heebo,sans-serif;letter-spacing:0;font-weight:700}
    """)
    page.wait_for_timeout(300)
    page.screenshot(path=str(out))
    print("og:", out.relative_to(ROOT))


def item_data(it):
    l, i = it["risk"]["l"], it["risk"]["i"]
    x = l * i
    n = 5 if x >= 15 else 4 if x >= 10 else 3 if x >= 6 else 2 if x >= 3 else 1
    have = {t["cat"] for t in it["threats"]}
    cats = " · ".join(c if c in have else "–" for c in "STRIDE")
    return {"site": "ATTACK SURFACE · THREAT MODEL", "badge": "סיכון " + LEVEL[n], "title": it["title"],
            "sub": it["summary"], "left": f"{len(it['threats'])} איומים · {it['country']}", "right": cats, "accent": ACCENT}


def main():
    ids = sys.argv[1:]
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        page = b.new_page(viewport={"width": 1200, "height": 630})
        if not ids:
            card(page, {"site": "ATTACK SURFACE", "badge": "הגנתי בלבד", "title": "כל מערכת היא משטח תקיפה.",
                        "sub": "מודלים של איומים על מערכות מתוך החדשות: דיאגרמה, STRIDE, עץ תקיפה, מטריצת סיכון והגנות.",
                        "left": "Desk", "right": "ronygralnic.github.io/attack-surface", "accent": ACCENT}, ROOT / "assets" / "og.png")
            ids = [q.parent.name for q in (ROOT / "items").glob("*/item.json")]
        for i in ids:
            it = json.loads((ROOT / "items" / i / "item.json").read_text(encoding="utf-8"))
            card(page, item_data(it), ROOT / "items" / i / "og.png")
        b.close()


if __name__ == "__main__":
    main()
