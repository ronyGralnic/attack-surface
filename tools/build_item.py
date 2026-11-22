#!/usr/bin/env python3
"""Build an item: items/<ID>/item.json -> data.js + index.html, and rebuild items/index.json + items/data.js.

Usage: python3 tools/build_item.py <ID>        (or --all)
The JSON is the source. data.js files are generated so pages work from file:// (no fetch). Never edit data.js by hand.
"""
import json, sys, html, pathlib, re

ROOT = pathlib.Path(__file__).resolve().parent.parent
ITEMS = ROOT / "items"
CATS = "STRIDE"
LEVELS = [(15, 5, "קריטי"), (10, 4, "גבוה"), (6, 3, "בינוני"), (3, 2, "נמוך-בינוני"), (0, 1, "נמוך")]


def level(l, i):
    x = l * i
    for th, n, he in LEVELS:
        if x >= th:
            return n, he


def validate(it):
    errs = []
    nodes = {n["id"] for n in it["dfd"]["nodes"]}
    mits = {m["id"] for m in it["mitigations"]["items"]}
    tids = set()
    for f in it["dfd"]["flows"]:
        if f["from"] not in nodes or f["to"] not in nodes:
            errs.append(f"flow {f['id']} has unknown node")
    for mode, L in it["dfd"]["layouts"].items():
        for n in nodes:
            if n not in L["nodes"]:
                errs.append(f"layout {mode} missing node {n}")
    for t in it["threats"]:
        tids.add(t["id"])
        if t["cat"] not in CATS: errs.append(f"threat {t['id']} bad cat")
        if t["node"] not in nodes: errs.append(f"threat {t['id']} unknown node")
        for m in t["mits"]:
            if m not in mits: errs.append(f"threat {t['id']} unknown mitigation {m}")
        for k in ("l", "i"):
            if not 1 <= t[k] <= 5 or not 1 <= t["res"][k] <= 5: errs.append(f"threat {t['id']} score out of range")
    for a in it["attack"]["items"]:
        for t in a["threats"]:
            if t not in tids: errs.append(f"attack {a['id']} unknown threat {t}")
    # glossary references
    blob = json.dumps(it, ensure_ascii=False)
    for ref in set(re.findall(r"\[\[([a-z0-9\-]+)", blob)):
        if ref not in it["glossary"]: errs.append(f"missing glossary term {ref}")

    def walk(n):
        for m in n.get("mits", []):
            if m not in mits: errs.append(f"tree {n['id']} unknown mitigation {m}")
        for c in n.get("children", []): walk(c)
    walk(it["tree"]["root"])
    # one quote, under 15 words
    q = it.get("quote")
    if q and len(q["text"].split()) >= 15: errs.append("quote too long")
    if "כתבה" in blob: errs.append('the word "כתבה" is not allowed')
    return errs


def entry(it):
    cats = {}
    for t in it["threats"]:
        cats[t["cat"]] = cats.get(t["cat"], 0) + 1
    n, he = level(it["risk"]["l"], it["risk"]["i"])
    return {
        "id": it["id"], "issue": it["issue"], "title": it["title"], "subtitle": it["subtitle"], "summary": it["summary"],
        "region": it["region"], "country": it.get("country"), "domain": it["domain"], "tags": it.get("tags", []),
        "risk": {"l": it["risk"]["l"], "i": it["risk"]["i"], "n": n, "label": "סיכון " + he},
        "threatCount": len(it["threats"]), "cats": {c: cats[c] for c in CATS if c in cats},
        "keyMetric": it.get("keyMetric"), "og": f"items/{it['id']}/og.png",
    }


def build(item_id):
    d = ITEMS / item_id
    it = json.loads((d / "item.json").read_text(encoding="utf-8"))
    errs = validate(it)
    if errs:
        print("\n".join("ERROR: " + e for e in errs)); sys.exit(1)
    (d / "data.js").write_text("/* generated from item.json by tools/build_item.py, do not edit */\nwindow.DESK_ITEM = "
                               + json.dumps(it, ensure_ascii=False) + ";\n", encoding="utf-8")
    tpl = (ROOT / "tools" / "item-template.html").read_text(encoding="utf-8")
    page = (tpl.replace("{{ID}}", it["id"]).replace("{{TITLE}}", html.escape(it["title"]))
               .replace("{{SUMMARY}}", html.escape(it["summary"])))
    (d / "index.html").write_text(page, encoding="utf-8")
    print("built", item_id)


def rebuild_index():
    items = []
    for p in sorted(ITEMS.glob("*/item.json")):
        items.append(entry(json.loads(p.read_text(encoding="utf-8"))))
    items.sort(key=lambda e: (e["issue"], e["id"]), reverse=True)
    idx = {"site": "attack-surface", "format": "TM", "items": items}
    (ITEMS / "index.json").write_text(json.dumps(idx, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (ITEMS / "data.js").write_text("/* generated from items/index.json by tools/build_item.py, do not edit */\nwindow.DESK_INDEX = "
                                   + json.dumps(idx, ensure_ascii=False) + ";\n", encoding="utf-8")
    print("index:", len(items), "items")


if __name__ == "__main__":
    args = sys.argv[1:]
    ids = [p.parent.name for p in ITEMS.glob("*/item.json")] if (not args or args[0] == "--all") else args
    for i in ids:
        build(i)
    rebuild_index()
