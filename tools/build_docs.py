#!/usr/bin/env python3
"""Threat Model documents for an item, in Hebrew and English, as DOCX and PDF.

python3 tools/build_docs.py <ID>
Inputs:  items/<ID>/item.json (Hebrew, source of truth for structure and scores) + items/<ID>/doc-en.json (English text by id)
Outputs: items/<ID>/threat-model-{he,en}.{docx,pdf} and items/<ID>/dfd-{he,en}.png (diagram captured from the page)
One block model feeds both renderers: DOCX via python-docx (Arial, RTL only where Hebrew), PDF via Chrome from HTML with kit fonts.
"""
import json, re, sys, html, pathlib
from playwright.sync_api import sync_playwright
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHROME = "/usr/bin/google-chrome"
HEB = re.compile(r"[֐-׿]")
# Latin runs inside Hebrew text: a parenthesised Latin group as one unit, or a Latin/number run without parentheses.
# Splitting with a capture group gives [rtl, ltr, rtl, ltr, ...].
LATIN = re.compile(r"(\([A-Za-z0-9][^()֐-׿]*\)|[A-Za-z0-9][A-Za-z0-9 .,&$%/:'’\-–×#]*[A-Za-z0-9%])")
CATS_EN = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
CATS_HE = {"S": "התחזות", "T": "שיבוש", "R": "הכחשה", "I": "חשיפת מידע", "D": "מניעת שירות", "E": "הסלמת הרשאות"}

HE = {
    "sections": {"meta": "פרטי המסמך", "summary": "תקציר", "context": "רקע", "scope": "היקף", "inScope": "בתוך ההיקף", "outScope": "מחוץ להיקף",
                 "model": "מודל המערכת", "components": "רכיבים", "flows": "זרימות נתונים", "boundaries": "גבולות אמון", "assets": "נכסים",
                 "threats": "איומים (STRIDE לכל רכיב)", "tree": "עץ תקיפה לאיום המרכזי", "risk": "סיכון לפני ואחרי ההגנות",
                 "mitigations": "הגנות", "residual": "סיכון שיורי", "attack": "מיפוי ל-MITRE ATT&CK", "takeaways": "מה לקחתי מזה",
                 "glossary": "נספח: מונחים", "claims": "עובדות וטענות"},
    "labels": {"system": "מערכת", "method": "שיטה", "status": "סטטוס", "date": "תאריך המקור", "id": "פריט", "id_col": "מזהה", "name": "שם", "type": "סוג",
               "zone": "גבול", "desc": "תיאור", "from": "מ-", "to": "אל", "flow": "זרימה", "owner": "בעלים", "value": "חשיבות", "why": "למה זה חשוב",
               "loss": "אם הוא אובד", "cat": "STRIDE", "component": "רכיב", "threat": "איום", "evidence": "בסיס בדיווח", "l": "ס", "i": "ה",
               "risk": "סיכון", "controls": "הגנות", "before": "לפני", "after": "אחרי", "note": "הערה", "covers": "מכסה", "limit": "מגבלה",
               "source": "מקור", "technique": "טכניקה", "where": "איפה זה מופיע", "gateOr": "או", "gateAnd": "וגם", "legal": "חוקי היום", "term": "מונח",
               "levels": {"5": "קריטי", "4": "גבוה", "3": "בינוני", "2": "נמוך-בינוני", "1": "נמוך"},
               "diagram": "איור 1. דיאגרמת זרימת נתונים עם גבולות אמון. זרימות אדומות מקווקוות הן חשד, לא עובדה."},
    "kinds": {"entity": "ישות חיצונית", "process": "תהליך", "store": "מאגר נתונים"},
    "types": {"prevent": "מניעה", "detect": "זיהוי", "respond": "תגובה"},
    "sources": {"report": "מוזכר בדיווח", "ours": "הצעה שלנו"},
    "status": "ניתוח לימודי · טיוטה לדיון",
    "method": "STRIDE לכל רכיב על דיאגרמת זרימת נתונים, עץ תקיפה לאיום המרכזי, מטריצת סבירות והשפעה 5×5",
}


def plain(s):
    """Strip site markup: [[id|label]] -> label, [[id]] -> id's term handled by caller, **x** stays for rich runs."""
    return re.sub(r"\[\[[a-z0-9\-]+\|([^\]]+)\]\]", r"\1", s or "")


def level(l, i):
    x = l * i
    return 5 if x >= 15 else 4 if x >= 10 else 3 if x >= 6 else 2 if x >= 3 else 1


def model(it, en, lang):
    """Return (title, subtitle, blocks) for one language."""
    he = lang == "he"
    gl = it["glossary"]

    def R(s):
        s = s or ""
        s = re.sub(r"\[\[([a-z0-9\-]+)\]\]", lambda m: gl[m.group(1)]["term"], s)
        return plain(s)
    L = HE["labels"] if he else en["labels"]
    S = HE["sections"] if he else en["sections"]
    kinds = HE["kinds"] if he else en["kinds"]
    types = HE["types"] if he else en["types"]
    srcs = HE["sources"] if he else en["sources"]
    cats = CATS_HE if he else CATS_EN
    nodes = {n["id"]: n for n in it["dfd"]["nodes"]}
    bnames = {b["id"]: b["label"] for b in it["dfd"]["boundaries"]}

    def nl(nid): return nodes[nid]["label"] if he else en["nodes"][nid]["label"]
    def lv(l, i): return L["levels"][str(level(l, i))]

    B = []
    title = it["title"] if he else en["title"]
    sub = it["subtitle"] if he else en["subtitle"]
    B.append(("table", [L["system"], ""], [
        [L["id"], it["id"]],
        [L["system"], R(it["facts"][0]["v"]) if he else en["facts"][0]["v"]],
        [L["method"], HE["method"] if he else en["method"]],
        [L["status"], HE["status"] if he else en["status"]],
        [L["date"], "14 בנובמבר 2026" if he else "14 November 2026"],
    ], {"kv": True}))
    B.append(("note", R(it["defensiveNote"]) if he else en["defensiveNote"].replace("Defensive only.", "**Defensive only.**", 1)))
    B.append(("h2", S["summary"]))
    if he:
        B.append(("p", "המשטר שומר על גבול אמון אחד: הגבול של המדינה המוגבלת. הבדיקות שלו סופרות חומרה ומסמכים. המודל מוצא " + str(len(it["threats"])) +
                  " איומים בכל שש הקטגוריות של STRIDE. את מסלול ההסטה הפיזית אפשר לסגור בכמה דרכים, כי כל אות זיהוי חזק לבד (ביקורת פתע עצמאית, אימות מיקום מהשבב, ניתוח נתוני סחר) שובר אותו. מסלול ההשכרה מרחוק שונה: החומרה לא זזה, כל הספירות נשארות נכונות, ורק חובת הכרת לקוח לשוכרי כוח חישוב מטפלת בו. הצעות החוק שבדיווח מכסות הסטה, לא השכרה. הרכיב עם הכי הרבה איומים הוא לא שרת אלא ההנהלה הבכירה, שם קשר אישי עם מנהלת אצל לקוח (שנבדק עכשיו כחשד למאמץ מודיעיני) מבטל את הפרדת התפקידים."))
    else:
        B.append(("p", en["summary"]))
    top = sorted(it["threats"], key=lambda t: -(t["l"] * t["i"]))[:4]
    B.append(("bullets", [f"**{t['id']}** · {t['title'] if he else en['threats'][t['id']]['title']} ({lv(t['l'], t['i'])}, {t['l']}×{t['i']})" for t in top]))
    B.append(("h2", S["context"]))
    for p in (it["minute"] if he else en["minute"]):
        B.append(("p", R(p)))
    B.append(("note", "**" + S["claims"] + ".** " + (R(it["claimsNote"]).replace("**עובדות וטענות.** ", "") if he else en["claimsNote"])))
    B.append(("h2", S["scope"]))
    sc = it["scope"] if he else en["scope"]
    B.append(("h3", S["inScope"])); B.append(("bullets", sc["in"]))
    B.append(("h3", S["outScope"])); B.append(("bullets", sc["out"]))

    B.append(("h2", S["model"]))
    B.append(("img", f"dfd-{lang}.png", L["diagram"]))
    B.append(("h3", S["boundaries"]))
    B.append(("bullets", [(bnames[b["id"]] if he else en["boundaries"][b["id"]]) for b in it["dfd"]["boundaries"]]))
    B.append(("h3", S["components"]))
    B.append(("table", [L["id_col"], L["name"], L["type"], L["zone"], L["desc"]],
              [[n["id"], nl(n["id"]), kinds[n["kind"]], bnames[n["zone"]] if he else en["boundaries"][n["zone"]],
                R(n["desc"]) if he else en["nodes"][n["id"]]["desc"]] for n in it["dfd"]["nodes"]], {"w": [1.2, 3, 2.4, 3, 8]}))
    B.append(("h3", S["flows"]))
    B.append(("table", ["#", L["from"], L["to"], L["flow"]],
              [[str(k + 1), nl(f["from"]), nl(f["to"]), R(f["label"]) if he else en["flows"][f["id"]]] for k, f in enumerate(it["dfd"]["flows"])], {"w": [1, 4, 4, 8]}))

    B.append(("h2", S["assets"]))
    B.append(("table", [L["id_col"], L["name"], L["owner"], L["value"], L["why"], L["loss"]],
              [[a["id"], a["name"] if he else en["assets"][a["id"]]["name"], R(a["owner"]) if he else en["assets"][a["id"]]["owner"],
                "●" * a["value"] + "○" * (3 - a["value"]), R(a["why"]) if he else en["assets"][a["id"]]["why"],
                R(a["loss"]) if he else en["assets"][a["id"]]["loss"]] for a in it["assets"]["items"]], {"w": [1.1, 3, 2.6, 1.6, 4.5, 4.5]}))

    B.append(("h2", S["threats"]))
    B.append(("p", ("ס = סבירות, ה = השפעה, כל אחת מ-1 עד 5. הציונים הם הערכה שלנו על בסיס הדיווח." if he else
                    "L = likelihood, I = impact, each 1-5. Scores are our estimate based on the reporting.")))
    for t in it["threats"]:
        tx = en["threats"][t["id"]] if not he else None
        B.append(("h3", f"{t['id']} · {t['cat']} ({cats[t['cat']]}) · {t['title'] if he else tx['title']}"))
        B.append(("p", f"**{L['component']}:** {nl(t['node'])} · **{L['risk']}:** {lv(t['l'], t['i'])} ({L['l']}{t['l']}×{L['i']}{t['i']}) · **{L['controls']}:** {', '.join(t['mits'])}"))
        B.append(("p", R(t["desc"]) if he else tx["desc"]))
        ev = R(t["evidence"]) + (f" ({t['claim']})" if t.get("claim") else "") if he else tx["evidence"]
        B.append(("p", f"**{L['evidence']}:** {ev}", {"muted": True}))
    B.append(("h3", "סיכום" if he else "Summary table"))
    B.append(("table", [L["id_col"], L["cat"], L["component"], L["threat"], L["risk"], L["controls"]],
              [[t["id"], t["cat"], nl(t["node"]), t["title"] if he else en["threats"][t["id"]]["title"], f"{lv(t['l'], t['i'])} ({t['l']}×{t['i']})", " ".join(t["mits"])]
               for t in it["threats"]], {"w": [1.1, 1.3, 3, 6.4, 3, 2.6]}))

    B.append(("h2", S["tree"]))
    B.append(("p", R(it["tree"]["intro"]) if he else "Root: the adversary's goal. Under OR any child suffices; under AND all children are needed. Controls that block each leaf are in brackets."))
    lines = []

    def walk(n, d):
        lab = R(n["label"]).replace("**", "") if he else en["tree"][n["id"]]
        gate = ""
        if n.get("children"):
            gate = f"[{L['gateAnd'] if n['gate'] == 'AND' else L['gateOr']}] "
        ms = f"  ({', '.join(n['mits'])})" if n.get("mits") else ""
        legal = f"  ({L['legal']})" if n.get("legal") and he else ""
        lines.append(("  " * d) + ("• " if d else "") + gate + lab + ms + legal)
        for c in n.get("children", []):
            walk(c, d + 1)
    walk(it["tree"]["root"], 0)
    B.append(("tree", lines))
    B.append(("note", R(it["tree"]["insight"]) if he else "**What the tree shows.** " + en["tree"]["insight"]))

    B.append(("h2", S["risk"]))
    B.append(("table", [L["id_col"], L["threat"], L["before"], L["after"], L["note"]],
              [[t["id"], t["title"] if he else en["threats"][t["id"]]["title"], f"{lv(t['l'], t['i'])} ({t['l']}×{t['i']})",
                f"{lv(t['res']['l'], t['res']['i'])} ({t['res']['l']}×{t['res']['i']})",
                (R(t.get("resNote", "")) if he else en["resNotes"].get(t["id"], ""))] for t in it["threats"]], {"w": [1.1, 5, 2.6, 2.6, 6]}))
    hi_b = sum(1 for t in it["threats"] if t["l"] * t["i"] >= 10)
    hi_a = sum(1 for t in it["threats"] if t["res"]["l"] * t["res"]["i"] >= 10)
    B.append(("p", (f"איומים בדרגת גבוה וקריטי: {hi_b} לפני ההגנות, {hi_a} אחריהן." if he else
                    f"Threats rated high or critical: {hi_b} before controls, {hi_a} after.")))

    B.append(("h2", S["mitigations"]))
    for m in it["mitigations"]["items"]:
        mx = en["mitigations"][m["id"]] if not he else None
        cov = [t["id"] for t in it["threats"] if m["id"] in t["mits"]]
        B.append(("h3", f"{m['id']} · {R(m['name']) if he else mx['name']}"))
        B.append(("p", f"**{L['type']}:** {types[m['type']]} · **{L['source']}:** {srcs['ours' if m['source'] == 'ours' else 'report']} · **{L['owner']}:** {R(m['owner']) if he else mx['owner']} · **{L['covers']}:** {', '.join(cov)}"))
        B.append(("p", R(m["desc"]) if he else mx["desc"]))
        B.append(("p", f"**{L['limit']}:** {R(m['limit']) if he else mx['limit']}", {"muted": True}))
    rule = it["mitigations"]["rule"]
    B.append(("h3", R(rule["title"]) if he else en["ruleTitle"]))
    B.append(("p", R(rule["intro"]) if he else en["ruleIntro"]))
    B.append(("code", rule["code"]))
    B.append(("p", R(rule["note"]) if he else en["ruleNote"], {"muted": True}))
    B.append(("h2", S["residual"]))
    B.append(("p", R(it["mitigations"]["residual"]) if he else en["residual"]))

    B.append(("h2", S["attack"]))
    B.append(("p", R(it["attack"]["intro"]) if he else en["attack"]["intro"]))
    B.append(("table", [L["technique"], L["where"], L["threat"]],
              [[f"{a['id']} {a['name']}", R(a["where"]) if he else en["attack"][a["id"]], ", ".join(a["threats"])] for a in it["attack"]["items"]], {"w": [5.5, 9, 2.5]}))
    B.append(("note", R(it["attack"]["caveat"]) if he else en["attack"]["caveat"]))

    B.append(("h2", S["takeaways"]))
    tks = it["takeaways"] if he else en["takeaways"]
    B.append(("bullets", [f"**{t['kind']}.** {R(t['text'])}" for t in tks]))

    B.append(("h2", S["glossary"]))
    B.append(("table", [L["term"], L["desc"]],
              [[f"{g['term']} · {g['en']}" if he else g["en"], R(g["def"]) if he else en["glossary"][k]] for k, g in it["glossary"].items()], {"w": [5, 12]}))
    B.append(("p", R(it["source"]) if he else en["source"], {"muted": True}))
    return title, sub, B


# ---------------------------------------------------------------- DOCX
def _set(el, tag, **attrs):
    e = el.find(qn(tag))
    if e is None:
        e = OxmlElement(tag); el.append(e)
    for k, v in attrs.items():
        e.set(qn(k), v)
    return e


def runs(par, text, rtl_par, bold=False, size=None, color=None, mono=False):
    """Add text with **bold** markup; Hebrew segments get rtl runs, Latin/number segments stay LTR."""
    for k, chunk in enumerate(re.split(r"\*\*", text)):
        if not chunk:
            continue
        b = bold or (k % 2 == 1)
        segs = LATIN.split(chunk) if rtl_par else [chunk]
        for si, seg in enumerate(segs):
            if not seg:
                continue
            r = par.add_run(seg)
            r.bold = b
            f = r.font
            f.name = "Consolas" if mono else "Arial"
            rpr = r._element.get_or_add_rPr()
            _set(rpr, "w:rFonts", **{"w:ascii": f.name, "w:hAnsi": f.name, "w:cs": "Arial"})
            if size:
                f.size = Pt(size); _set(rpr, "w:szCs", **{"w:val": str(int(size * 2))})
            if color:
                f.color.rgb = RGBColor.from_string(color)
            if b:
                _set(rpr, "w:bCs")
            if rtl_par and si % 2 == 0:
                _set(rpr, "w:rtl")


def para(doc_or_cell, text, rtl, style=None, size=10.5, color=None, bold=False, mono=False, space=4):
    p = doc_or_cell.add_paragraph(style=style) if style else doc_or_cell.add_paragraph()
    if rtl:
        _set(p._p.get_or_add_pPr(), "w:bidi")
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    p.paragraph_format.space_after = Pt(space)
    runs(p, text, rtl, bold=bold, size=size, color=color, mono=mono)
    return p


def shade(cell, hexcolor):
    tcPr = cell._tc.get_or_add_tcPr()
    _set(tcPr, "w:shd", **{"w:val": "clear", "w:color": "auto", "w:fill": hexcolor})


def to_docx(title, sub, blocks, lang, out, item_dir):
    rtl = lang == "he"
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21), Cm(29.7)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Cm(2))
    sec.top_margin = sec.bottom_margin = Cm(1.8)
    st = doc.styles["Normal"]
    st.font.name = "Arial"; st.font.size = Pt(10.5)
    _set(st.element.get_or_add_rPr(), "w:rFonts", **{"w:ascii": "Arial", "w:hAnsi": "Arial", "w:cs": "Arial"})
    for name, size, color in (("Heading 1", 20, "17191E"), ("Heading 2", 14, "0E6F6A"), ("Heading 3", 11.5, "17191E")):
        hs = doc.styles[name]
        hs.font.name = "Arial"; hs.font.size = Pt(size); hs.font.bold = True; hs.font.color.rgb = RGBColor.from_string(color)
        rpr = hs.element.get_or_add_rPr()
        _set(rpr, "w:rFonts", **{"w:ascii": "Arial", "w:hAnsi": "Arial", "w:cs": "Arial"})
        _set(rpr, "w:szCs", **{"w:val": str(int(size * 2))}); _set(rpr, "w:bCs")
        hs.paragraph_format.space_before = Pt(14 if name != "Heading 3" else 10)
    # footer with page number
    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = fp.add_run("Attack Surface · Threat Model · " + ("עמוד " if rtl else "page "))
    r.font.size = Pt(8); r.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
    if rtl: _set(r._element.get_or_add_rPr(), "w:rtl")
    r2 = fp.add_run()
    for t, txt in (("begin", None), (None, "PAGE"), ("end", None)):
        if t:
            fc = OxmlElement("w:fldChar"); fc.set(qn("w:fldCharType"), t); r2._r.append(fc)
        else:
            it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = txt; r2._r.append(it)
    r2.font.size = Pt(8)

    para(doc, "THREAT MODEL · ATTACK SURFACE", False if not rtl else True, size=8.5, color="0E6F6A", bold=True)
    para(doc, title, rtl, style="Heading 1")
    para(doc, sub, rtl, size=11.5, color="565D6A", space=10)
    for b in blocks:
        kind = b[0]
        if kind in ("h2", "h3"):
            para(doc, b[1], rtl, style="Heading 2" if kind == "h2" else "Heading 3")
        elif kind == "p":
            muted = len(b) > 2 and b[2].get("muted")
            para(doc, b[1], rtl, color="565D6A" if muted else None, size=9.5 if muted else 10.5)
        elif kind == "note":
            t = doc.add_table(rows=1, cols=1)
            if rtl: _set(t._tbl.tblPr, "w:bidiVisual")
            c = t.rows[0].cells[0]; shade(c, "EAF4F3")
            c.paragraphs[0]._p.getparent().remove(c.paragraphs[0]._p)
            para(c, b[1], rtl, size=9.5, space=2)
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        elif kind == "bullets":
            for x in b[1]:
                p = para(doc, x, rtl, style="List Bullet", space=2)
        elif kind == "tree":
            for line in b[1]:
                d = (len(line) - len(line.lstrip(" "))) // 2
                p = para(doc, line.strip(), rtl, size=10, space=1)
                p.paragraph_format.left_indent = None
                if rtl: p.paragraph_format.right_indent = Cm(0.7 * d)
                else: p.paragraph_format.left_indent = Cm(0.7 * d)
        elif kind == "code":
            t = doc.add_table(rows=1, cols=1)
            c = t.rows[0].cells[0]; shade(c, "F2F3F5")
            c.paragraphs[0]._p.getparent().remove(c.paragraphs[0]._p)
            for line in b[1].split("\n"):
                p = para(c, line or " ", False, size=7.5, mono=True, space=0)
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        elif kind == "img":
            p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.add_run().add_picture(str(item_dir / b[1]), width=Cm(17))
            para(doc, b[2], rtl, size=8.5, color="565D6A")
        elif kind == "table":
            heads, rows, opt = b[1], b[2], b[3]
            kv = opt.get("kv")
            t = doc.add_table(rows=0 if kv else 1, cols=len(heads))
            t.style = "Table Grid"; t.alignment = WD_TABLE_ALIGNMENT.CENTER
            if rtl: _set(t._tbl.tblPr, "w:bidiVisual")
            if not kv:
                for k, hd in enumerate(heads):
                    c = t.rows[0].cells[k]; shade(c, "E9EEF0")
                    c.paragraphs[0]._p.getparent().remove(c.paragraphs[0]._p)
                    para(c, hd, rtl and bool(HEB.search(hd)), size=8.5, bold=True, space=0)
                    if rtl: c.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
            for row in rows:
                cells = t.add_row().cells
                for k, val in enumerate(row):
                    c = cells[k]
                    c.paragraphs[0]._p.getparent().remove(c.paragraphs[0]._p)
                    has_he = bool(HEB.search(str(val)))
                    p = para(c, str(val), rtl and has_he, size=8.5, bold=kv and k == 0, space=0)
                    if rtl: p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
                    if kv and k == 0: shade(c, "E9EEF0")
            if opt.get("w") or kv:
                ws = opt.get("w") or [4, 13]
                tot = sum(ws)
                t.autofit = False
                tw = [int(17 * 567 * w / tot) for w in ws]          # twips
                for k, gc in enumerate(t._tbl.tblGrid.findall(qn("w:gridCol"))):
                    gc.set(qn("w:w"), str(tw[k]))
                _set(t._tbl.tblPr, "w:tblLayout", **{"w:type": "fixed"})
                for row in t.rows:
                    for k, c in enumerate(row.cells):
                        c.width = Cm(17 * ws[k] / tot)
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
    doc.core_properties.title = title
    doc.core_properties.author = "Attack Surface (Desk)"
    doc.save(str(out))


# ---------------------------------------------------------------- PDF


def inline(s):
    """Escape once, bold **x**, isolate Latin runs inside Hebrew text with <bdi> (so 'ATT&CK', 'T1199' keep their order)."""
    he = bool(HEB.search(s))
    out = []
    for k, chunk in enumerate(re.split(r"\*\*", s)):
        parts = LATIN.split(chunk) if he else [chunk]
        h = "".join((f"<bdi>{html.escape(p, quote=False)}</bdi>" if (he and i % 2) else html.escape(p, quote=False)) for i, p in enumerate(parts))
        out.append(f"<b>{h}</b>" if k % 2 else h)
    return "".join(out)


def to_html(title, sub, blocks, lang):
    rtl = lang == "he"
    out = []
    for b in blocks:
        k = b[0]
        if k == "h2": out.append(f"<h2>{inline(b[1])}</h2>")
        elif k == "h3": out.append(f"<h3>{inline(b[1])}</h3>")
        elif k == "p": out.append(f"<p class='{'muted' if len(b) > 2 and b[2].get('muted') else ''}'>{inline(b[1])}</p>")
        elif k == "note": out.append(f"<div class='note'>{inline(b[1])}</div>")
        elif k == "bullets": out.append("<ul>" + "".join(f"<li>{inline(x)}</li>" for x in b[1]) + "</ul>")
        elif k == "tree":
            out.append("<div class='tree'>" + "".join(
                f"<div style='padding-inline-start:{(len(l) - len(l.lstrip(' '))) // 2 * 18}px'>{inline(l.strip())}</div>" for l in b[1]) + "</div>")
        elif k == "code": out.append(f"<pre>{html.escape(b[1])}</pre>")
        elif k == "img": out.append(f"<figure><img src='{b[1]}'><figcaption>{inline(b[2])}</figcaption></figure>")
        elif k == "table":
            heads, rows, opt = b[1], b[2], b[3]
            cls = "kv" if opt.get("kv") else ""
            hrow = "" if opt.get("kv") else "<thead><tr>" + "".join(f"<th>{inline(h)}</th>" for h in heads) + "</tr></thead>"
            cols = ""
            if opt.get("w"):
                tot = sum(opt["w"]); cols = "<colgroup>" + "".join(f"<col style='width:{w / tot * 100:.1f}%'>" for w in opt["w"]) + "</colgroup>"
            body = "".join("<tr>" + "".join(f"<td>{inline(str(c))}</td>" for c in r) + "</tr>" for r in rows)
            out.append(f"<table class='{cls}'>{cols}{hrow}<tbody>{body}</tbody></table>")
    css = """
    @page{size:A4;margin:16mm 16mm 18mm}
    body{font-family:Heebo,Arial,sans-serif;font-size:10pt;line-height:1.55;color:#17191e}
    .kick{font:600 8pt 'IBM Plex Mono',monospace;letter-spacing:.08em;color:#0e6f6a}
    h1{font-family:'Frank Ruhl Libre',serif;font-size:22pt;line-height:1.2;margin:4px 0 6px}
    .sub{font-size:11.5pt;color:#565d6a;margin:0 0 14px}
    h2{font-family:'Frank Ruhl Libre',serif;font-size:14pt;color:#0e6f6a;margin:18px 0 6px;border-bottom:1px solid #d7dde0;padding-bottom:3px;break-after:avoid}
    h3{font-size:10.5pt;margin:12px 0 3px;break-after:avoid}
    p{margin:0 0 6px} .muted{color:#565d6a;font-size:9pt}
    ul{margin:0 0 8px;padding-inline-start:18px} li{margin-bottom:2px}
    .note{background:#eaf4f3;border-inline-start:3px solid #0e6f6a;padding:8px 10px;margin:8px 0;font-size:9pt;break-inside:avoid}
    table{width:100%;border-collapse:collapse;margin:6px 0 10px;font-size:8.3pt;break-inside:auto}
    th,td{border:1px solid #d7dde0;padding:4px 6px;vertical-align:top;text-align:start}
    th{background:#e9eef0;font-weight:700} tr{break-inside:avoid}
    table.kv td:first-child{background:#e9eef0;font-weight:700;width:24%}
    pre{direction:ltr;text-align:left;background:#f2f3f5;border:1px solid #e1e4e8;border-radius:6px;padding:8px 10px;font:7.6pt/1.45 'IBM Plex Mono',monospace;white-space:pre-wrap;break-inside:avoid}
    figure{margin:8px 0 12px;text-align:center} figure img{width:100%;border:1px solid #e1e4e8;border-radius:6px}
    figcaption{font-size:8.5pt;color:#565d6a;margin-top:4px}
    .tree{font-size:9.3pt;line-height:1.6;margin:6px 0 8px}
    bdi{unicode-bidi:isolate}
    """
    return f"""<!doctype html><html lang="{lang}" dir="{'rtl' if rtl else 'ltr'}"><head><meta charset="utf-8">
<link rel="stylesheet" href="../../kit/fonts.css"><style>{css}</style><title>{html.escape(title)}</title></head><body>
<div class="kick">THREAT MODEL · ATTACK SURFACE</div><h1>{html.escape(title)}</h1><p class="sub">{html.escape(sub)}</p>
{''.join(out)}</body></html>"""


# ---------------------------------------------------------------- diagram capture
def capture_dfd(page, item_id, en):
    url = (ROOT / "items" / item_id / "index.html").as_uri()
    for lang in ("he", "en"):
        page.goto(url)
        page.wait_for_function("document.documentElement.getAttribute('data-ready')==='1'")
        page.wait_for_selector("svg.dfd.wide")
        if lang == "en":
            page.evaluate("""en => {
              const svg = document.querySelector('svg.dfd');
              svg.querySelectorAll('.node').forEach(g => {
                const n = en.nodes[g.getAttribute('data-node')], t = g.querySelectorAll('text:not(.count-t)');
                if (t[0]) { t[0].textContent = n.label; t[0].setAttribute('direction','ltr'); }
                if (t[1]) { t[1].textContent = n.sub; t[1].setAttribute('direction','ltr'); }
              });
              const ids = ['us','transit','customer','restricted'];
              svg.querySelectorAll('.zone text').forEach((t, i) => { t.textContent = en.boundaries[ids[i]]; t.setAttribute('direction','ltr'); t.setAttribute('text-anchor','end'); });
            }""", en)
        page.wait_for_timeout(200)
        page.locator("svg.dfd").screenshot(path=str(ROOT / "items" / item_id / f"dfd-{lang}.png"))


def main(item_id):
    d = ROOT / "items" / item_id
    it = json.loads((d / "item.json").read_text(encoding="utf-8"))
    en = json.loads((d / "doc-en.json").read_text(encoding="utf-8"))
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        ctx = b.new_context(viewport={"width": 1280, "height": 900}, device_scale_factor=2)
        ctx.add_init_script("try{localStorage.setItem('desk-theme','light')}catch(e){}")
        page = ctx.new_page()
        capture_dfd(page, item_id, en)
        for lang in ("he", "en"):
            title, sub, blocks = model(it, en, lang)
            to_docx(title, sub, blocks, lang, d / f"threat-model-{lang}.docx", d)
            hp = d / f"_doc-{lang}.html"
            hp.write_text(to_html(title, sub, blocks, lang), encoding="utf-8")
            page.goto(hp.as_uri()); page.wait_for_timeout(400)
            page.evaluate("document.fonts.ready")
            page.pdf(path=str(d / f"threat-model-{lang}.pdf"), format="A4", print_background=True, display_header_footer=True,
                     header_template="<span></span>",
                     footer_template="<div style='font:7pt Arial;color:#6b7280;width:100%;text-align:center'>Attack Surface · Threat Model · <span class='pageNumber'></span>/<span class='totalPages'></span></div>",
                     margin={"top": "16mm", "bottom": "18mm", "left": "16mm", "right": "16mm"})
            hp.unlink()
            print("doc:", lang)
        b.close()


if __name__ == "__main__":
    main(sys.argv[1])
