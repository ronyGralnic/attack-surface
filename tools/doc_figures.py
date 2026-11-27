"""Figures for the Threat Model documents. One HTML page per language; each <figure id=...> is screenshotted
to items/<ID>/fig-<name>-<lang>.png by build_docs.py. Print palette (light), no dependencies, inline SVG/CSS.

Figures: kpi (metric strip), stride (threats per category + per component), heat (before/after 5x5 heat maps),
burn (per-threat risk reduction, dumbbell), tree (attack tree with the minimal blocking set), cover (controls x threats).
"""
import html, re
from itertools import combinations

ACC, BND, INK, INK2, LINE = "#0b6b46", "#b3261e", "#16140f", "#5b5347", "#d8d2c4"
CAT = {"S": "#6235c9", "T": "#a85400", "R": "#4b5563", "I": "#1b5a9e", "D": "#b3261e", "E": "#b0185f"}
RISK = {1: "#2b7a3d", 2: "#6f8a1f", 3: "#a86d00", 4: "#c2410c", 5: "#b3261e"}
CAT_HE = {"S": "התחזות", "T": "שיבוש", "R": "הכחשה", "I": "חשיפת מידע", "D": "מניעת שירות", "E": "הסלמת הרשאות"}
CAT_EN = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Info. disclosure", "D": "Denial of service", "E": "Elevation of privilege"}
E = html.escape


def level(l, i):
    x = l * i
    return 5 if x >= 15 else 4 if x >= 10 else 3 if x >= 6 else 2 if x >= 3 else 1


def plain(s):
    s = re.sub(r"\[\[[a-z0-9\-]+\|([^\]]+)\]\]", r"\1", s or "")
    return s.replace("**", "")


def blocked(n, on):
    if n.get("children"):
        r = [blocked(c, on) for c in n["children"]]
        return any(r) if n["gate"] == "AND" else all(r)
    return any(m in on for m in n.get("mits", []))


def tree_mits(n, acc=None):
    acc = [] if acc is None else acc
    for m in n.get("mits", []):
        if m not in acc:
            acc.append(m)
    for c in n.get("children", []):
        tree_mits(c, acc)
    return acc


def min_cut(root):
    ms = tree_mits(root)
    for k in range(1, len(ms) + 1):
        for combo in combinations(ms, k):
            if blocked(root, set(combo)):
                return list(combo)
    return []


def stats(it):
    T = it["threats"]
    return {
        "threats": len(T),
        "nodes": len(it["dfd"]["nodes"]),
        "hot_nodes": len({t["node"] for t in T}),
        "bounds": len(it["dfd"]["boundaries"]),
        "controls": len(it["mitigations"]["items"]),
        "ours": sum(1 for m in it["mitigations"]["items"] if m["source"] == "ours"),
        "hi_b": sum(1 for t in T if t["l"] * t["i"] >= 10),
        "hi_a": sum(1 for t in T if t["res"]["l"] * t["res"]["i"] >= 10),
        "sum_b": sum(t["l"] * t["i"] for t in T),
        "sum_a": sum(t["res"]["l"] * t["res"]["i"] for t in T),
        "cut": min_cut(it["tree"]["root"]),
    }


def page(it, en, lang):
    he = lang == "he"
    T = it["threats"]
    st = stats(it)
    tl = (lambda t: t["title"]) if he else (lambda t: en["threats"][t["id"]]["title"])
    nl = (lambda nid: next(n["label"] for n in it["dfd"]["nodes"] if n["id"] == nid)) if he else (lambda nid: en["nodes"][nid]["label"])
    figs = []

    # ---- KPI strip
    red = round(100 * (st["sum_b"] - st["sum_a"]) / st["sum_b"]) if st["sum_b"] else 0
    k = [
        (str(st["threats"]), "איומים שזוהו" if he else "threats identified", f"{st['hot_nodes']}/{st['nodes']} " + ("רכיבים מושפעים" if he else "components affected")),
        (str(st["bounds"]), "גבולות אמון" if he else "trust boundaries", f"{len(it['dfd']['flows'])} " + ("זרימות נתונים" if he else "data flows")),
        (f"{st['hi_b']} → {st['hi_a']}", "גבוה וקריטי" if he else "high + critical", "לפני ← אחרי ההגנות" if he else "before → after controls"),
        (f"−{red}%", "סכום הסיכון" if he else "aggregate risk", f"{st['sum_b']} → {st['sum_a']} " + ("נקודות" if he else "points")),
        (str(st["controls"]), "הגנות" if he else "controls", f"{st['ours']} " + ("הצעה שלנו" if he else "proposed by us")),
        (" + ".join(st["cut"]), "חסימה מינימלית" if he else "minimal blocking set", "סוגרת את כל העץ" if he else "closes every attack path"),
    ]
    tiles = "".join(f"<div class='kp'><b dir='ltr'>{E(v)}</b><span>{E(a)}</span><small>{E(s)}</small></div>" for v, a, s in k)
    figs.append(("kpi", f"<div class='kpis'>{tiles}</div>"))

    # ---- STRIDE distribution + per component (HTML bars: direction-safe in both languages)
    cnt = {c: sum(1 for t in T if t["cat"] == c) for c in "STRIDE"}
    mx = max(cnt.values()) or 1
    left = "".join(f"<div class='br'><span class='bl'>{c} · {E(CAT_HE[c] if he else CAT_EN[c])}</span><span class='bt'><i style='width:{100 * cnt[c] / mx:.0f}%;background:{CAT[c]}'></i></span><b>{cnt[c]}</b></div>" for c in "STRIDE")
    comp = {}
    for t in T:
        comp.setdefault(t["node"], []).append(t)
    order = sorted(comp, key=lambda n: -len(comp[n]))
    mc = max(len(v) for v in comp.values())
    right = ""
    for nid in order:
        segs = "".join(f"<i style='width:{100 / mc:.1f}%;background:{CAT[t['cat']]}'>{t['cat']}</i>" for t in sorted(comp[nid], key=lambda t: "STRIDE".index(t["cat"])))
        right += f"<div class='br'><span class='bl'>{E(nl(nid))}</span><span class='bt stack'>{segs}</span><b>{len(comp[nid])}</b></div>"
    figs.append(("stride", f"<div class='two'><div><h4>{'איומים לפי קטגוריה' if he else 'Threats by STRIDE category'}</h4>{left}</div>"
                           f"<div><h4>{'איומים לפי רכיב' if he else 'Threats by component'}</h4>{right}</div></div>"))

    # ---- heat maps (LTR axes in both languages: likelihood grows to the right)
    def heat(title, pos):
        cs, g0x, g0y = 52, 40, 34
        out = f"<text x='{g0x + cs * 2.5}' y='18' text-anchor='middle' class='tt'>{E(title)}</text>"
        cells = {}
        for t in T:
            p = pos(t)
            cells.setdefault((p[0], p[1]), []).append(t)
        for imp in range(5, 0, -1):
            for lik in range(1, 6):
                x = g0x + (lik - 1) * cs
                y = g0y + (5 - imp) * cs
                lv = level(lik, imp)
                out += f"<rect x='{x}' y='{y}' width='{cs - 3}' height='{cs - 3}' rx='3' fill='{RISK[lv]}' fill-opacity='.16' stroke='{RISK[lv]}' stroke-opacity='.35'/>"
                ts = cells.get((lik, imp), [])
                for j, t in enumerate(ts[:6]):
                    cx = x + 4 + (j % 2) * 23
                    cy = y + 4 + (j // 2) * 15
                    out += f"<rect x='{cx}' y='{cy}' width='21' height='13' rx='2' fill='#fff' stroke='{CAT[t['cat']]}'/><text x='{cx + 10.5}' y='{cy + 10}' text-anchor='middle' class='chip' fill='{CAT[t['cat']]}'>{t['id']}</text>"
        for n in range(1, 6):
            out += f"<text x='{g0x + (n - 1) * cs + cs / 2 - 1.5}' y='{g0y + 5 * cs + 12}' text-anchor='middle' class='ax'>{n}</text>"
            out += f"<text x='{g0x - 10}' y='{g0y + (5 - n) * cs + cs / 2 + 3}' text-anchor='middle' class='ax'>{n}</text>"
        out += f"<text x='{g0x + cs * 2.5}' y='{g0y + 5 * cs + 28}' text-anchor='middle' class='ax'>{'סבירות →' if he else 'Likelihood →'}</text>"
        out += f"<text x='12' y='{g0y + cs * 2.5}' text-anchor='middle' class='ax' transform='rotate(-90 12 {g0y + cs * 2.5})'>{'השפעה →' if he else 'Impact →'}</text>"
        return out
    hw = 40 + 52 * 5 + 10
    left = heat("לפני ההגנות" if he else "Inherent (before controls)", lambda t: (t["l"], t["i"]))
    right = heat("אחרי ההגנות" if he else "Residual (after controls)", lambda t: (t["res"]["l"], t["res"]["i"]))
    first, second = (left, right) if not he else (right, left)
    legend = "".join(f"<rect x='{20 + i * 120}' y='0' width='12' height='12' rx='2' fill='{RISK[lv]}'/><text x='{36 + i * 120}' y='10' class='ax' text-anchor='start'>{E(n)}</text>"
                     for i, (lv, n) in enumerate([(5, 'קריטי ≥15' if he else 'Critical ≥15'), (4, 'גבוה 10–14' if he else 'High 10–14'), (3, 'בינוני 6–9' if he else 'Medium 6–9'),
                                                  (2, 'נמוך-בינוני 3–5' if he else 'Low-med 3–5'), (1, 'נמוך 1–2' if he else 'Low 1–2')]))
    svg = (f"<svg viewBox='0 0 {hw * 2 + 40} {34 + 52 * 5 + 64}' class='chart' direction='ltr'><g>{first}</g><g transform='translate({hw + 40},0)'>{second}</g>"
           f"<g transform='translate(0,{34 + 52 * 5 + 44})'>{legend}</g></svg>")
    figs.append(("heat", svg))

    # ---- burn-down (dumbbell), HTML rows; the score axis runs left to right in both languages
    rows = sorted(T, key=lambda t: (-(t["l"] * t["i"]), -(t["res"]["l"] * t["res"]["i"])))
    P = lambda v: f"{100 * v / 25:.2f}%"
    grid = "".join(f"<u style='left:{P(v)}'></u>" for v in (6, 10, 15))
    body = ""
    for t in rows:
        bv, av = t["l"] * t["i"], t["res"]["l"] * t["res"]["i"]
        lab = f"{t['id']} · {tl(t)}"
        body += (f"<div class='db'><span class='dl'>{E(lab)}</span><span class='dt' dir='ltr'>{grid}"
                 f"<s style='left:{P(av)};width:{P(bv - av)}'></s>"
                 f"<em class='b' style='left:{P(bv)};background:{RISK[level(t['l'], t['i'])]}' title='{bv}'></em>"
                 f"<em class='a' style='left:{P(av)};border-color:{RISK[level(t['res']['l'], t['res']['i'])]}'></em></span>"
                 f"<span class='dv' dir='ltr'>{bv} → {av}</span></div>")
    axis = "".join(f"<span style='left:{P(v)}'>{v}</span>" for v in (0, 6, 10, 15, 25))
    ttl = ("ציון סיכון (סבירות × השפעה) לכל איום. עיגול מלא: לפני ההגנות. עיגול ריק: אחריהן. קווים: סף בינוני, גבוה וקריטי." if he else
           "Risk score (likelihood × impact) per threat. Filled: before controls. Hollow: after. Lines: medium, high and critical thresholds.")
    figs.append(("burn", f"<h4>{E(ttl)}</h4>{body}<div class='db'><span class='dl'></span><span class='dt ax2' dir='ltr'>{axis}</span><span class='dv'></span></div>"))

    # ---- tree with the minimal cut applied
    cut = set(st["cut"])
    def node(n, d):
        lab = plain(n.get("short") or n["label"]) if he else en["tree"][n["id"]]
        gate = ("AND" if n["gate"] == "AND" else "OR") if n.get("children") else ""
        gl = {"AND": "צריך את כולם" if he else "AND · all needed", "OR": "אחד מספיק" if he else "OR · any one"}.get(gate, "צעד" if he else "step")
        b = blocked(n, cut)
        ms = "".join(f"<i class='m{' on' if m in cut else ''}'>{m}</i>" for m in n.get("mits", []))
        legal = f"<i class='lg'>{'חוקי היום' if he else 'legal today'}</i>" if n.get("legal") else ""
        cls = "tn" + (" root" if d == 0 else "") + (" blk" if b else "")
        box = f"<div class='{cls}'><span class='g {gate.lower() or 'leaf'}'>{E(gl)}</span><span class='lb2'>{E(lab)}</span>{('<span class=ms>' + ms + legal + '</span>') if (ms or legal) else ''}</div>"
        kids = "".join(node(c, d + 1) for c in n.get("children", []))
        return f"<li>{box}{('<ul>' + kids + '</ul>') if kids else ''}</li>"
    cap = (("החסימה המינימלית מופעלת: " if he else "Minimal blocking set applied: ") + " + ".join(st["cut"]) +
           (". צמתים מקווקווים בירוק נחסמים." if he else ". Dashed green nodes are blocked."))
    figs.append(("tree", f"<div class='org' dir='{'rtl' if he else 'ltr'}'><ul>{node(it['tree']['root'], 0)}</ul></div><p class='cap2'>{E(cap)}</p>"))

    # ---- coverage matrix
    head = "".join(f"<th style='color:{CAT[t['cat']]}'>{t['id']}</th>" for t in T)
    body = ""
    for m in it["mitigations"]["items"]:
        name = plain(m.get("short") or m["name"]) if he else en["mitigations"][m["id"]]["name"]
        if len(name) > 46:
            name = name[:45] + "…"
        cells = "".join(f"<td style='background:{CAT[t['cat']]}'></td>" if m["id"] in t["mits"] else "<td></td>" for t in T)
        n = sum(1 for t in T if m["id"] in t["mits"])
        body += f"<tr><th class='mh'><b>{m['id']}</b> {E(name)}</th>{cells}<td class='n'>{n}</td></tr>"
    foot = "".join(f"<td class='n'>{len(t['mits'])}</td>" for t in T)
    figs.append(("cover", f"<table class='cov'><thead><tr><th></th>{head}<th>Σ</th></tr></thead><tbody>{body}<tr><th class='mh'>{'הגנות לכל איום' if he else 'controls per threat'}</th>{foot}<td></td></tr></tbody></table>"))

    css = f"""
    @font-face{{font-family:x}}
    body{{margin:0;background:#fff;color:{INK};font-family:Heebo,Arial,sans-serif;width:760px}}
    figure{{margin:0 0 30px;padding:14px;background:#fff;width:760px;box-sizing:border-box}}
    svg.chart{{width:100%;height:auto;display:block;font-family:Heebo,Arial,sans-serif}}
    .tt{{font-size:13px;font-weight:700;fill:{INK}}} .lb{{font-size:12px;fill:{INK}}} .lb.sm{{font-size:11px}}
    .num{{font:700 12px 'IBM Plex Mono',monospace;fill:{INK}}} .in{{font:700 9px 'IBM Plex Mono',monospace;fill:#fff}}
    .ax{{font-size:10.5px;fill:{INK2}}} .chip{{font:700 8.5px 'IBM Plex Mono',monospace}}
    .kpis{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}}
    .kp{{border:1px solid {LINE};border-top:3px solid {ACC};border-radius:4px;padding:10px 12px;display:flex;flex-direction:column;gap:2px}}
    .kp b{{font:700 22px 'IBM Plex Mono',monospace;color:{ACC}}} .kp span{{font-weight:700;font-size:13px}} .kp small{{font-size:11px;color:{INK2}}}
    .org ul{{list-style:none;margin:0;padding:18px 0 0;display:flex;justify-content:center;position:relative}}
    .org>ul{{padding-top:0}}
    .org li{{position:relative;padding:18px 3px 0;display:flex;flex-direction:column;align-items:center;flex:1 1 0;min-width:0}}
    .org>ul>li{{padding-top:0}}
    .org li::before,.org li::after{{content:"";position:absolute;top:0;width:50%;height:18px;border-top:1.5px solid #b9b09c}}
    .org li::before{{right:50%}} .org li::after{{left:50%;border-left:1.5px solid #b9b09c}}
    .org li:first-child::{'after' if he else 'before'}{{border-top:0}} .org li:last-child::{'before' if he else 'after'}{{border-top:0}}
    .org li:only-child::before{{display:none}} .org li:only-child::after{{border-top:0}}
    .org>ul>li::before,.org>ul>li::after{{display:none}}
    .org ul ul::before{{content:"";position:absolute;top:0;left:50%;height:18px;border-left:1.5px solid #b9b09c}}
    .tn{{width:100%;max-width:170px;box-sizing:border-box;border:1.5px solid {BND};border-radius:4px;padding:6px 5px;text-align:center;font-size:10.5px;line-height:1.3;background:#fff}}
    .tn.root{{max-width:300px;font-size:12px;background:#fbeceb}}
    .tn.blk{{border:1.5px dashed {ACC};background:#eef6f1;color:#46614f}}
    .tn .g{{display:inline-block;font-size:8.5px;font-weight:700;padding:1px 5px;border-radius:2px;margin-bottom:3px}}
    .g.and{{background:#f6e7cf;color:#8a4d00}} .g.or{{background:#dfe8f3;color:#1b5a9e}} .g.leaf{{background:#eee;color:#666}}
    .lb2{{display:block;font-weight:600}}
    .ms{{display:flex;gap:3px;justify-content:center;flex-wrap:wrap;margin-top:4px}}
    .ms i{{font:700 8.5px 'IBM Plex Mono',monospace;font-style:normal;border:1px dashed #aaa;border-radius:2px;padding:0 3px;color:#666}}
    .ms i.on{{border:1px solid {ACC};background:{ACC};color:#fff}} .ms i.lg{{border-color:#a86d00;color:#a86d00;font-family:Heebo}}
    .cap2{{font-size:11px;color:{INK2};text-align:center;margin:8px 0 0}}
    figure#tree{{width:1080px}}
    h4{{margin:0 0 8px;font-size:13px}}
    .two{{display:grid;grid-template-columns:1fr 1fr;gap:28px}}
    .br{{display:grid;grid-template-columns:150px 1fr 22px;gap:8px;align-items:center;margin:0 0 6px;font-size:11.5px}}
    .br .bl{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
    .br .bt{{display:flex;height:16px;background:#f1eee6;border-radius:2px;overflow:hidden}}
    .br .bt i{{display:block;height:100%}}
    .br .bt.stack{{background:none;gap:2px}} .br .bt.stack i{{display:grid;place-items:center;color:#fff;font:700 9px 'IBM Plex Mono',monospace;font-style:normal;border-radius:2px}}
    .br b{{font:700 12px 'IBM Plex Mono',monospace}}
    .db{{display:grid;grid-template-columns:280px 1fr 64px;gap:10px;align-items:center;height:24px;font-size:11px}}
    .db .dl{{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
    .db .dt{{position:relative;height:100%}}
    .db .dt u{{position:absolute;top:0;bottom:0;border-left:1px dashed {LINE}}}
    .db .dt s{{position:absolute;top:50%;height:2px;background:{INK2};transform:translateY(-1px)}}
    .db .dt em{{position:absolute;top:50%;width:12px;height:12px;border-radius:50%;transform:translate(-6px,-6px)}}
    .db .dt em.a{{background:#fff;border:2.5px solid;box-sizing:border-box}}
    .db .dv{{font:600 10.5px 'IBM Plex Mono',monospace;color:{INK2}}}
    .ax2 span{{position:absolute;transform:translateX(-50%);font-size:10.5px;color:{INK2}}}
    table.cov{{border-collapse:separate;border-spacing:2px;margin:0 auto;font-size:10.5px}}
    table.cov th{{font:700 9.5px 'IBM Plex Mono',monospace;padding:2px}}
    table.cov th.mh{{text-align:start;font:600 10.5px Heebo,Arial;white-space:nowrap;padding-inline-end:8px}}
    table.cov th.mh b{{font-family:'IBM Plex Mono',monospace;color:{ACC}}}
    table.cov td{{width:22px;height:17px;background:#f1eee6;border-radius:2px}}
    table.cov td.n{{background:none;font:700 10px 'IBM Plex Mono',monospace;color:{INK2};text-align:center}}
    """
    body = "".join(f"<figure id='{n}'>{c}</figure>" for n, c in figs)
    return f"<!doctype html><html lang='{lang}' dir='{'rtl' if he else 'ltr'}'><head><meta charset='utf-8'><link rel='stylesheet' href='../../kit/fonts.css'><style>{css}</style></head><body>{body}</body></html>", [n for n, _ in figs], st
