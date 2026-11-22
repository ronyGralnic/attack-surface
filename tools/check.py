#!/usr/bin/env python3
"""The standing check. Every page x {1280, 390} x {light, dark} x {http, file://}, plus file:// navigation and the documents.

python3 tools/check.py [--item <ID>] [--shots DIR]
Checks: no horizontal page scroll, no console errors/warnings, no page errors, data rendered, fonts loaded,
and on the item page every interactive component (DFD selection, STRIDE filter, attack tree, risk matrix,
glossary popover, theme toggle). Each step is wrapped so one failure is reported, not fatal.
"""
import sys, json, threading, functools, pathlib, http.server, socketserver, zipfile
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHROME = "/usr/bin/google-chrome"
PORT = 8765
args = sys.argv[1:]
ITEM = args[args.index("--item") + 1] if "--item" in args else sorted(p.parent.name for p in (ROOT / "items").glob("*/item.json"))[-1]
SHOTS = pathlib.Path(args[args.index("--shots") + 1]) if "--shots" in args else None
results = []


def rec(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def serve():
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass
    h = functools.partial(Quiet, directory=str(ROOT))
    socketserver.TCPServer.allow_reuse_address = True
    srv = socketserver.TCPServer(("127.0.0.1", PORT), h)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def url(proto, path):
    return f"http://127.0.0.1:{PORT}/{path}" if proto == "http" else (ROOT / path).as_uri()


def step(tag, name, fn):
    try:
        r = fn()
        ok, detail = (r if isinstance(r, tuple) else (r, ""))
        rec(f"{tag} {name}", ok, detail)
    except Exception as e:  # report, never crash
        rec(f"{tag} {name}", False, f"exception: {str(e).splitlines()[0][:160]}")


def item_interactions(pg, tag, it):
    hi_before = sum(1 for t in it["threats"] if t["l"] * t["i"] >= 10)
    hi_after = sum(1 for t in it["threats"] if t["res"]["l"] * t["res"]["i"] >= 10)
    node = max(it["dfd"]["nodes"], key=lambda n: sum(1 for t in it["threats"] if t["node"] == n["id"]))
    ncount = sum(1 for t in it["threats"] if t["node"] == node["id"])

    def dfd():
        pg.locator(f'svg.dfd .node[data-node="{node["id"]}"]').click()
        pg.wait_for_timeout(150)
        h3 = pg.locator(".dfd-panel h3").inner_text()
        vis = pg.locator("article.threat:not([hidden])").count()
        ok = node["label"] in h3 and vis == ncount
        return ok, f"panel='{h3[:30]}' visible={vis}/{ncount}"
    step(tag, "DFD select -> panel + STRIDE filter", dfd)

    def dfd_key():
        pg.locator(f'svg.dfd .node[data-node="{node["id"]}"]').press("Enter")  # toggles off
        pg.wait_for_timeout(100)
        return pg.locator("article.threat:not([hidden])").count() == len(it["threats"]), "keyboard toggle clears filter"
    step(tag, "DFD keyboard", dfd_key)

    def heat():
        t = it["threats"][0]
        pg.locator(f'.heat td button[data-node="{t["node"]}"][data-cat="{t["cat"]}"]').click()
        pg.wait_for_timeout(100)
        exp = sum(1 for x in it["threats"] if x["node"] == t["node"] and x["cat"] == t["cat"])
        vis = pg.locator("article.threat:not([hidden])").count()
        pg.locator(".filter-line .chip").click()
        return vis == exp, f"cell filter {vis}/{exp}"
    step(tag, "STRIDE heat cell filter", heat)

    def tree():
        pg.get_by_role("button", name="הצגת החסימה הקטנה ביותר").click()
        pg.wait_for_timeout(100)
        blocked = "blocked" in (pg.locator(".tree-status").get_attribute("class") or "")
        pg.get_by_role("button", name="איפוס").click()
        pg.wait_for_timeout(100)
        open_again = "blocked" not in (pg.locator(".tree-status").get_attribute("class") or "")
        first = pg.locator(".def-toggles .chip").first
        first.click(); pressed = first.get_attribute("aria-pressed") == "true"; first.click()
        return blocked and open_again and pressed, f"min-cut blocks={blocked} reset={open_again} toggle={pressed}"
    step(tag, "attack tree toggles", tree)

    def matrix():
        b = int(pg.locator(".rm-sum .stat .v").first.inner_text())
        pg.get_by_role("button", name="אחרי הגנות").click(); pg.wait_for_timeout(100)
        a = int(pg.locator(".rm-sum .stat .v").first.inner_text())
        dots = pg.locator(".grid5 .dotb").count()
        pg.locator(".grid5 .dotb").first.click(); pg.wait_for_timeout(80)
        det = pg.locator(".rm-detail .card").count()
        pg.get_by_role("button", name="לפני הגנות").click()
        return b == hi_before and a == hi_after and dots == len(it["threats"]) and det == 1, f"high {b}->{a} (expected {hi_before}->{hi_after}), dots={dots}, detail={det}"
    step(tag, "risk matrix before/after", matrix)

    def term():
        t = pg.locator(".term").first
        t.click(); pg.wait_for_timeout(100)
        opened = pg.locator(".term-pop").count() == 1
        pg.keyboard.press("Escape"); pg.wait_for_timeout(80)
        return opened and pg.locator(".term-pop").count() == 0, f"opened={opened}"
    step(tag, "glossary popover", term)

    def mit_link():
        pg.locator("article.threat .mchip").first.click(); pg.wait_for_timeout(500)
        return pg.locator(".mit.flash").count() == 1, "mitigation chip scrolls + flashes"
    step(tag, "threat -> mitigation link", mit_link)


def page_checks(pw, proto, path, width, theme, it):
    tag = f"[{proto} {width} {theme} {path.split('/')[-2] if 'items/' in path else path}]"
    ctx = pw.new_context(viewport={"width": width, "height": 900})
    ctx.add_init_script(f"try{{localStorage.setItem('desk-theme','{theme}')}}catch(e){{}}")
    pg = ctx.new_page()
    logs = []
    pg.on("console", lambda m: logs.append(f"{m.type}: {m.text}") if m.type in ("error", "warning") else None)
    pg.on("pageerror", lambda e: logs.append(f"pageerror: {e}"))
    try:
        pg.goto(url(proto, path), wait_until="load")
        if path != "about.html":
            pg.wait_for_function("document.documentElement.getAttribute('data-ready')==='1'", timeout=8000)
        pg.wait_for_timeout(400)
        step(tag, "theme applied", lambda: (pg.evaluate("document.documentElement.getAttribute('data-theme')") == theme, ""))
        step(tag, "no horizontal scroll", lambda: (lambda d: (d <= 0, f"overflow={d}px"))(pg.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")))
        step(tag, "fonts loaded", lambda: (lambda f: (f > 0, f"{f} faces"))(pg.evaluate("document.fonts.ready.then(()=>[...document.fonts].filter(f=>f.status==='loaded').length)")))
        if "items/" in path:
            step(tag, "item rendered", lambda: (pg.locator("svg.dfd .node").count() == len(it["dfd"]["nodes"]) and pg.locator("article.threat").count() == len(it["threats"]), ""))
            step(tag, "DFD layout fits width", lambda: (lambda m: (m == ("wide" if width >= 1000 else "tall"), m))(pg.evaluate("document.querySelector('svg.dfd').classList.contains('wide')?'wide':'tall'")))
            if SHOTS:
                pg.screenshot(path=str(SHOTS / f"{proto}-{width}-{theme}-item.png"), full_page=True)
            item_interactions(pg, tag, it)
            step(tag, "theme toggle", lambda: (pg.locator(".theme-toggle").click() or pg.evaluate("document.documentElement.getAttribute('data-theme')") != theme, ""))
        elif path == "index.html":
            step(tag, "gallery cards", lambda: (pg.locator(".item-card").count() >= 1, ""))
            def tiles():
                pg.locator(".stride-tile").first.click(); pg.wait_for_timeout(80)
                return pg.locator("#stride-explain a").count() >= 1, "tile explains + links"
            step(tag, "STRIDE tiles", tiles)
            def filt():
                chip = pg.locator("#filters .row").first.locator(".chip").nth(1)
                chip.click(); pg.wait_for_timeout(80)
                return chip.get_attribute("aria-pressed") == "true" and pg.locator(".item-card").count() >= 1, ""
            step(tag, "gallery filter", filt)
            if SHOTS:
                pg.screenshot(path=str(SHOTS / f"{proto}-{width}-{theme}-home.png"), full_page=True)
        else:
            if SHOTS:
                pg.screenshot(path=str(SHOTS / f"{proto}-{width}-{theme}-about.png"), full_page=True)
        rec(f"{tag} console clean", not logs, "; ".join(logs)[:300])
    except Exception as e:
        rec(f"{tag} load", False, str(e).splitlines()[0][:200])
    ctx.close()


def nav_file(pw):
    ctx = pw.new_context(viewport={"width": 1280, "height": 900}); pg = ctx.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    def go():
        pg.goto(url("file", "index.html")); pg.wait_for_timeout(300)
        pg.locator(".item-card").first.click()
        pg.wait_for_function("document.documentElement.getAttribute('data-ready')==='1'", timeout=8000)
        a = "items/" in pg.url and pg.locator("svg.dfd").count() == 1
        pg.locator(".brand").click(); pg.wait_for_timeout(300)
        b = pg.url.endswith("/index.html") and pg.locator(".item-card").count() >= 1
        pg.get_by_role("link", name="אודות").first.click(); pg.wait_for_timeout(300)
        c = pg.url.endswith("about.html") and "אודות" in pg.title()
        return a and b and c and not errs, f"home->item={a} item->home={b} home->about={c} errs={errs}"
    step("[file nav]", "home -> item -> home -> about", go)
    ctx.close()


def docs(it):
    d = ROOT / "items" / ITEM
    for doc in it["docs"]:
        p = d / doc["href"]
        def chk(p=p):
            if not p.exists() or p.stat().st_size < 5000:
                return False, "missing or tiny"
            if p.suffix == ".docx":
                from docx import Document
                Document(str(p)); z = zipfile.ZipFile(p)
                return "word/document.xml" in z.namelist(), f"{p.stat().st_size // 1024}KB"
            head = p.read_bytes()[:5]
            return head == b"%PDF-", f"{p.stat().st_size // 1024}KB"
        step("[docs]", doc["href"], chk)


def main():
    it = json.loads((ROOT / "items" / ITEM / "item.json").read_text(encoding="utf-8"))
    if SHOTS: SHOTS.mkdir(parents=True, exist_ok=True)
    srv = serve()
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=CHROME, args=["--no-sandbox"])
        for proto in ("http", "file"):
            for path in ("index.html", "about.html", f"items/{ITEM}/index.html"):
                for width in (1280, 390):
                    for theme in ("light", "dark"):
                        page_checks(b, proto, path, width, theme, it)
        nav_file(b)
        b.close()
    srv.shutdown()
    docs(it)
    bad = [r for r in results if not r[1]]
    for name, ok, det in results:
        if not ok or "-v" in args:
            print(("PASS " if ok else "FAIL ") + name + (f"  ({det})" if det else ""))
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
