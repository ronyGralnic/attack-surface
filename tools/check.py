#!/usr/bin/env python3
"""The standing check. Every page x {1280, 390} x {light, dark} x {http, file://}, plus file:// navigation and the documents.

python3 tools/check.py [--item <ID>] [--shots DIR]
Checks: no horizontal page scroll, no console errors/warnings, no page errors, data rendered, fonts loaded,
and on the item page every interactive component (guided DFD build, in-frame inspector, legend popovers,
STRIDE by component, attack tree, twin risk matrices with floating detail, coverage grid, rule terminal,
glossary popover, recap, theme toggle). Home: hero questions, STRIDE cards, seven steps, gallery filter. Each step is wrapped so one failure is reported, not fatal.
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
    T = it["threats"]
    hi_before = sum(1 for t in T if t["l"] * t["i"] >= 10)
    hi_after = sum(1 for t in T if t["res"]["l"] * t["res"]["i"] >= 10)
    node = max(it["dfd"]["nodes"], key=lambda n: sum(1 for t in T if t["node"] == n["id"]))
    ncount = sum(1 for t in T if t["node"] == node["id"])
    nsteps = len(it["dfd"].get("steps") or [])

    def stepper():
        pg.locator(".dfd-card").scroll_into_view_if_needed()
        first = pg.locator("svg.dfd .node:not(.off)").count()
        clicks = 0
        while pg.locator('.dfd-nav [data-act="next"]').count() and clicks < 12:
            pg.locator('.dfd-nav [data-act="next"]').click(); pg.wait_for_timeout(60); clicks += 1
        allv = pg.locator("svg.dfd .node:not(.off)").count()
        ok = first < allv == len(it["dfd"]["nodes"]) and (not nsteps or clicks == nsteps)
        return ok, f"step1 shows {first}, after {clicks} steps shows {allv}/{len(it['dfd']['nodes'])}"
    step(tag, "DFD guided build", stepper)

    def dfd():
        pg.locator(f'svg.dfd .node[data-node="{node["id"]}"]').click(); pg.wait_for_timeout(150)
        h3 = pg.locator(".dfd-side h3").inner_text()
        lis = pg.locator(".dfd-side .tl li").count()
        return node["label"] in h3 and lis == ncount, f"inspector='{h3[:30]}' threats={lis}/{ncount}"
    step(tag, "DFD select -> in-frame inspector", dfd)

    def dfd_key():
        pg.locator(f'svg.dfd .node[data-node="{node["id"]}"]').press("Enter"); pg.wait_for_timeout(100)
        return pg.locator(".dfd-side .tl").count() == 0, "keyboard toggles inspector off"
    step(tag, "DFD keyboard", dfd_key)

    def legend():
        pg.locator('.legend [data-term="trust-boundary"]').click(); pg.wait_for_timeout(100)
        ok = pg.locator(".term-pop").count() == 1
        pg.keyboard.press("Escape"); pg.wait_for_timeout(60)
        return ok, "legend explains its symbols"
    step(tag, "DFD legend popover", legend)

    def stride():
        comps = len({t["node"] for t in T})
        return pg.locator(".comp").count() == comps and pg.locator(".legend6 .l").count() == 6, f"components={pg.locator('.comp').count()}/{comps}"
    step(tag, "STRIDE by component", stride)

    def tree():
        pg.locator('[data-act="mincut"]').click(); pg.wait_for_timeout(650 * 6 + 200)
        blocked = "blocked" in (pg.locator(".goal").get_attribute("class") or "")
        pg.get_by_role("button", name="איפוס").click(); pg.wait_for_timeout(100)
        open_again = "blocked" not in (pg.locator(".goal").get_attribute("class") or "")
        first = pg.locator(".tree-bar .dchip").first
        first.click(); pressed = first.get_attribute("aria-pressed") == "true"; first.click()
        return blocked and open_again and pressed, f"min-cut blocks={blocked} reset={open_again} toggle={pressed}"
    step(tag, "attack tree", tree)

    def matrix():
        g = pg.locator(".grid5"); dots = [g.nth(0).locator(".dotb").count(), g.nth(1).locator(".dotb").count()]
        def hi(n):
            el = pg.locator(".rm-sum .stack").nth(n).locator("i.h")
            return int(el.inner_text()) if el.count() else 0
        b, a = hi(0), hi(1)
        pg.locator(".grid5 .dotb").first.click(); pg.wait_for_timeout(100)
        pop = pg.locator(".rm-pop").count()
        pg.keyboard.press("Escape"); pg.wait_for_timeout(60)
        closed = pg.locator(".rm-pop").count() == 0
        ok = dots == [len(T), len(T)] and b == hi_before and a == hi_after and pop == 1 and closed
        return ok, f"dots={dots} high {b}->{a} (expected {hi_before}->{hi_after}) popover={pop} closed={closed}"
    step(tag, "risk matrices + floating detail", matrix)

    def coverage():
        exp = sum(len(t["mits"]) for t in T)
        got = pg.locator("table.cov td.on").count()
        return got == exp, f"lit cells {got}/{exp}"
    step(tag, "coverage grid", coverage)

    def terminal():
        rule = it["mitigations"].get("rule")
        if not rule: return True, "no rule"
        lines = pg.locator(".code-lines .ln[data-l]").count()
        notes = pg.locator(".anno li").count()
        return lines == len(rule["code"].split("\n")) and notes == len(rule.get("notes", [])), f"lines={lines} notes={notes}"
    step(tag, "detection rule terminal", terminal)

    def term():
        t = pg.locator(".facts .term, .sec-intro .term").first
        t.click(); pg.wait_for_timeout(100)
        opened = pg.locator(".term-pop").count() == 1
        pg.keyboard.press("Escape"); pg.wait_for_timeout(80)
        return opened and pg.locator(".term-pop").count() == 0, f"opened={opened}"
    step(tag, "glossary popover", term)

    def mit_link():
        pg.locator("article.threat .mchip").first.click(); pg.wait_for_timeout(500)
        return pg.locator(".ctl.flash").count() == 1, "mitigation chip scrolls + flashes"
    step(tag, "threat -> mitigation link", mit_link)

    step(tag, "recap of seven steps", lambda: (pg.locator(".recap li").count() == 7, ""))
    step(tag, "method strips", lambda: (pg.locator(".method").count() == 7, f"{pg.locator('.method').count()}"))


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
            step(tag, "STRIDE cards + seven steps", lambda: (pg.locator(".s6").count() == 6 and pg.locator(".path7 li").count() == 7, ""))
            def hero():
                pg.locator('#qsteps li[data-s="3"] button').click(); pg.wait_for_timeout(80)
                return "s3" in (pg.locator("#sys").get_attribute("class") or ""), "question 3 drives the illustration"
            step(tag, "hero questions", hero)
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
