/* =========================================================================
   Attack Surface · item page renderer
   Reads window.DESK_ITEM (items/<ID>/data.js, generated from item.json).
   Falls back to fetch("item.json") over http. No dependencies beyond kit.js.
   ========================================================================= */
(function(){
  "use strict";
  var h = Desk.h, rich = Desk.rich;
  var SVGNS = "http://www.w3.org/2000/svg";
  var CATS = ["S","T","R","I","D","E"];
  var CAT_HE = {S:"התחזות",T:"שיבוש",R:"הכחשה",I:"חשיפת מידע",D:"מניעת שירות",E:"הסלמת הרשאות"};
  var CAT_EN = {S:"Spoofing",T:"Tampering",R:"Repudiation",I:"Information disclosure",D:"Denial of service",E:"Elevation of privilege"};
  var KIND_HE = {entity:"ישות חיצונית",process:"תהליך",store:"מאגר נתונים"};
  var TYPE_HE = {prevent:"מניעה",detect:"זיהוי",respond:"תגובה"};

  var item, nodesById = {}, threatsById = {}, mitsById = {};
  var state = {node:null, cat:null, after:false, picked:null, on:{}};
  var listeners = [];
  function emit(){ listeners.forEach(function(f){ f(); }); }

  /* ---------- helpers ---------- */
  function s(tag, attrs){
    var el = document.createElementNS(SVGNS, tag), k;
    for (k in attrs || {}) if (attrs[k] != null) el.setAttribute(k, attrs[k]);
    for (var i = 2; i < arguments.length; i++){ var c = arguments[i]; if (c != null) el.append(c.nodeType ? c : document.createTextNode(String(c))); }
    return el;
  }
  function riskLevel(l, i){
    var x = l * i;
    if (x >= 15) return {n:5, he:"קריטי"};
    if (x >= 10) return {n:4, he:"גבוה"};
    if (x >= 6) return {n:3, he:"בינוני"};
    if (x >= 3) return {n:2, he:"נמוך-בינוני"};
    return {n:1, he:"נמוך"};
  }
  function riskPill(l, i){ var r = riskLevel(l, i); return h("span", {class:"risk r" + r.n}, r.he); }
  function sb(cat){ return h("span", {class:"sb " + cat, title:CAT_EN[cat] + " · " + CAT_HE[cat]}, cat); }
  function v(x){ return h("span", {dir:Desk.autoDir(x)}, x); }
  function flash(el){ if (!el) return; el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); setTimeout(function(){ el.classList.remove("flash"); }, 1600); }
  function goTo(id){
    var el = document.getElementById(id); if (!el) return;
    el.scrollIntoView({behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block:"start"});
    flash(el);
  }
  function section(id, no, title, intro){
    var sec = h("section", {id:id, "aria-labelledby":id + "-h"});
    var w = h("div", {class:"wrap"});
    w.append(h("div", {class:"sec-head"}, no ? h("span", {class:"no"}, no) : null, h("h2", {id:id + "-h"}, title)));
    if (intro) w.append(h("p", {class:"sec-intro"}, rich(intro)));
    sec.append(w); sec._w = w; return sec;
  }
  function bridge(key){
    var t = item.bridges && item.bridges[key];
    return t ? h("div", {class:"bridge", role:"note"}, h("span", null, rich(t))) : null;
  }
  function threatsOn(nodeId){ return item.threats.filter(function(t){ return t.node === nodeId; }); }

  /* ---------- banner / trailer / minute ---------- */
  function banner(){
    var it = item, w = h("header", {class:"wrap banner"});
    w.append(h("div", {class:"top"},
      h("span", {class:"kicker"}, "Threat Model · " + it.id),
      riskPill(it.risk.l, it.risk.i),
      h("span", {class:"tag"}, it.domain), h("span", {class:"tag"}, it.region)));
    w.append(h("h1", null, it.title));
    w.append(h("p", {class:"sub"}, rich(it.subtitle)));
    var dl = h("dl", {class:"facts"});
    (it.facts || []).forEach(function(f){ dl.append(h("div", null, h("dt", null, f.k), h("dd", null, rich(f.v)))); });
    w.append(dl);
    w.append(h("p", {class:"defensive"},
      h("span", {html:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>'}),
      h("span", null, rich(it.defensiveNote))));
    return w;
  }
  function trailer(){
    var sec = h("section", {class:"wrap", "aria-label":"פתיחה"});
    sec.append(h("p", {class:"trailer"}, rich(item.trailer.text), h("span", {class:"q"}, rich(item.trailer.question))));
    return sec;
  }
  function minute(){
    var sec = section("minute", null, "הסיפור בדקה");
    var w = sec._w; w.classList.add("minute");
    item.minute.forEach(function(p, i){
      w.append(Desk.p(p));
      if (item.quote && item.quote.after === i){
        w.append(h("figure", {class:"pull"}, h("blockquote", {style:{margin:0}}, h("q", {lang:"en", dir:"ltr"}, item.quote.text)),
          h("figcaption", {class:"who"}, rich(item.quote.who))));
      }
    });
    if (item.claimsNote) w.append(h("div", {class:"callout warn"}, Desk.p(item.claimsNote)));
    return sec;
  }

  /* ---------- 01 DFD ---------- */
  function rectEdge(c, hw, hh, tx, ty){
    var dx = tx - c.x, dy = ty - c.y;
    if (!dx && !dy) return {x:c.x, y:c.y};
    var t = Math.min(dx ? hw / Math.abs(dx) : Infinity, dy ? hh / Math.abs(dy) : Infinity);
    return {x:c.x + dx * t, y:c.y + dy * t};
  }
  function dfdSection(){
    var d = item.dfd;
    var sec = section("dfd", "01", d.title, d.intro);
    var w = sec._w;
    w.classList.add("wrap-dfd");
    var box = h("div", {class:"dfd-wrap"});
    var key = h("div", {class:"dfd-key", "aria-hidden":"true"},
      h("span", {html:'<svg viewBox="0 0 26 14"><rect x="1" y="2" width="24" height="10" rx="1" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>ישות חיצונית'}),
      h("span", {html:'<svg viewBox="0 0 26 14"><rect x="1" y="2" width="24" height="10" rx="5" fill="none" stroke="var(--accent)" stroke-width="1.4"/></svg>תהליך'}),
      h("span", {html:'<svg viewBox="0 0 26 14"><path d="M1 2h24M1 12h24M1 2v10" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>מאגר'}),
      h("span", {html:'<svg viewBox="0 0 26 14"><path d="M1 7h24" stroke="var(--boundary)" stroke-width="1.6" stroke-dasharray="5 3"/></svg>גבול אמון'}),
      h("span", {html:'<svg viewBox="0 0 26 14"><path d="M1 7h24" stroke="var(--flow-threat)" stroke-width="1.8" stroke-dasharray="5 3"/></svg>זרימה חשודה'}),
      h("span", {html:'<svg viewBox="0 0 26 14"><path d="M2 7h22" stroke="var(--flow-influence)" stroke-width="2" stroke-dasharray="1.5 3.5" stroke-linecap="round"/></svg>ערוץ השפעה'}));
    box.append(h("div", {class:"dfd-tools"}, key));
    var holder = h("div", {class:"dfd-holder"});
    box.append(holder);
    var panel = h("div", {class:"dfd-panel", "aria-live":"polite"});
    box.append(panel);
    var fl = h("ol", {class:"flow-list", "aria-label":"זרימות נתונים"});
    d.flows.forEach(function(f, i){
      var li = h("li", {class:f.kind ? "k-" + f.kind : "", "data-flow":f.id}, h("span", {class:"n"}, i + 1),
        h("span", null, h("b", null, nodesById[f.from].label + " ← " + nodesById[f.to].label), ": ", rich(f.label)));
      li.addEventListener("mouseenter", function(){ hiFlow(f.id); });
      li.addEventListener("mouseleave", function(){ hiFlow(null); });
      fl.append(li);
    });
    box.append(h("details", {class:"flows", open:true}, h("summary", null, "הזרימות במספרים (" + d.flows.length + ")"), fl));
    w.append(box);

    var svgEl = null, curMode = null;
    function draw(){
      var width = holder.clientWidth || w.clientWidth;
      var mode = width >= 680 ? "wide" : "tall";
      if (mode === curMode && svgEl) { mark(); return; }
      curMode = mode;
      var L = d.layouts[mode];
      var svg = s("svg", {class:"dfd " + mode, viewBox:"0 0 " + L.w + " " + L.h, role:"group", "aria-label":d.aria});
      var defs = s("defs");
      [["a-n","var(--flow)"],["a-t","var(--flow-threat)"],["a-i","var(--flow-influence)"]].forEach(function(m){
        defs.append(s("marker", {id:m[0] + "-" + mode, viewBox:"0 0 10 10", refX:"9", refY:"5", markerWidth:"7", markerHeight:"7", orient:"auto-start-reverse"},
          s("path", {d:"M0 0L10 5L0 10z", style:"fill:" + m[1]})));
      });
      svg.append(defs);
      d.boundaries.forEach(function(b){
        var g = L.zones[b.id]; if (!g) return;
        var z = s("g", {class:"zone" + (b.inner ? " inner" : "")},
          s("rect", {x:g.x, y:g.y, width:g.w, height:g.h, rx:14}),
          s("text", {x:g.lx, y:g.ly, "text-anchor":g.anchor || "start", direction:"rtl"}, b.label));
        svg.append(z);
      });
      var nw = L.nw, nh = L.nh;
      var flowsG = s("g"), nodesG = s("g");
      d.flows.forEach(function(f, i){
        var a = L.nodes[f.from], b = L.nodes[f.to];
        var via = (L.via && L.via[f.id]) || [];
        var pts = [a].concat(via, [b]);
        var p0 = rectEdge(a, nw/2 + 2, nh/2 + 2, pts[1].x, pts[1].y);
        var pn = rectEdge(b, nw/2 + 5, nh/2 + 5, pts[pts.length-2].x, pts[pts.length-2].y);
        var all = [p0].concat(via, [pn]);
        var dstr = all.map(function(p, k){ return (k ? "L" : "M") + p.x.toFixed(1) + " " + p.y.toFixed(1); }).join(" ");
        var mk = f.kind === "threat" ? "a-t" : f.kind === "influence" ? "a-i" : "a-n";
        var g = s("g", {class:"flow " + (f.kind || ""), "data-flow":f.id, "data-from":f.from, "data-to":f.to});
        g.append(s("path", {d:dstr, "marker-end":"url(#" + mk + "-" + mode + ")"}));
        var best = 0, bi = 0;
        for (var k = 0; k < all.length - 1; k++){ var len = Math.hypot(all[k+1].x - all[k].x, all[k+1].y - all[k].y); if (len > best){ best = len; bi = k; } }
        var at = (L.numAt && L.numAt[f.id] != null) ? L.numAt[f.id] : .5;
        var mx = all[bi].x + (all[bi+1].x - all[bi].x) * at, my = all[bi].y + (all[bi+1].y - all[bi].y) * at;
        g.append(s("g", {class:"num"}, s("circle", {cx:mx, cy:my, r:9.5}), s("text", {x:mx, y:my + 3.6, "text-anchor":"middle"}, i + 1)));
        flowsG.append(g);
      });
      d.nodes.forEach(function(n){
        var c = L.nodes[n.id]; if (!c) return;
        var x = c.x - nw/2, y = c.y - nh/2;
        var tc = threatsOn(n.id).length;
        var g = s("g", {class:"node " + n.kind + (n.adversary ? " adversary" : ""), tabindex:"0", role:"button", "data-node":n.id,
          "aria-label":n.label + " · " + KIND_HE[n.kind] + (tc ? " · " + tc + " איומים" : ""), "aria-pressed":"false"});
        g.append(s("rect", {class:"focus-ring", x:x - 5, y:y - 5, width:nw + 10, height:nh + 10, rx:10}));
        if (n.kind === "store"){
          g.append(s("rect", {class:"shape", x:x, y:y, width:nw, height:nh}));
          g.append(s("path", {class:"rail", d:"M" + (x+nw) + " " + y + "H" + x + "M" + (x+nw) + " " + (y+nh) + "H" + x + "M" + (x+nw) + " " + y + "V" + (y+nh), fill:"none"}));
        } else {
          g.append(s("rect", {class:"shape", x:x, y:y, width:nw, height:nh, rx:n.kind === "process" ? nh/2 : 3}));
        }
        var hasSub = !!n.sub;
        g.append(s("text", {x:c.x, y:c.y + (hasSub ? -2 : 5), "text-anchor":"middle", direction:"rtl"}, n.label));
        if (hasSub) g.append(s("text", {class:"sub", x:c.x, y:c.y + 14, "text-anchor":"middle", direction:"rtl"}, n.sub));
        if (tc){
          var bx = x + 2, by = y + 2;
          g.append(s("circle", {class:"count", cx:bx, cy:by, r:10}));
          g.append(s("text", {class:"count-t", x:bx, y:by + 4, "text-anchor":"middle"}, tc));
        }
        g.addEventListener("click", function(){ select(n.id); });
        g.addEventListener("keydown", function(e){ if (e.key === "Enter" || e.key === " "){ e.preventDefault(); select(n.id); } });
        g.addEventListener("mouseenter", function(){ if (!state.node) hiNode(n.id); });
        g.addEventListener("mouseleave", function(){ if (!state.node) hiNode(null); });
        nodesG.append(g);
      });
      svg.append(flowsG, nodesG);
      holder.innerHTML = ""; holder.append(svg); svgEl = svg;
      mark();
    }
    function hiNode(id){
      if (!svgEl) return;
      svgEl.querySelectorAll(".node").forEach(function(g){
        var nid = g.getAttribute("data-node");
        var linked = !id || nid === id || d.flows.some(function(f){ return (f.from === id && f.to === nid) || (f.to === id && f.from === nid); });
        g.classList.toggle("dim", !linked);
      });
      svgEl.querySelectorAll(".flow").forEach(function(g){
        var on = !id || g.getAttribute("data-from") === id || g.getAttribute("data-to") === id;
        g.classList.toggle("dim", !on); g.classList.toggle("hi", !!id && on);
      });
      fl.querySelectorAll("li").forEach(function(li){
        var f = d.flows.filter(function(x){ return x.id === li.getAttribute("data-flow"); })[0];
        li.style.opacity = (!id || f.from === id || f.to === id) ? "" : ".4";
      });
    }
    function hiFlow(fid){
      if (!svgEl || state.node) return;
      svgEl.querySelectorAll(".flow").forEach(function(g){ var on = !fid || g.getAttribute("data-flow") === fid; g.classList.toggle("dim", !on); g.classList.toggle("hi", !!fid && on); });
      svgEl.querySelectorAll(".node").forEach(function(g){
        if (!fid){ g.classList.remove("dim"); return; }
        var f = d.flows.filter(function(x){ return x.id === fid; })[0];
        var nid = g.getAttribute("data-node"); g.classList.toggle("dim", nid !== f.from && nid !== f.to);
      });
    }
    function mark(){
      if (!svgEl) return;
      svgEl.querySelectorAll(".node").forEach(function(g){
        var on = g.getAttribute("data-node") === state.node;
        g.classList.toggle("sel", on); g.setAttribute("aria-pressed", on ? "true" : "false");
      });
      hiNode(state.node);
      renderPanel();
    }
    function select(id){
      state.node = state.node === id ? null : id;
      state.cat = null;
      emit();
    }
    function renderPanel(){
      panel.innerHTML = "";
      if (!state.node){
        panel.append(h("p", {class:"hint"}, h("span", {"aria-hidden":"true"}, "☝"), rich(d.hint)));
        return;
      }
      var n = nodesById[state.node], ts = threatsOn(n.id);
      var b = d.boundaries.filter(function(x){ return x.id === n.zone; })[0];
      panel.append(h("h3", null, n.label, h("span", {class:"kind"}, KIND_HE[n.kind]), b ? h("span", {class:"tag"}, b.label) : null));
      panel.append(Desk.p(n.desc));
      if (ts.length){
        var ul = h("ul", {class:"tl"});
        ts.forEach(function(t){
          ul.append(h("li", null, sb(t.cat), h("span", {class:"tid"}, t.id),
            h("button", {type:"button", onclick:function(){ state.cat = null; emit(); goTo("th-" + t.id); }}, t.title), riskPill(t.l, t.i)));
        });
        panel.append(h("p", {class:"small muted", style:{margin:"10px 0 0"}}, ts.length + " איומים על הרכיב הזה. לחיצה מובילה לכרטיס האיום בטבלת STRIDE."));
        panel.append(ul);
      } else panel.append(h("p", {class:"small muted"}, "אין איום שממופה ישירות לרכיב הזה. הוא חלק מהמערכת כי זרימות עוברות דרכו."));
      panel.append(h("button", {type:"button", class:"btn", style:{marginTop:"10px"}, onclick:function(){ select(n.id); }}, "ניקוי הבחירה"));
    }
    listeners.push(mark);
    var lastW = 0;
    if (window.ResizeObserver){
      new ResizeObserver(function(es){ var nw = Math.round(es[0].contentRect.width); if (nw !== lastW){ lastW = nw; draw(); } }).observe(holder);
    } else window.addEventListener("resize", draw);
    setTimeout(draw, 0);
    sec._draw = draw;
    return sec;
  }

  /* ---------- 02 assets ---------- */
  function assetsSection(){
    var a = item.assets;
    var sec = section("assets", "02", a.title, a.intro);
    var g = h("div", {class:"assets"});
    a.items.forEach(function(x){
      g.append(h("article", {class:"asset"},
        h("h3", null, h("span", null, x.name), h("span", {class:"stars", "aria-label":"חשיבות " + x.value + " מתוך 3"}, "●".repeat(x.value) + "○".repeat(3 - x.value))),
        h("div", {class:"owner"}, "למי: ", rich(x.owner)),
        Desk.p(x.why),
        h("p", {class:"loss"}, h("b", null, "אם הוא אובד: "), rich(x.loss))));
    });
    sec._w.append(g);
    return sec;
  }

  /* ---------- 03 STRIDE ---------- */
  function strideSection(){
    var st = item.stride;
    var sec = section("stride", "03", st.title, st.intro);
    var w = sec._w;
    var rows = item.dfd.nodes.filter(function(n){ return threatsOn(n.id).length; });
    var table = h("table", {class:"heat"});
    var thead = h("thead", null, h("tr", null, h("th", {class:"row", scope:"col"}, h("span", {class:"sr-only"}, "רכיב")),
      CATS.map(function(c){ return h("th", {scope:"col", title:CAT_EN[c] + " · " + CAT_HE[c]}, sb(c)); })));
    var tbody = h("tbody");
    rows.forEach(function(n){
      var tr = h("tr");
      var rb = h("button", {type:"button", "data-node":n.id, "aria-pressed":"false", onclick:function(){
        state.node = state.node === n.id && !state.cat ? null : n.id; state.cat = null; emit(); }}, n.label);
      tr.append(h("th", {class:"row", scope:"row"}, rb));
      CATS.forEach(function(c){
        var cnt = item.threats.filter(function(t){ return t.node === n.id && t.cat === c; }).length;
        var b = h("button", {type:"button", class:(cnt ? "has c-" + c : ""), style:cnt ? {"--n":String(Math.min(cnt,3))} : null, "data-node":n.id, "data-cat":c,
          "aria-pressed":"false", "aria-label":n.label + " · " + CAT_HE[c] + ": " + cnt, disabled:!cnt,
          onclick:function(){ var same = state.node === n.id && state.cat === c; state.node = same ? null : n.id; state.cat = same ? null : c; emit(); }}, cnt || "·");
        tr.append(h("td", null, b));
      });
      tbody.append(tr);
    });
    table.append(thead, tbody);
    w.append(h("div", {class:"card", style:{padding:"10px"}}, table));
    var fline = h("div", {class:"filter-line", "aria-live":"polite"});
    w.append(fline);
    var list = h("div", {class:"threats"});
    w.append(list);
    item.threats.forEach(function(t){
      var n = nodesById[t.node];
      var card = h("article", {class:"threat c-" + t.cat, id:"th-" + t.id, "data-node":t.node, "data-cat":t.cat},
        h("div", {class:"th-top"}, sb(t.cat), h("span", {class:"tid"}, t.id), h("h3", null, t.title), riskPill(t.l, t.i)),
        h("div", {class:"on"}, CAT_HE[t.cat] + " · על: ", h("b", null, n.label)),
        Desk.p(t.desc),
        h("p", {class:"ev"}, h("b", null, "בסיס בדיווח: "), rich(t.evidence), t.claim ? h("span", {class:"claim"}, t.claim) : null),
        h("div", {class:"row2"},
          h("span", null, "סבירות ", v(t.l + "/5"), " · השפעה ", v(t.i + "/5")),
          h("span", null, "הגנות: "),
          t.mits.map(function(m){ return h("button", {type:"button", class:"mchip", title:mitsById[m].name, onclick:function(){ goTo("m-" + m); }}, m); })));
      list.append(card);
    });
    function update(){
      tbody.querySelectorAll("th button").forEach(function(b){ b.setAttribute("aria-pressed", b.getAttribute("data-node") === state.node && !state.cat ? "true" : "false"); });
      tbody.querySelectorAll("td button").forEach(function(b){ b.setAttribute("aria-pressed", b.getAttribute("data-node") === state.node && b.getAttribute("data-cat") === state.cat ? "true" : "false"); });
      var shown = 0;
      list.querySelectorAll(".threat").forEach(function(c){
        var ok = (!state.node || c.getAttribute("data-node") === state.node) && (!state.cat || c.getAttribute("data-cat") === state.cat);
        c.hidden = !ok; if (ok) shown++;
      });
      fline.innerHTML = "";
      var desc = state.node ? nodesById[state.node].label + (state.cat ? " · " + CAT_HE[state.cat] : "") : "כל הרכיבים";
      fline.append(h("span", null, "מציג ", h("b", {class:"what"}, shown), " מתוך " + item.threats.length + " איומים · ", desc));
      if (state.node) fline.append(h("button", {type:"button", class:"chip", onclick:function(){ state.node = null; state.cat = null; emit(); }}, "הצגת הכל"));
    }
    listeners.push(update);
    update();
    return sec;
  }

  /* ---------- 04 attack tree ---------- */
  function evalNode(n){
    if (n.children){
      var rs = n.children.map(evalNode);
      n._blocked = n.gate === "AND" ? rs.some(Boolean) : rs.every(Boolean);
    } else n._blocked = (n.mits || []).some(function(m){ return state.on[m]; });
    return n._blocked;
  }
  function treeMits(n, acc){ acc = acc || []; (n.mits || []).forEach(function(m){ if (acc.indexOf(m) < 0) acc.push(m); }); (n.children || []).forEach(function(c){ treeMits(c, acc); }); return acc; }
  function minimalCut(root, ms){
    var best = null;
    for (var mask = 1; mask < (1 << ms.length); mask++){
      var on = {}, cnt = 0;
      ms.forEach(function(m, i){ if (mask & (1 << i)){ on[m] = true; cnt++; } });
      if (best && cnt >= best.length) continue;
      var save = state.on; state.on = on;
      if (evalNode(root)) best = ms.filter(function(m, i){ return mask & (1 << i); });
      state.on = save;
    }
    evalNode(root);
    return best;
  }
  function treeSection(){
    var t = item.tree;
    var sec = section("tree", "04", t.title, t.intro);
    var w = sec._w;
    var ms = treeMits(t.root);
    var minCut = minimalCut(t.root, ms);
    var toggles = h("div", {class:"def-toggles", role:"group", "aria-label":"הגנות להפעלה"});
    ms.forEach(function(m){
      var b = h("button", {type:"button", class:"chip", "aria-pressed":"false", "data-m":m, onclick:function(){ state.on[m] = !state.on[m]; emit(); }},
        h("span", {class:"mid"}, m), mitsById[m].short || mitsById[m].name);
      toggles.append(b);
    });
    var status = h("div", {class:"tree-status", "aria-live":"polite"});
    var tools = h("div", {style:{display:"flex",gap:"8px",flexWrap:"wrap",marginBottom:"14px"}},
      h("button", {type:"button", class:"btn", onclick:function(){ state.on = {}; emit(); }}, "איפוס"),
      h("button", {type:"button", class:"btn", onclick:function(){ state.on = {}; minCut.forEach(function(m){ state.on[m] = true; }); emit(); }}, "הצגת החסימה הקטנה ביותר"));
    w.append(h("p", {class:"small muted", style:{marginBottom:"4px"}}, rich(t.howto)), toggles, tools, status);
    var ul = h("ul", {class:"tree"});
    function build(n, depth){
      var gate = n.children ? (n.gate === "AND" ? "and" : "or") : "leaf";
      var gl = n.children ? (n.gate === "AND" ? "וגם" : "או") : "צעד";
      var box = h("div", {class:"tnode" + (depth === 0 ? " root" : ""), "data-id":n.id},
        h("span", {class:"gate " + gate, title:n.children ? (n.gate === "AND" ? "AND: צריך את כל הצעדים" : "OR: מספיק אחד מהם") : "צעד בודד"}, gl),
        h("div", {class:"txt"}, rich(n.label), n.legal ? h("span", {class:"legal"}, n.legal) : null,
          (n.mits && n.mits.length) ? h("div", {class:"ms"}, n.mits.map(function(m){ return h("span", {"data-m":m, title:mitsById[m].name}, m); })) : null),
        h("span", {class:"st"}, ""));
      var li = h("li", null, box);
      if (n.children){ var sub = h("ul"); n.children.forEach(function(c){ sub.append(build(c, depth + 1)); }); li.append(sub); }
      n._el = box;
      return li;
    }
    ul.append(build(t.root, 0));
    w.append(ul);
    w.append(h("div", {class:"callout accent"}, Desk.p(t.insight)));
    function walk(n, f){ f(n); (n.children || []).forEach(function(c){ walk(c, f); }); }
    function update(){
      evalNode(t.root);
      walk(t.root, function(n){
        n._el.classList.toggle("blocked", n._blocked);
        n._el.querySelector(".st").textContent = n._blocked ? "חסום" : (n.children ? "פתוח" : "אפשרי");
        n._el.querySelectorAll(".ms span").forEach(function(sp){ sp.classList.toggle("on", !!state.on[sp.getAttribute("data-m")]); });
      });
      toggles.querySelectorAll("button").forEach(function(b){ b.setAttribute("aria-pressed", state.on[b.getAttribute("data-m")] ? "true" : "false"); });
      var cnt = ms.filter(function(m){ return state.on[m]; }).length;
      status.className = "tree-status" + (t.root._blocked ? " blocked" : "");
      status.innerHTML = "";
      var open = (t.root.children || []).filter(function(c){ return !c._blocked; }).map(function(c){ return c.short || c.label; });
      status.append(h("span", {class:"dot", "aria-hidden":"true"}),
        h("span", null, t.root._blocked ? "המטרה חסומה בכל המסלולים" : "המטרה עדיין בהישג יד",
          h("span", {class:"sub", style:{display:"block"}},
            t.root._blocked ? ("עם " + cnt + " הגנות פעילות." + (cnt === minCut.length ? " זה המינימום האפשרי בעץ הזה." : " אפשר גם עם " + minCut.length + ".")) :
            "מסלולים פתוחים: " + open.join(" · "))));
    }
    listeners.push(update);
    update();
    return sec;
  }

  /* ---------- 05 risk matrix ---------- */
  function riskSection(){
    var r = item.riskMatrix;
    var sec = section("risk", "05", r.title, r.intro);
    var w = sec._w;
    var seg = h("div", {class:"seg", role:"group", "aria-label":"מצב המטריצה"});
    var bBefore = h("button", {type:"button", "aria-pressed":"true", onclick:function(){ state.after = false; emit(); }}, "לפני הגנות");
    var bAfter = h("button", {type:"button", "aria-pressed":"false", onclick:function(){ state.after = true; emit(); }}, "אחרי הגנות");
    seg.append(bBefore, bAfter);
    w.append(h("div", {class:"rm-tools"}, seg, h("span", {class:"small muted"}, rich(r.note))));
    var grid = h("div", {class:"grid5", role:"grid", "aria-label":"סבירות מול השפעה"});
    var cells = {};
    for (var imp = 5; imp >= 1; imp--){
      for (var lik = 1; lik <= 5; lik++){
        var lv = riskLevel(lik, imp);
        var c = h("div", {class:"cell r" + lv.n, role:"gridcell", "aria-label":"סבירות " + lik + ", השפעה " + imp});
        cells[lik + "-" + imp] = c; grid.append(c);
      }
    }
    var ynums = h("div", {class:"ynums", "aria-hidden":"true"}, [5,4,3,2,1].map(function(n){ return h("span", null, n); }));
    var rm = h("div", {class:"rm"},
      h("div", {class:"left"}, h("div", {class:"ylab"}, "השפעה ↑"), ynums), grid,
      h("div"), h("div", {class:"xlab", "aria-hidden":"true"}, [1,2,3,4,5].map(function(n){ return h("span", null, n); })),
      h("div"), h("div", {class:"axis", dir:"ltr"}, "סבירות →"));
    w.append(h("div", {class:"card", style:{padding:"12px"}}, rm));
    var sum = h("div", {class:"rm-sum"});
    w.append(sum);
    var detail = h("div", {class:"rm-detail", "aria-live":"polite"});
    w.append(detail);
    var prev = {};
    function pos(t){ return state.after ? t.res : {l:t.l, i:t.i}; }
    function update(){
      bBefore.setAttribute("aria-pressed", state.after ? "false" : "true");
      bAfter.setAttribute("aria-pressed", state.after ? "true" : "false");
      Object.keys(cells).forEach(function(k){ cells[k].innerHTML = ""; });
      var hi = 0, mid = 0, lo = 0;
      item.threats.forEach(function(t){
        var p = pos(t), key = p.l + "-" + p.i;
        var b = h("button", {type:"button", class:"dotb c-" + t.cat + (prev[t.id] && prev[t.id] !== key ? " moved" : ""), "aria-pressed":state.picked === t.id ? "true" : "false",
          "aria-label":t.id + " " + t.title, title:t.title, onclick:function(){ state.picked = state.picked === t.id ? null : t.id; emit(); }}, t.id);
        cells[key].append(b);
        prev[t.id] = key;
        var x = p.l * p.i; if (x >= 10) hi++; else if (x >= 6) mid++; else lo++;
      });
      sum.innerHTML = "";
      sum.append(h("div", {class:"stat"}, h("div", {class:"v", style:{color:"var(--risk-5)"}}, hi), h("div", {class:"l"}, "גבוה וקריטי")),
        h("div", {class:"stat"}, h("div", {class:"v", style:{color:"var(--risk-3)"}}, mid), h("div", {class:"l"}, "בינוני")),
        h("div", {class:"stat"}, h("div", {class:"v", style:{color:"var(--risk-1)"}}, lo), h("div", {class:"l"}, "נמוך")));
      detail.innerHTML = "";
      if (state.picked){
        var t = threatsById[state.picked];
        detail.append(h("div", {class:"card"},
          h("div", {class:"th-top", style:{display:"flex",gap:"8px",alignItems:"center",flexWrap:"wrap"}}, sb(t.cat), h("b", null, t.id + " · " + t.title)),
          h("p", {style:{margin:"8px 0 0"}}, "לפני: ", riskPill(t.l, t.i), " ", v("(" + t.l + "×" + t.i + ")"), " ← אחרי: ", riskPill(t.res.l, t.res.i), " ", v("(" + t.res.l + "×" + t.res.i + ")")),
          t.resNote ? Desk.p(t.resNote, "small muted") : null,
          h("p", {class:"small", style:{margin:"6px 0 0"}}, h("a", {href:"#th-" + t.id, onclick:function(e){ e.preventDefault(); state.node = null; state.cat = null; emit(); goTo("th-" + t.id); }}, "לכרטיס האיום"))));
      } else detail.append(h("p", {class:"small muted"}, "לחיצה על נקודה מציגה את האיום ואת המעבר שלו לפני ואחרי ההגנות."));
    }
    listeners.push(update);
    update();
    return sec;
  }

  /* ---------- 06 mitigations ---------- */
  function mitSection(){
    var m = item.mitigations;
    var sec = section("mitigations", "06", m.title, m.intro);
    var w = sec._w;
    var g = h("div", {class:"mits"});
    m.items.forEach(function(x){
      var covered = item.threats.filter(function(t){ return t.mits.indexOf(x.id) >= 0; });
      g.append(h("article", {class:"mit", id:"m-" + x.id},
        h("div", {class:"top"}, h("span", {class:"mid"}, x.id), h("span", {class:"type " + x.type}, TYPE_HE[x.type]),
          h("span", {class:"src" + (x.source === "ours" ? " ours" : "")}, x.source === "ours" ? "הצעה שלנו" : "מוזכר בדיווח")),
        h("h3", null, rich(x.name)),
        Desk.p(x.desc),
        x.limit ? h("p", {class:"limit"}, h("b", null, "המגבלה: "), rich(x.limit)) : null,
        h("p", {class:"small muted", style:{margin:0}}, "באחריות: ", rich(x.owner)),
        h("div", {class:"covers"}, "מכסה: ", covered.map(function(t){
          return h("a", {href:"#th-" + t.id, class:"sb " + t.cat, onclick:function(e){ e.preventDefault(); state.node = null; state.cat = null; emit(); goTo("th-" + t.id); }}, t.id);
        }))));
    });
    w.append(g);
    if (m.rule){
      w.append(h("h3", {style:{marginTop:"1.6em"}}, rich(m.rule.title)));
      w.append(Desk.p(m.rule.intro));
      var pre = h("pre", {class:"code", tabindex:"0"}, m.rule.code);
      var cb = h("button", {type:"button", class:"copy-btn"}, "העתקה");
      Desk.copy(cb, function(){ return m.rule.code; });
      w.append(h("div", {class:"code-wrap"}, cb, pre));
      if (m.rule.note) w.append(Desk.p(m.rule.note, "small muted"));
    }
    w.append(h("div", {class:"callout warn residual"}, Desk.p("**סיכון שיורי.** " + m.residual)));
    return sec;
  }

  /* ---------- 07 ATT&CK ---------- */
  function attackSection(){
    var a = item.attack;
    var sec = section("attack", "07", a.title, a.intro);
    var tb = h("tbody");
    a.items.forEach(function(x){
      tb.append(h("tr", null,
        h("td", null, h("span", {class:"tech", dir:"ltr"}, x.id), h("span", {class:"tname"}, x.name)),
        h("td", null, rich(x.where)),
        h("td", null, x.threats.map(function(id){ var t = threatsById[id]; return h("a", {href:"#th-" + id, class:"sb " + t.cat, style:{marginInlineEnd:"4px"}, onclick:function(e){ e.preventDefault(); state.node = null; state.cat = null; emit(); goTo("th-" + id); }}, id); }))));
    });
    sec._w.append(h("table", {class:"table stack attack"},
      h("thead", null, h("tr", null, h("th", null, "טכניקה"), h("th", null, "איפה זה מופיע כאן"), h("th", null, "איומים"))), tb));
    if (a.caveat) sec._w.append(h("div", {class:"callout"}, Desk.p(a.caveat)));
    return sec;
  }

  /* ---------- closing ---------- */
  function takeawaysSection(){
    var sec = section("takeaways", null, "מה לקחתי מזה");
    var g = h("div", {class:"takeaways"});
    item.takeaways.forEach(function(t){ g.append(h("div", {class:"take"}, h("span", {class:"k"}, t.kind), Desk.p(t.text))); });
    sec._w.append(g);
    return sec;
  }
  function docsSection(){
    var sec = section("docs", null, "המסמך המקצועי");
    sec._w.append(Desk.p(item.docsIntro || "אותו מודל איומים, כמסמך עבודה להורדה."));
    var g = h("div", {class:"docs"});
    (item.docs || []).forEach(function(d){
      g.append(h("a", {class:"doc", href:d.href, download:""}, h("span", {class:"ext"}, d.ext), h("span", {class:"t"}, d.label, h("small", null, d.lang))));
    });
    sec._w.append(g);
    sec._w.append(h("p", {class:"source"}, rich(item.source)));
    return sec;
  }

  /* ---------- boot ---------- */
  function render(data){
    item = data;
    item.dfd.nodes.forEach(function(n){ nodesById[n.id] = n; });
    item.threats.forEach(function(t){ threatsById[t.id] = t; });
    item.mitigations.items.forEach(function(m){ mitsById[m.id] = m; });
    Desk.terms.init(item.glossary);
    document.title = item.title + " · Attack Surface";
    var app = document.getElementById("app");
    app.innerHTML = "";
    var parts = [banner(), trailer(), minute(), bridge("dfd"), dfdSection(), bridge("assets"), assetsSection(), bridge("stride"), strideSection(),
      bridge("tree"), treeSection(), bridge("risk"), riskSection(), bridge("mitigations"), mitSection(), bridge("attack"), attackSection(),
      bridge("takeaways"), takeawaysSection(), docsSection()];
    parts.forEach(function(p){ if (p) app.append(p); });
    emit();
    if (location.hash){ var el = document.getElementById(location.hash.slice(1)); if (el) setTimeout(function(){ el.scrollIntoView(); }, 30); }
    document.documentElement.setAttribute("data-ready", "1");
  }
  function fail(msg){
    var app = document.getElementById("app");
    app.innerHTML = "";
    app.append(h("div", {class:"wrap", style:{padding:"60px 0"}}, h("div", {class:"callout warn"}, h("p", null, msg))));
  }
  document.addEventListener("DOMContentLoaded", function(){
    if (window.DESK_ITEM) return render(window.DESK_ITEM);
    if (location.protocol === "file:") return fail("לא נמצא data.js לפריט הזה. הריצו tools/build_item.py.");
    fetch("item.json").then(function(r){ return r.json(); }).then(render).catch(function(){ fail("לא הצלחנו לטעון את הפריט."); });
  });
})();
