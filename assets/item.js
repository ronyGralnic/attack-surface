/* =========================================================================
   Attack Surface · item page renderer v2 ("night dossier")
   Reads window.DESK_ITEM (items/<ID>/data.js, generated from item.json).
   Falls back to fetch("item.json") over http. No dependencies beyond kit.js.
   Optional data (all backward compatible):
     characters[{id,name,role,color,initials}]        fictional cast
     minute[] items may be {text, scene, voice:{who,text}}
       scene.type: route | stats | timeline | versus | chat
     facts[].term                                      glossary id → "?" bubble
     dfd.steps[{title,text,add:[ids],focus:[ids]}]     guided build (ids: node, flow, "zone:<id>")
     assets.items[].who / .say                         character + line
     mitigations.rule.notes[{line,text}]               annotated detection rule
     docs[].preview                                    first-page thumbnail
   ========================================================================= */
(function(){
  "use strict";
  var h = Desk.h, rich = Desk.rich;
  var SVGNS = "http://www.w3.org/2000/svg";
  var CATS = ["S","T","R","I","D","E"];
  var CAT_HE = {S:"התחזות",T:"שיבוש",R:"הכחשה",I:"חשיפת מידע",D:"מניעת שירות",E:"הסלמת הרשאות"};
  var CAT_EN = {S:"Spoofing",T:"Tampering",R:"Repudiation",I:"Information disclosure",D:"Denial of service",E:"Elevation of privilege"};
  var CAT_Q = {S:"מישהו יכול להעמיד פנים שהוא מישהו אחר?",T:"מישהו יכול לשנות נתונים או תהליך בלי שנדע?",R:"מישהו יכול להכחיש שעשה משהו, ואין איך להוכיח?",
    I:"מידע יכול להגיע למי שאסור לו?",D:"אפשר להשבית את זה או להציף אותו?",E:"מישהו יכול לקבל יותר כוח ממה שמגיע לו?"};
  var KIND_HE = {entity:"ישות חיצונית",process:"תהליך",store:"מאגר נתונים"};
  var KIND_TERM = {entity:"dfd-entity",process:"dfd-process",store:"dfd-store"};
  var TYPE_HE = {prevent:"מניעה",detect:"זיהוי",respond:"תגובה"};
  var BASE_GLOSSARY = {
    "dfd-entity":{term:"ישות חיצונית", en:"External entity", def:"מישהו או משהו מחוץ למערכת, שהמערכת מדברת איתו אבל לא שולטת בו: לקוח, רגולטור, ספק, או תוקף. בדיאגרמה זה מלבן עם פינות חדות, ויריב מסומן בקו אדום מקווקו.", example:"בחנות אונליין: הקונה, חברת האשראי והשליח הם ישויות חיצוניות."},
    "dfd-process":{term:"תהליך", en:"Process", def:"מקום שבו משהו קורה: מחליטים, בודקים, מחשבים, מאשרים. זה יכול להיות תוכנה, צוות או אדם. בדיאגרמה זו צורה מעוגלת עם מסגרת בצבע הדגש.", example:"\"אישור הזמנה\" הוא תהליך: הוא מקבל הזמנה, בודק מלאי ומחליט אם להמשיך."},
    "dfd-store":{term:"מאגר נתונים", en:"Data store", def:"מקום שבו מידע נשמר ונשאר: מסד נתונים, רשימה, ארכיון, יומן. בדיאגרמה זה מלבן פתוח עם שני קווים.", example:"טבלת הלקוחות, או קלסר עם חשבוניות."},
    "dfd-flow":{term:"זרימה", en:"Data flow", def:"חץ שמראה מה עובר ממקום למקום, ובאיזה כיוון. המספר על החץ מתאים לרשימת הזרימות. חץ אדום מקווקו הוא מסלול תקיפה או חשד, וחץ סגול מנוקד הוא השפעה או לחץ, לא נתונים.", example:"\"הזמנה\" זורמת מהקונה לתהליך האישור."},
    "trust-boundary":{term:"גבול אמון", en:"Trust boundary", def:"קו שבו נתונים או שליטה עוברים בין גורמים שאין להם אותה רמת אמון. רוב האיומים נמצאים בדיוק על הקווים האלה, כי שם צריך לבדוק במקום להניח.", example:"הגבול בין הדפדפן של המשתמש לשרת: כל מה שמגיע מהדפדפן צריך בדיקה."},
    "stride":{term:"STRIDE", en:"Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege", def:"רשימת בדיקה של שש קטגוריות איומים שפותחה במיקרוסופט. שואלים את שש השאלות על כל רכיב בדיאגרמה.", example:"על טופס התחברות: אפשר להתחזות למשתמש? (S) אפשר לשנות את הבקשה בדרך? (T)"},
    "attack-tree":{term:"עץ תקיפה", en:"Attack tree", def:"תרשים שבראשו המטרה של התוקף, ומתחתיה הדרכים להגיע אליה. \"אחד מספיק\" אומר שכל ענף לבד מגיע למטרה. \"צריך את כולם\" אומר שחסימה של צעד אחד סוגרת את כל הענף.", example:"לפתוח כספת: לנחש את הקוד, או לפרוץ את הדלת (שצריך גם כלי וגם זמן)."},
    "risk-matrix":{term:"מטריצת סיכון", en:"Risk matrix", def:"טבלה של סבירות מול השפעה, כל אחת מ-1 עד 5. המכפלה קובעת סדר עדיפויות. המספרים הם הערכה ולא מדידה.", example:"סבירות 2 והשפעה 5 נותנות 10, כלומר עדיפות גבוהה."},
    "scope":{term:"היקף המודל", en:"Scope", def:"מה בדיוק ממדלים: איזו מערכת, מאיפה עד איפה, ומה בכוונה נשאר בחוץ. בלי היקף ברור אי אפשר לדעת מתי סיימנו.", example:"\"אפליקציית הבנקאות והשרתים שלה\", בלי מערכות הסניפים."},
    "main-threat":{term:"האיום המרכזי", en:"Top threat / attacker goal", def:"התוצאה שהכי כואב שתקרה. היא יושבת בראש עץ התקיפה, וכל ההגנות נבחנות לפי השאלה אם הן מונעות אותה.", example:"בבית חולים: שיבוש של מכשירים רפואיים, לא דליפה של מיילים."},
    "op-ed":{term:"מאמר דעה", en:"Op-ed", def:"טקסט שבו הכותב טוען טענה ומשכנע. הוא לא דיווח חדשותי, ולכן הטענות בו מסומנות כאן כטענות ולא כעובדות.", example:"\"כך צריך להגן על רשת החשמל\", מאת מומחית לשעבר."},
    "residual-risk":{term:"סיכון שיורי", en:"Residual risk", def:"הסיכון שנשאר אחרי שכל ההגנות שהוצעו פועלות, ומי מקבל אותו.", example:"גם עם אימות דו-שלבי, משתמש יכול למסור את הקוד למתחזה."}
  };
  var METHOD = {
    dfd:["רשמו מי מדבר עם המערכת מבחוץ (ישויות), מה קורה בפנים (תהליכים) ואיפה נשמר מידע (מאגרים).","חברו אותם בחיצים: מה עובר, ולאיזה כיוון.","מתחו קו בכל מקום שבו עוברים בין גורמים עם רמת אמון שונה. שם יהיו האיומים."],
    assets:["שאלו מה הכי כואב לאבד. לא רק מידע: גם שירות, בטיחות ואמון.","לכל נכס רשמו מי הבעלים ומה קורה אם הוא נפרץ.","דרגו 1 עד 3. הנכס בדרגה הגבוהה ביותר הופך למטרה בראש עץ התקיפה."],
    stride:["עברו רכיב אחרי רכיב בדיאגרמה.","שאלו על כל רכיב את שש השאלות של STRIDE.","כל \"כן\" סביר הוא איום: כתבו מה קורה, על מה הטענה נשענת, וכמה זה חמור."],
    tree:["בראש העץ שימו את המטרה של התוקף.","מתחתיה, הדרכים להגיע אליה. בכל צומת: \"אחד מספיק\" או \"צריך את כולם\".","חפשו את הקבוצה הקטנה ביותר של הגנות שחוסמת את כל המסלולים."],
    risk:["לכל איום תנו סבירות מ-1 עד 5 והשפעה מ-1 עד 5.","המכפלה קובעת את הסדר: 15 ומעלה קריטי, 10 ומעלה גבוה, 6 ומעלה בינוני.","דרגו שוב בהנחה שההגנות פועלות. מה שנשאר גבוה הוא הסיכון השיורי."],
    mitigations:["לכל איום לפחות הגנה אחת: מניעה, זיהוי או תגובה.","בדקו כיסוי: אין איום בלי הגנה, ואין הגנה שלא מכסה כלום.","לכל הגנה רשמו מי אחראי עליה ומה המגבלה שלה."],
    attack:["לכל איום חפשו טכניקה מתאימה בקטלוג MITRE ATT&CK.","השתמשו במזהה (כמו T0859) כדי לדבר באותה שפה עם צוותי זיהוי.","איום שאין לו טכניקה בקטלוג הוא ממצא בפני עצמו."]
  };
  var ICON = {
    entity:'<svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="10" width="30" height="20" rx="1"/><path d="M12 30v4M28 30v4"/></svg>',
    process:'<svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="32" height="18" rx="9"/><path d="M14 20h12M22 16l4 4-4 4"/></svg>',
    store:'<svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2"><path d="M36 11H6v18h30M6 11v18"/><path d="M12 17h16M12 23h10" opacity=".6"/></svg>',
    adversary:'<svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="2"><circle cx="20" cy="20" r="13" stroke-dasharray="4 3"/><circle cx="20" cy="20" r="5"/><path d="M20 3v8M20 29v8M3 20h8M29 20h8"/></svg>',
    prevent:'<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 3l11 4v8c0 7-4.7 12-11 14C9.7 27 5 22 5 15V7z"/><path d="M11 16l3.5 3.5L21 13"/></svg>',
    detect:'<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 16s5-9 14-9 14 9 14 9-5 9-14 9S2 16 2 16z"/><circle cx="16" cy="16" r="4.5"/></svg>',
    respond:'<svg viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 24V14a8 8 0 0 1 16 0v10"/><path d="M5 24h22M13 28h6M16 2v3M4.5 7l2 2M27.5 7l-2 2"/></svg>',
    lock:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
    shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
    tk:{"טכנולוגי":"⌁","אנושי":"◉","מקצועי":"▣"}
  };

  var item, nodesById = {}, threatsById = {}, mitsById = {}, charsById = {};
  var state = {node:null, on:{}};
  var listeners = [];
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  function emit(){ listeners.forEach(function(f){ f(); }); }

  /* ---------- helpers ---------- */
  function s(tag, attrs){
    var el = document.createElementNS(SVGNS, tag), k;
    for (k in attrs || {}) if (attrs[k] != null) el.setAttribute(k, attrs[k]);
    for (var i = 2; i < arguments.length; i++){ var c = arguments[i]; if (c != null) el.append(c.nodeType ? c : document.createTextNode(String(c))); }
    return el;
  }
  function icon(svg, cls){ return h("span", {class:cls || "ico", "aria-hidden":"true", html:svg}); }
  function riskLevel(l, i){
    var x = l * i;
    if (x >= 15) return {n:5, he:"קריטי"};
    if (x >= 10) return {n:4, he:"גבוה"};
    if (x >= 6) return {n:3, he:"בינוני"};
    if (x >= 3) return {n:2, he:"נמוך-בינוני"};
    return {n:1, he:"נמוך"};
  }
  function riskPill(l, i){ var r = riskLevel(l, i); return h("span", {class:"risk r" + r.n, title:"סבירות " + l + " × השפעה " + i}, r.he); }
  function sb(cat){ return h("span", {class:"sb " + cat, title:CAT_EN[cat] + " · " + CAT_HE[cat]}, cat); }
  function flash(el){ if (!el) return; el.classList.remove("flash"); void el.offsetWidth; el.classList.add("flash"); setTimeout(function(){ el.classList.remove("flash"); }, 1700); }
  function goTo(id){
    var el = document.getElementById(id); if (!el) return;
    el.scrollIntoView({behavior:reduce ? "auto" : "smooth", block:"center"});
    flash(el);
  }
  function termBtn(id, label){
    if (!Desk.glossary[id]) return h("span", null, label);
    return h("span", {class:"term", role:"button", tabindex:"0", "data-term":id, "aria-expanded":"false", "aria-haspopup":"dialog"}, label);
  }
  function qmark(id){
    if (!Desk.glossary[id]) return null;
    return h("span", {class:"term qmark", role:"button", tabindex:"0", "data-term":id, "aria-expanded":"false", "aria-haspopup":"dialog",
      "aria-label":"מה זה " + Desk.glossary[id].term + "?"}, "?");
  }
  function section(id, no, title, intro, wide){
    var sec = h("section", {id:id, "aria-labelledby":id + "-h", class:"sec"});
    var w = h("div", {class:wide ? "wrap " + wide : "wrap"});
    w.append(h("div", {class:"sec-head"}, no ? h("span", {class:"no", dir:"ltr"}, "File " + no) : null,
      h("h2", {id:id + "-h", class:"redact"}, title)));
    if (intro) w.append(h("p", {class:"sec-intro"}, rich(intro)));
    var mk = (item.method && item.method[id]) || METHOD[id];
    if (mk) w.append(h("div", {class:"method", role:"note", "aria-label":"השיטה, כדי לעשות את זה בעצמכם"},
      h("span", {class:"mt"}, h("span", {dir:"ltr", class:"lat"}, "Method"), " איך עושים את זה בעצמכם"),
      h("ol", null, mk.map(function(t){ return h("li", null, rich(t)); }))));
    sec.append(w); sec._w = w; observe(sec); return sec;
  }
  function bridge(key){
    var t = item.bridges && item.bridges[key];
    return t ? h("div", {class:"wrap"}, h("div", {class:"bridge", role:"note"}, h("span", null, rich(t)))) : null;
  }
  function threatsOn(nodeId){ return item.threats.filter(function(t){ return t.node === nodeId; }); }
  function avatar(id, size){
    var c = charsById[id]; if (!c) return null;
    var ini = c.initials || c.name.trim().charAt(0);
    var el = h("span", {class:"av" + (size ? " " + size : ""), title:c.name + " · " + c.role, "aria-hidden":"true"}, ini);
    if (c.color) el.style.setProperty("--ac", c.color);
    return el;
  }
  function voice(v){
    if (!v) return null;
    var c = charsById[v.who];
    var bub = h("div", {class:"bub"},
      c ? h("b", null, c.name + " · " + c.role) : null, rich(v.text));
    if (c && c.color) bub.style.setProperty("--ac", c.color);
    return h("div", {class:"voice"}, avatar(v.who), bub);
  }

  /* ---------- reveal on scroll ---------- */
  var io = null;
  function observe(el){
    if (!el) return el;
    if (reduce || !("IntersectionObserver" in window)){ el.classList.add("in"); if (el._onIn) setTimeout(el._onIn, 0); return el; }
    if (!io) io = new IntersectionObserver(function(es){
      es.forEach(function(e){ if (e.isIntersecting){ e.target.classList.add("in"); io.unobserve(e.target); if (e.target._onIn) e.target._onIn(); } });
    }, {rootMargin:"0px 0px -12% 0px", threshold:.08});
    io.observe(el);
    return el;
  }

  /* ---------- banner / trailer ---------- */
  function banner(){
    var it = item, w = h("header", {class:"wrap banner"});
    var lv = riskLevel(it.risk.l, it.risk.i);
    w.append(h("div", {class:"case-line", dir:"ltr"},
      h("span", null, h("span", {class:"k"}, "Case file"), " · TM-" + it.id),
      h("span", null, "Issue " + it.issue),
      h("span", null, "Threats " + it.threats.length),
      h("span", null, "Controls " + it.mitigations.items.length)));
    w.append(h("h1", null, it.title));
    w.append(h("p", {class:"sub"}, rich(it.subtitle)));
    w.append(h("div", {class:"top"}, riskPill(it.risk.l, it.risk.i), h("span", {class:"tag"}, it.domain), h("span", {class:"tag"}, it.region),
      (it.tags || []).slice(0, 3).map(function(t){ return h("span", {class:"tag"}, "#" + t); })));
    var dl = h("dl", {class:"facts"});
    (it.facts || []).forEach(function(f){ dl.append(h("div", null, h("dt", null, f.k, f.term ? qmark(f.term) : null), h("dd", null, rich(f.v)))); });
    w.append(dl);
    w.append(h("p", {class:"defensive"}, icon(ICON.shield, "s"), h("span", null, rich(it.defensiveNote))));
    return w;
  }
  function trailer(){
    var sec = h("section", {class:"wrap trailer-box", "aria-label":"פתיחה"});
    sec.append(h("p", {class:"trailer rv"}, rich(item.trailer.text), h("span", {class:"q"}, rich(item.trailer.question))));
    observe(sec.firstChild);
    return sec;
  }

  /* ---------- minute: cast + scenes ---------- */
  function scene(sc){
    if (!sc) return null;
    var box = h("figure", {class:"scene hud", "aria-label":sc.title || "המחשה"});
    if (sc.title) box.append(h("figcaption", {class:"cap"}, h("span", null, sc.title), h("b", {dir:"ltr"}, sc.tag || "Scene")));
    var t = sc.type;
    if (t === "route"){
      var r = h("div", {class:"route"}, h("i", {class:"rail"}), h("i", {class:"pkt"}));
      (sc.stops || []).forEach(function(st, i){
        r.append(h("div", {class:"stop " + (st.tone || "")}, h("span", {class:"dot"}, st.icon || String(i + 1)), h("b", null, st.label), st.sub ? h("small", null, st.sub) : null));
      });
      box.append(r);
      if (sc.split && sc.split.length) box.append(h("div", {class:"split"}, h("b", null, sc.splitLabel || "מסלולים חשודים:"), sc.split.map(function(x){ return h("span", null, x); })));
    } else if (t === "stats"){
      var g = h("div", {class:"stats"});
      (sc.items || []).forEach(function(x){
        var bar = x.bar != null ? h("div", {class:"bar"}, h("i", {"data-w":Math.max(2, Math.min(100, x.bar)) + "%"})) : null;
        g.append(h("div", {class:"stat " + (x.tone || "")}, h("div", {class:"v", dir:Desk.autoDir(x.value)}, x.value), h("div", {class:"l"}, rich(x.label)), bar));
      });
      box.append(g);
      box._onIn = function(){ box.querySelectorAll(".bar i").forEach(function(i){ i.style.width = i.getAttribute("data-w"); }); };
    } else if (t === "timeline"){
      var tl = h("div", {class:"tline"});
      (sc.events || []).forEach(function(e){ tl.append(h("div", {class:"ev " + (e.tone || "")}, h("b", {dir:"ltr"}, e.date), rich(e.label))); });
      box.append(tl);
    } else if (t === "versus"){
      function side(x){ return h("div", {class:"side " + (x.tone || "")}, h("h4", null, x.title), h("ul", null, (x.items || []).map(function(i){ return h("li", null, rich(i)); }))); }
      box.append(h("div", {class:"versus"}, side(sc.left), h("span", {class:"vs", dir:"ltr"}, "VS"), side(sc.right)));
    } else if (t === "chat"){
      var ch = h("div", {class:"chat"});
      (sc.msgs || []).forEach(function(m){
        var c = charsById[m.who];
        ch.append(h("div", {class:"msg" + (m.side === "r" ? " r" : "")}, avatar(m.who, "sm"), h("div", {class:"bub"}, c ? h("b", null, c.name) : null, rich(m.text))));
      });
      box.append(ch);
    }
    observe(box);
    return box;
  }
  function minute(){
    var sec = section("minute", null, "הסיפור בדקה");
    var w = sec._w; w.classList.add("minute");
    if (item.characters && item.characters.length){
      w.append(h("p", {class:"small muted", style:{margin:"0 0 6px"}}, "מי מלווה אותנו בתיק:"));
      w.append(h("div", {class:"cast"}, item.characters.map(function(c){
        return h("div", {class:"person"}, avatar(c.id), h("span", {class:"who"}, h("b", null, c.name), h("small", null, c.role)), h("span", {class:"fict"}, "בדוי"));
      })));
    }
    item.minute.forEach(function(p, i){
      var o = typeof p === "string" ? {text:p} : p;
      var txt = h("div", {class:"ptext"}, Desk.p(o.text), voice(o.voice));
      var sc = Array.isArray(o.scene) ? h("div", {class:"scenes"}, o.scene.map(scene)) : scene(o.scene);
      var row = h("div", {class:"para rv" + (sc ? "" : " solo")}, txt, sc);
      observe(row);
      w.append(row);
      if (item.quote && item.quote.after === i){
        w.append(h("figure", {class:"pull rv"}, h("blockquote", {style:{margin:0}}, h("q", {lang:"en", dir:"ltr"}, item.quote.text)),
          h("figcaption", {class:"who"}, rich(item.quote.who))));
        observe(w.lastChild);
      }
    });
    if (item.claimsNote) w.append(h("div", {class:"callout warn"}, Desk.p(item.claimsNote)));
    return sec;
  }

  /* ---------- 01 DFD: guided build + in-frame inspector ---------- */
  function rectEdge(c, hw, hh, tx, ty){
    var dx = tx - c.x, dy = ty - c.y;
    if (!dx && !dy) return {x:c.x, y:c.y};
    var t = Math.min(dx ? hw / Math.abs(dx) : Infinity, dy ? hh / Math.abs(dy) : Infinity);
    return {x:c.x + dx * t, y:c.y + dy * t};
  }
  function autoSteps(d){
    var st = [];
    d.boundaries.forEach(function(b){
      var ns = d.nodes.filter(function(n){ return n.zone === b.id; }).map(function(n){ return n.id; });
      if (ns.length) st.push({title:b.label, text:"הרכיבים בתוך הגבול \"" + b.label + "\".", add:["zone:" + b.id].concat(ns), focus:ns});
    });
    return st;
  }
  function dfdSection(){
    var d = item.dfd;
    var sec = section("dfd", "01", d.title, d.intro, "wrap-dfd");
    var w = sec._w;
    var steps = (d.steps && d.steps.length) ? d.steps : autoSteps(d);
    var total = steps.length;            // index === total → explore mode
    var cur = 0, prevVisible = {};
    var card = h("div", {class:"dfd-card hud"});
    var legend = h("div", {class:"legend", role:"group", "aria-label":"מקרא. לחיצה מסבירה כל סימן"},
      lg("dfd-entity", '<svg viewBox="0 0 26 14"><rect x="1" y="2" width="24" height="10" rx="1" fill="none" stroke="currentColor" stroke-width="1.4"/></svg>', "ישות חיצונית"),
      lg("dfd-process", '<svg viewBox="0 0 26 14"><rect x="1" y="2" width="24" height="10" rx="5" fill="none" stroke="var(--accent)" stroke-width="1.4"/></svg>', "תהליך"),
      lg("dfd-store", '<svg viewBox="0 0 26 14"><path d="M25 2H1M25 12H1M1 2v10" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>', "מאגר"),
      lg("trust-boundary", '<svg viewBox="0 0 26 14"><path d="M1 7h24" stroke="var(--boundary)" stroke-width="1.6" stroke-dasharray="5 3"/></svg>', "גבול אמון"),
      lg("dfd-flow", '<svg viewBox="0 0 26 14"><path d="M1 7h22" stroke="var(--flow)" stroke-width="1.6"/><path d="M19 3l5 4-5 4" fill="none" stroke="var(--flow)" stroke-width="1.6"/></svg>', "זרימה"));
    function lg(term, svg, label){
      return h("button", {type:"button", class:"term", "data-term":term, "aria-expanded":"false", "aria-haspopup":"dialog"}, h("span", {html:svg, "aria-hidden":"true"}), label);
    }
    card.append(h("div", {class:"dfd-head"}, legend, h("span", {class:"lat", dir:"ltr"}, "DFD · trust boundaries · " + d.nodes.length + " parts · " + d.flows.length + " flows")));
    var stage = h("div", {class:"dfd-stage"});
    var holder = h("div", {class:"dfd-holder"});
    var side = h("div", {class:"dfd-side", "aria-live":"polite"});
    stage.append(holder, side);
    card.append(stage);
    var fl = h("ol", {class:"flow-list", "aria-label":"זרימות נתונים"});
    d.flows.forEach(function(f, i){
      fl.append(h("li", {class:f.kind ? "k-" + f.kind : "", "data-flow":f.id}, h("span", {class:"n"}, i + 1),
        h("span", null, h("b", null, nodesById[f.from].label + " ← " + nodesById[f.to].label), ": ", rich(f.label))));
    });
    card.append(h("details", {class:"dfd-flows"}, h("summary", null, "כל הזרימות כטקסט (" + d.flows.length + ")"), fl));
    w.append(card);

    // which step introduces each element
    var introAt = {};
    steps.forEach(function(st, i){ (st.add || []).forEach(function(id){ if (introAt[id] == null) introAt[id] = i; }); });
    function nodeStep(id){ return introAt[id] != null ? introAt[id] : total; }
    function visibleAt(idx){
      var vis = {};
      d.nodes.forEach(function(n){ if (nodeStep(n.id) <= idx) vis[n.id] = true; });
      d.boundaries.forEach(function(b){
        var key = "zone:" + b.id;
        var byNode = d.nodes.some(function(n){ return n.zone === b.id && vis[n.id]; });
        if ((introAt[key] != null && introAt[key] <= idx) || byNode) vis[key] = true;
      });
      d.flows.forEach(function(f){
        var at = introAt[f.id];
        if (at != null ? at <= idx : (vis[f.from] && vis[f.to])) vis[f.id] = true;
      });
      return vis;
    }

    var svgEl = null, curMode = null;
    function draw(){
      var cw = card.clientWidth || w.clientWidth;
      stage.classList.toggle("tallmode", cw < 900);
      var width = holder.clientWidth || cw;
      var mode = width >= 640 ? "wide" : "tall";
      if (mode === curMode && svgEl){ apply(false); return; }
      curMode = mode;
      var L = d.layouts[mode];
      var svg = s("svg", {class:"dfd " + mode, viewBox:"0 0 " + L.w + " " + L.h, role:"group", "aria-label":d.aria});
      var defs = s("defs");
      [["a-n","var(--flow)"],["a-t","var(--flow-threat)"],["a-i","var(--flow-influence)"]].forEach(function(m){
        defs.append(s("marker", {id:m[0] + "-" + mode, viewBox:"0 0 10 10", refX:"9", refY:"5", markerWidth:"7", markerHeight:"7", orient:"auto-start-reverse"},
          s("path", {d:"M0 0L10 5L0 10z", style:"fill:" + m[1]})));
      });
      svg.append(defs);
      var zonesG = s("g"), labelsG = s("g", {class:"zone-labels"}), flowsG = s("g"), nodesG = s("g");
      d.boundaries.forEach(function(b){
        var g = L.zones[b.id]; if (!g) return;
        zonesG.append(s("g", {class:"zone" + (b.inner ? " inner" : ""), "data-el":"zone:" + b.id}, s("rect", {x:g.x, y:g.y, width:g.w, height:g.h, rx:12})));
        labelsG.append(s("g", {class:"zone" + (b.inner ? " inner" : ""), "data-el":"zone:" + b.id},
          s("text", {class:"zone-label", x:g.lx, y:g.ly, "text-anchor":g.anchor || "start", direction:"rtl"}, b.label)));
      });
      var nw = L.nw, nh = L.nh;
      d.flows.forEach(function(f, i){
        var a = L.nodes[f.from], b = L.nodes[f.to];
        var via = (L.via && L.via[f.id]) || [];
        var pts = [a].concat(via, [b]);
        var p0 = rectEdge(a, nw/2 + 2, nh/2 + 2, pts[1].x, pts[1].y);
        var pn = rectEdge(b, nw/2 + 5, nh/2 + 5, pts[pts.length-2].x, pts[pts.length-2].y);
        var all = [p0].concat(via, [pn]);
        var dstr = all.map(function(p, k){ return (k ? "L" : "M") + p.x.toFixed(1) + " " + p.y.toFixed(1); }).join(" ");
        var mk = f.kind === "threat" ? "a-t" : f.kind === "influence" ? "a-i" : "a-n";
        var g = s("g", {class:"flow " + (f.kind || ""), "data-el":f.id, "data-flow":f.id, "data-from":f.from, "data-to":f.to});
        g.append(s("title", null, (i + 1) + ". " + f.label));
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
        var g = s("g", {class:"node " + n.kind + (n.adversary ? " adversary" : ""), tabindex:"0", role:"button", "data-el":n.id, "data-node":n.id,
          "aria-label":n.label + " · " + KIND_HE[n.kind] + (tc ? " · " + tc + " איומים" : ""), "aria-pressed":"false"});
        g.append(s("rect", {class:"focus-ring", x:x - 5, y:y - 5, width:nw + 10, height:nh + 10, rx:10}));
        if (n.kind === "store"){
          g.append(s("rect", {class:"shape", x:x, y:y, width:nw, height:nh}));
          g.append(s("path", {class:"rail", d:"M" + (x+nw) + " " + y + "H" + x + "M" + (x+nw) + " " + (y+nh) + "H" + x + "M" + (x+nw) + " " + y + "V" + (y+nh), fill:"none"}));
        } else g.append(s("rect", {class:"shape", x:x, y:y, width:nw, height:nh, rx:n.kind === "process" ? nh/2 : 3}));
        var hasSub = !!n.sub;
        g.append(s("text", {x:c.x, y:c.y + (hasSub ? -2 : 5), "text-anchor":"middle", direction:"rtl"}, n.label));
        if (hasSub) g.append(s("text", {class:"sub", x:c.x, y:c.y + 14, "text-anchor":"middle", direction:"rtl"}, n.sub));
        if (tc){
          g.append(s("circle", {class:"count", cx:x + 2, cy:y + 2, r:10}));
          g.append(s("text", {class:"count-t", x:x + 2, y:y + 6, "text-anchor":"middle"}, tc));
        }
        g.addEventListener("click", function(){ pick(n.id); });
        g.addEventListener("keydown", function(e){ if (e.key === "Enter" || e.key === " "){ e.preventDefault(); pick(n.id); } });
        nodesG.append(g);
      });
      svg.append(zonesG, flowsG, labelsG, nodesG);
      svg.setAttribute("preserveAspectRatio", "xMidYMid meet");
      svg.style.aspectRatio = L.w + " / " + L.h;
      svg._full = [0, 0, L.w, L.h]; svg._vb = svg._full.slice();
      holder.innerHTML = ""; holder.append(svg); svgEl = svg;
      prevVisible = {};
      apply(true);
    }
    function apply(animate){
      if (!svgEl) return;
      var vis = visibleAt(cur), st = steps[cur] || {}, focus = {};
      (st.focus || []).forEach(function(id){ focus[id] = true; });
      svgEl.querySelectorAll("[data-el]").forEach(function(el){
        var id = el.getAttribute("data-el"), on = !!vis[id];
        el.classList.toggle("off", !on);
        el.classList.remove("fresh");
        if (on && !prevVisible[id] && animate !== false){ void el.getBBox; el.classList.add("fresh"); }
        el.classList.toggle("focus", !!focus[id] && cur < total);
      });
      prevVisible = vis;
      camera();
      var sel = state.node;
      svgEl.querySelectorAll(".node").forEach(function(g){
        var on = g.getAttribute("data-node") === sel;
        g.classList.toggle("sel", on); g.setAttribute("aria-pressed", on ? "true" : "false");
      });
      if (sel){
        svgEl.querySelectorAll(".node").forEach(function(g){
          var nid = g.getAttribute("data-node");
          var linked = nid === sel || d.flows.some(function(f){ return (f.from === sel && f.to === nid) || (f.to === sel && f.from === nid); });
          g.classList.toggle("dim", !linked);
        });
        svgEl.querySelectorAll(".flow").forEach(function(g){
          var on = g.getAttribute("data-from") === sel || g.getAttribute("data-to") === sel;
          g.classList.toggle("dim", !on); g.classList.toggle("hi", on);
        });
      } else svgEl.querySelectorAll(".dim,.hi").forEach(function(g){ g.classList.remove("dim"); g.classList.remove("hi"); });
      renderSide();
    }
    var camRaf = 0;
    function camera(){
      var full = svgEl._full, target = full;
      if (cur < total){
        var x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
        svgEl.querySelectorAll("[data-el]:not(.off)").forEach(function(el){
          try { var b = el.getBBox(); if (!b.width && !b.height) return;
            x0 = Math.min(x0, b.x); y0 = Math.min(y0, b.y); x1 = Math.max(x1, b.x + b.width); y1 = Math.max(y1, b.y + b.height); } catch(e){}
        });
        if (isFinite(x0)){
          var pad = 40, w0 = x1 - x0 + pad * 2, h0 = y1 - y0 + pad * 2;
          var ar = full[2] / full[3];
          var minW = full[2] * .4;
          var vw = Math.max(w0, h0 * ar, minW), vh = vw / ar;
          var cx = (x0 + x1) / 2, cy = (y0 + y1) / 2;
          var vx = Math.max(0, Math.min(cx - vw / 2, full[2] - vw)), vy = Math.max(0, Math.min(cy - vh / 2, full[3] - vh));
          if (vw >= full[2]) { vx = 0; vw = full[2]; vh = full[3]; vy = 0; }
          target = [vx, vy, vw, vh];
        }
      }
      var from = svgEl._vb.slice(), t0 = performance.now(), dur = reduce ? 0 : 700;
      cancelAnimationFrame(camRaf);
      (function tick(now){
        var k = dur ? Math.min(1, (now - t0) / dur) : 1, e = k < .5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2;
        var vb = from.map(function(v, i){ return v + (target[i] - v) * e; });
        svgEl._vb = vb; svgEl.setAttribute("viewBox", vb.map(function(v){ return v.toFixed(1); }).join(" "));
        if (k < 1) camRaf = requestAnimationFrame(tick);
      })(t0);
    }
    function navBar(){
      var dots = h("span", {class:"dots", "aria-hidden":"true"});
      for (var i = 0; i <= total; i++) dots.append(h("i", {class:i <= cur ? "on" : ""}));
      var prev = h("button", {type:"button", class:"btn", "data-act":"prev", disabled:cur === 0 && !state.node, onclick:function(){
        if (state.node){ state.node = null; emit(); return; }
        if (cur > 0){ cur--; apply(); } }}, state.node ? "→ חזרה" : "→ הקודם");
      var next = cur < total ? h("button", {type:"button", class:"btn primary", "data-act":"next", onclick:function(){ state.node = null; cur++; apply(); emit(); }}, cur === total - 1 ? "כל המערכת ←" : "הבא ←") : null;
      var skip = cur < total - 1 ? h("button", {type:"button", class:"btn", "data-act":"all", onclick:function(){ state.node = null; cur = total; apply(); emit(); }, title:"לדלג לתמונה המלאה"}, "הכל") : null;
      return h("div", {class:"dfd-nav"}, prev, dots, skip, next);
    }
    function renderSide(){
      side.innerHTML = "";
      if (state.node){
        var n = nodesById[state.node], ts = threatsOn(n.id);
        var b = d.boundaries.filter(function(x){ return x.id === n.zone; })[0];
        var ins = h("div", {class:"ins-h"}, h("span", {class:"step-k", dir:"ltr"}, "Inspect · " + n.id),
          h("h3", null, n.label),
          h("div", {class:"meta"}, h("span", {class:"tag"}, termBtn(KIND_TERM[n.kind], KIND_HE[n.kind])), b ? h("span", {class:"tag"}, b.label) : null,
            n.adversary ? h("span", {class:"tag", style:{color:"var(--boundary)"}}, "יריב משוער") : null));
        side.append(ins, Desk.p(n.desc));
        var ins2 = d.flows.filter(function(f){ return f.to === n.id; }).length, outs = d.flows.filter(function(f){ return f.from === n.id; }).length;
        side.append(h("p", {class:"small muted"}, "זרימות: " + ins2 + " נכנסות, " + outs + " יוצאות (מודגשות בדיאגרמה)."));
        if (ts.length){
          side.append(h("p", {class:"small", style:{fontWeight:"700"}}, ts.length + " איומים על הרכיב:"));
          side.append(h("ul", {class:"tl"}, ts.map(function(t){
            return h("li", null, sb(t.cat), h("button", {type:"button", onclick:function(){ goTo("th-" + t.id); }}, t.title));
          })));
        } else side.append(h("p", {class:"small muted"}, "אין איום שממופה ישירות לרכיב. הוא כאן כי זרימות עוברות דרכו."));
      } else if (cur < total){
        var st = steps[cur];
        side.append(h("span", {class:"step-k", dir:"ltr"}, "Step " + (cur + 1) + " / " + total), h("h3", null, st.title), Desk.p(st.text));
        if (cur === 0) side.append(h("p", {class:"dfd-hint"}, "אפשר ללחוץ על כל רכיב שכבר מופיע, ועל סימני המקרא למעלה."));
      } else {
        side.append(h("span", {class:"step-k", dir:"ltr"}, "Full system"), h("h3", null, "כל המערכת לפניכם"), Desk.p(d.hint));
        var top = d.nodes.slice().sort(function(a, b){ return threatsOn(b.id).length - threatsOn(a.id).length; })[0];
        if (top && threatsOn(top.id).length) side.append(h("p", {class:"small"}, "הכי הרבה איומים: ",
          h("button", {type:"button", class:"mchip", onclick:function(){ pick(top.id); }}, top.label + " (" + threatsOn(top.id).length + ")")));
      }
      side.append(navBar());
    }
    function pick(id){
      if (d.nodes.filter(function(n){ return n.id === id; }).length === 0) return;
      state.node = state.node === id ? null : id;
      emit();
    }
    listeners.push(function(){ apply(false); });
    var lastW = 0;
    if (window.ResizeObserver){
      new ResizeObserver(function(es){ var nwid = Math.round(es[0].contentRect.width); if (nwid !== lastW){ lastW = nwid; draw(); } }).observe(card);
    } else window.addEventListener("resize", draw);
    setTimeout(draw, 0);
    sec._pick = pick;
    return sec;
  }

  /* ---------- 02 assets: vault ---------- */
  function assetsSection(){
    var a = item.assets;
    var sec = section("assets", "02", a.title, a.intro);
    var g = h("div", {class:"vault"});
    a.items.forEach(function(x){
      var c = x.who ? charsById[x.who] : null;
      var pips = h("span", {class:"pips", "aria-label":"חשיבות " + x.value + " מתוך 3"}, [1,2,3].map(function(k){ return h("i", {class:k <= x.value ? "on" : ""}); }));
      var cardEl = h("article", {class:"vcard hud rv"});
      var btn = h("button", {type:"button", class:"breach", "aria-pressed":"false", onclick:function(){
        var on = !cardEl.classList.contains("broken"); cardEl.classList.toggle("broken", on);
        btn.setAttribute("aria-pressed", on ? "true" : "false"); btn.textContent = on ? "שחזור" : "מה אם זה נפרץ?"; }}, "מה אם זה נפרץ?");
      [
        h("div", {class:"vhead"}, h("h3", null, x.name), pips),
        h("div", {class:"owner"}, c ? avatar(c.id, "sm") : null, h("span", null, "שייך ל: ", rich(x.owner))),
        x.say ? h("p", {class:"say"}, c ? h("b", {style:{display:"block",fontSize:".76rem",color:c.color}}, c.name) : null, "“", rich(x.say), "”") : null,
        h("p", {class:"why"}, rich(x.why)),
        h("p", {class:"lost", role:"status"}, rich(x.loss)),
        btn].forEach(function(n){ if (n) cardEl.append(n); });
      observe(cardEl);
      g.append(cardEl);
    });
    sec._w.append(g);
    return sec;
  }

  /* ---------- 03 STRIDE by component ---------- */
  function strideSection(){
    var st = item.stride;
    var sec = section("stride", "03", st.title, st.intro);
    var w = sec._w;
    w.append(h("div", {class:"legend6", "aria-label":"תזכורת: שש האותיות"}, CATS.map(function(c){
      var n = item.threats.filter(function(t){ return t.cat === c; }).length;
      return h("div", {class:"l c-" + c}, h("b", {dir:"ltr"}, c), h("span", null, CAT_HE[c] + (n ? " · " + n : "")), h("small", null, CAT_Q[c]));
    })));
    var comps = item.dfd.nodes.filter(function(n){ return threatsOn(n.id).length; })
      .sort(function(a, b){ return threatsOn(b.id).length - threatsOn(a.id).length; });
    var rail = h("nav", {class:"rail-nav", "aria-label":"רכיבים"});
    comps.forEach(function(n){ rail.append(h("a", {href:"#comp-" + n.id, "data-c":n.id, onclick:function(e){ e.preventDefault(); goTo("comp-" + n.id); }}, n.label, h("i", null, threatsOn(n.id).length))); });
    w.append(rail);
    comps.forEach(function(n){
      var b = item.dfd.boundaries.filter(function(x){ return x.id === n.zone; })[0];
      var ts = threatsOn(n.id).sort(function(a, b){ return CATS.indexOf(a.cat) - CATS.indexOf(b.cat); });
      var block = h("div", {class:"comp", id:"comp-" + n.id, "data-c":n.id},
        h("div", {class:"comp-h"}, icon(n.adversary ? ICON.adversary : ICON[n.kind], "kind" + (n.adversary ? " adv" : "")),
          h("div", null, h("h3", null, n.label), h("small", null, KIND_HE[n.kind] + (b ? " · " + b.label : "") + (n.sub ? " · " + n.sub : ""))),
          h("span", {class:"n"}, ts.length + " איומים")));
      ts.forEach(function(t){
        var card = h("article", {class:"tcard card threat c-" + t.cat + " rv", id:"th-" + t.id, "data-node":t.node, "data-cat":t.cat},
          h("div", {class:"letter"}, h("b", {dir:"ltr"}, t.cat), h("span", null, CAT_HE[t.cat]), h("small", null, CAT_Q[t.cat])),
          h("div", {class:"tb"},
            h("div", {class:"th"}, h("h4", null, h("span", {class:"tid"}, t.id + " "), t.title), riskPill(t.l, t.i)),
            Desk.p(t.desc),
            h("details", null, h("summary", null, "על מה זה נשען", t.claim ? h("span", {class:"claim"}, t.claim) : null), Desk.p(t.evidence)),
            h("div", {class:"tfoot"},
              h("span", {class:"shift"}, "אחרי ההגנות: ", riskPill(t.l, t.i), h("span", {class:"arr", "aria-hidden":"true"}, "←"), riskPill(t.res.l, t.res.i)),
              h("span", {class:"shift"}, "הגנות:", t.mits.map(function(m){ return h("button", {type:"button", class:"mchip", title:mitsById[m].short || "", onclick:function(){ goTo("m-" + m); }}, m); })))));
        observe(card);
        block.append(card);
      });
      w.append(block);
    });
    if ("IntersectionObserver" in window){
      var spy = new IntersectionObserver(function(es){
        es.forEach(function(e){ if (e.isIntersecting){ var id = e.target.getAttribute("data-c");
          rail.querySelectorAll("a").forEach(function(a){ var on = a.getAttribute("data-c") === id; a.classList.toggle("on", on); if (on && a.scrollIntoView && rail.scrollWidth > rail.clientWidth) rail.scrollLeft = a.offsetLeft - 40; }); } });
      }, {rootMargin:"-40% 0px -55% 0px"});
      w.querySelectorAll(".comp").forEach(function(c){ spy.observe(c); });
    }
    return sec;
  }

  /* ---------- 04 attack tree (org chart) ---------- */
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
    return best || [];
  }
  function plain(t){ return String(t || "").replace(/\*\*/g, ""); }
  function treeSection(){
    var t = item.tree;
    var sec = section("tree", "04", t.title, t.intro, "wrap-tree");
    var w = sec._w;
    var ms = treeMits(t.root);
    var minCut = minimalCut(t.root, ms);
    var goal = h("div", {class:"goal", "aria-live":"polite"});
    var bar = h("div", {class:"tree-bar", role:"group", "aria-label":"הגנות להפעלה"}, h("span", {class:"lbl", dir:"ltr"}, "Controls"));
    ms.forEach(function(m){
      bar.append(h("button", {type:"button", class:"dchip", "aria-pressed":"false", "data-m":m, title:plain(mitsById[m].name), onclick:function(){ state.on[m] = !state.on[m]; emit(); }},
        h("span", {class:"mid"}, m), mitsById[m].short || plain(mitsById[m].name)));
    });
    var timer = null;
    var tools = h("div", {class:"tree-bar"},
      h("button", {type:"button", class:"btn primary", "data-act":"mincut", onclick:function(){
        clearTimeout(timer); state.on = {}; emit();
        var k = 0; (function step(){ if (k >= minCut.length) return; state.on[minCut[k++]] = true; emit(); timer = setTimeout(step, reduce ? 0 : 650); })(); }}, "הראו לי את החסימה הקטנה ביותר"),
      h("button", {type:"button", class:"btn", onclick:function(){ clearTimeout(timer); state.on = {}; emit(); }}, "איפוס"));
    w.append(h("p", {class:"small muted", style:{margin:"0 0 10px"}}, rich(t.howto)));
    w.append(goal, bar, tools);
    w.append(h("div", {class:"gate-key"},
      h("span", null, h("span", {class:"g or", style:{font:"700 .66rem var(--font-mono)",padding:"2px 6px",background:"color-mix(in srgb,var(--i) 18%,transparent)",color:"var(--i)",borderRadius:"2px"}}, "אחד מספיק"), "כל ענף לבד מגיע ליעד"),
      h("span", null, h("span", {class:"g and", style:{font:"700 .66rem var(--font-mono)",padding:"2px 6px",background:"color-mix(in srgb,var(--amber) 18%,transparent)",color:"var(--amber)",borderRadius:"2px"}}, "צריך את כולם"), "חוסמים צעד אחד, והענף נסגר"),
      h("span", null, icon(ICON.lock, "s"), "חסום")));
    var org = h("div", {class:"org hud", style:{padding:"18px 10px"}});
    function build(n, depth){
      var gate = n.children ? (n.gate === "AND" ? "and" : "or") : "leaf";
      var gl = n.children ? (n.gate === "AND" ? "צריך את כולם" : "אחד מספיק") : "צעד";
      var box = h("div", {class:"tn" + (depth === 0 ? " root" : depth === 1 ? " branch" : ""), "data-id":n.id},
        h("span", {class:"lock", html:ICON.lock, "aria-hidden":"true"}),
        h("span", {class:"g " + gate}, gl),
        h("span", {class:"lb"}, rich(n.short || n.label)),
        n.legal ? h("span", {class:"legal"}, n.legal) : null,
        (n.mits && n.mits.length) ? h("span", {class:"ms"}, n.mits.map(function(m){
          return h("button", {type:"button", "data-m":m, title:plain(mitsById[m].name), onclick:function(){ state.on[m] = !state.on[m]; emit(); }}, m);
        })) : null);
      if (n.short && n.label) box.setAttribute("title", plain(n.label));
      var li = h("li", null, box);
      if (n.children){ var sub = h("ul"); n.children.forEach(function(c){ sub.append(build(c, depth + 1)); }); li.append(sub); }
      n._el = box; n._li = li;
      return li;
    }
    org.append(h("ul", null, build(t.root, 0)));
    w.append(org);
    var ins = h("div", {class:"callout insight"}, Desk.p(t.insight));
    w.append(ins);
    function walk(n, f){ f(n); (n.children || []).forEach(function(c){ walk(c, f); }); }
    function update(){
      evalNode(t.root);
      var any = ms.some(function(m){ return state.on[m]; });
      walk(t.root, function(n){
        n._el.classList.toggle("blocked", n._blocked);
        n._el.classList.toggle("open", any && !n._blocked);
        n._li.classList.toggle("open-path", any && !n._blocked);
        n._el.querySelectorAll(".ms button").forEach(function(b){ var on = !!state.on[b.getAttribute("data-m")]; b.classList.toggle("on", on); b.setAttribute("aria-pressed", on ? "true" : "false"); });
      });
      bar.querySelectorAll("button").forEach(function(b){ b.setAttribute("aria-pressed", state.on[b.getAttribute("data-m")] ? "true" : "false"); });
      var cnt = ms.filter(function(m){ return state.on[m]; }).length;
      var open = (t.root.children || []).filter(function(c){ return !c._blocked; }).map(function(c){ return c.short || plain(c.label); });
      goal.className = "goal" + (t.root._blocked ? " blocked" : "");
      goal.innerHTML = "";
      goal.append(h("span", {class:"lamp", "aria-hidden":"true"}),
        h("div", null, h("b", null, t.root._blocked ? "המטרה חסומה בכל המסלולים" : "המטרה עדיין בהישג יד"),
          h("small", null, t.root._blocked ? ("עם " + cnt + " הגנות" + (cnt === minCut.length ? ", המינימום האפשרי בעץ הזה." : ". אפשר גם עם " + minCut.length + ".")) :
            (cnt ? "עדיין פתוח: " : "מסלולים פתוחים: ") + open.join(" · "))));
    }
    listeners.push(update);
    update();
    return sec;
  }

  /* ---------- 05 risk: two matrices + floating detail ---------- */
  function riskSection(){
    var r = item.riskMatrix;
    var sec = section("risk", "05", r.title, r.intro, "wrap-dfd");
    var w = sec._w;
    var twin = h("div", {class:"rm-twin"});
    var pop = null, popFor = null;
    function closePop(){ if (pop){ pop.remove(); pop = null; } if (popFor){ popFor.setAttribute("aria-expanded", "false"); popFor = null; } }
    function openPop(btn, t){
      if (popFor === btn){ closePop(); return; }
      closePop();
      pop = h("div", {class:"rm-pop", role:"dialog", "aria-label":t.title},
        h("button", {type:"button", class:"x", "aria-label":"סגירה", onclick:closePop}, "×"),
        h("h4", null, sb(t.cat), h("span", null, t.id + " · " + t.title)),
        h("div", {class:"mv"}, "לפני ", riskPill(t.l, t.i), h("span", {dir:"ltr", class:"tid"}, t.l + "×" + t.i), " ← אחרי ", riskPill(t.res.l, t.res.i), h("span", {dir:"ltr", class:"tid"}, t.res.l + "×" + t.res.i)),
        t.resNote ? Desk.p(t.resNote) : h("p", {class:"muted"}, "ההגנות: " + t.mits.join(", ")),
        h("p", null, h("a", {href:"#th-" + t.id, onclick:function(e){ e.preventDefault(); closePop(); goTo("th-" + t.id); }}, "לכרטיס האיום ←")));
      twin.append(pop);
      popFor = btn; btn.setAttribute("aria-expanded", "true");
      var tr = twin.getBoundingClientRect(), br = btn.getBoundingClientRect();
      var pw = pop.offsetWidth, ph = pop.offsetHeight;
      var left = br.left - tr.left + br.width / 2 - pw / 2;
      left = Math.max(8, Math.min(left, tr.width - pw - 8));
      var top = br.bottom - tr.top + 8;
      if (top + ph > tr.height && br.top - tr.top - ph - 8 > 0) top = br.top - tr.top - ph - 8;
      pop.style.left = left + "px"; pop.style.top = top + "px";
    }
    document.addEventListener("click", function(e){ if (pop && !pop.contains(e.target) && !(e.target.closest && e.target.closest(".dotb"))) closePop(); });
    document.addEventListener("keydown", function(e){ if (e.key === "Escape") closePop(); });
    function matrix(title, tag, posFn){
      var grid = h("div", {class:"grid5", role:"grid", "aria-label":title});
      var cells = {};
      for (var imp = 5; imp >= 1; imp--) for (var lik = 1; lik <= 5; lik++){
        var lv = riskLevel(lik, imp);
        var c = h("div", {class:"cell r" + lv.n, role:"gridcell", "aria-label":"סבירות " + lik + ", השפעה " + imp});
        cells[lik + "-" + imp] = c; grid.append(c);
      }
      item.threats.forEach(function(t){
        var p = posFn(t);
        var b = h("button", {type:"button", class:"dotb c-" + t.cat, "data-t":t.id, "aria-expanded":"false", "aria-label":t.id + " " + t.title, title:t.title,
          onclick:function(e){ e.stopPropagation(); openPop(b, t); }}, t.id);
        b.addEventListener("mouseenter", function(){ twin.querySelectorAll('.dotb[data-t="' + t.id + '"]').forEach(function(x){ x.classList.add("hot"); }); });
        b.addEventListener("mouseleave", function(){ twin.querySelectorAll(".dotb.hot").forEach(function(x){ x.classList.remove("hot"); }); });
        cells[p.l + "-" + p.i].append(b);
      });
      return h("div", {class:"rm hud"}, h("h3", null, title, h("span", {class:"lat", dir:"ltr"}, tag)),
        h("div", {class:"rm-g"}, h("div", {class:"rm-y", "aria-hidden":"true"}, [5,4,3,2,1].map(function(n){ return h("span", null, n); })), grid),
        h("div", {class:"rm-x", "aria-hidden":"true"}, h("span"), [1,2,3,4,5].map(function(n){ return h("span", null, n); })),
        h("div", {class:"rm-axes"}, h("span", null, "↑ השפעה"), h("span", null, "סבירות →")));
    }
    twin.append(matrix("לפני ההגנות", "Inherent risk", function(t){ return {l:t.l, i:t.i}; }), matrix("אחרי ההגנות", "Residual risk", function(t){ return t.res; }));
    w.append(twin);
    function counts(fn){ var c = {h:0,m:0,l:0}; item.threats.forEach(function(t){ var p = fn(t), x = p.l * p.i; if (x >= 10) c.h++; else if (x >= 6) c.m++; else c.l++; }); return c; }
    function stack(label, c){
      var n = item.threats.length;
      return h("div", null, h("div", {class:"small", style:{fontWeight:"700",marginBottom:"4px"}}, label),
        h("div", {class:"stack", role:"img", "aria-label":label + ": " + c.h + " גבוה וקריטי, " + c.m + " בינוני, " + c.l + " נמוך"},
          c.h ? h("i", {class:"h", style:{flexGrow:c.h}}, c.h) : null, c.m ? h("i", {class:"m", style:{flexGrow:c.m}}, c.m) : null, c.l ? h("i", {class:"l", style:{flexGrow:c.l}}, c.l) : null),
        h("div", {class:"stack-l"}, h("span", null, "גבוה וקריטי"), h("span", null, "בינוני"), h("span", null, "נמוך")));
    }
    w.append(h("div", {class:"rm-sum"}, stack("לפני: " + item.threats.length + " איומים", counts(function(t){ return {l:t.l, i:t.i}; })), stack("אחרי ההגנות", counts(function(t){ return t.res; }))));
    w.append(h("p", {class:"small muted", style:{marginTop:"10px"}}, rich(r.note), " לחיצה על איום פותחת את הפרטים, ומעבר עכבר מסמן אותו בשתי המטריצות."));
    return sec;
  }

  /* ---------- 06 mitigations: coverage + compact tiles + terminal ---------- */
  function mitSection(){
    var m = item.mitigations;
    var sec = section("mitigations", "06", m.title, m.intro, "wrap-dfd");
    var w = sec._w;
    var tbl = h("table", {class:"cov", "aria-label":"איזו הגנה מכסה איזה איום"});
    tbl.append(h("thead", null, h("tr", null, h("th", null, ""), item.threats.map(function(t){
      return h("th", {scope:"col"}, h("a", {href:"#th-" + t.id, class:"sb " + t.cat, title:t.title, onclick:function(e){ e.preventDefault(); goTo("th-" + t.id); }}, t.id)); }))));
    var tb = h("tbody");
    m.items.forEach(function(x){
      tb.append(h("tr", null, h("th", {scope:"row", class:"mh"}, h("a", {href:"#m-" + x.id, onclick:function(e){ e.preventDefault(); goTo("m-" + x.id); }}, h("span", {class:"mid"}, x.id), h("span", {class:"nm"}, x.short || plain(x.name)))),
        item.threats.map(function(t){ var on = t.mits.indexOf(x.id) >= 0; return h("td", {class:on ? "on c-" + t.cat : "", title:on ? x.id + " ← " + t.id : ""}); })));
    });
    tbl.append(tb);
    w.append(h("div", {class:"cov-wrap hud"}, h("p", {class:"small muted", style:{margin:"0 0 8px"}}, "מפת כיסוי: כל שורה היא הגנה, כל עמודה היא איום. משבצת דולקת = ההגנה מורידה את האיום."), tbl));
    var g = h("div", {class:"ctrls"});
    m.items.forEach(function(x){
      var covered = item.threats.filter(function(t){ return t.mits.indexOf(x.id) >= 0; });
      var el = h("article", {class:"ctl card rv " + x.type, id:"m-" + x.id},
        h("div", {class:"top"}, icon(ICON[x.type]), h("span", {class:"mid"}, x.id), h("span", {class:"tag"}, TYPE_HE[x.type]),
          h("span", {class:"src" + (x.source === "ours" ? " ours" : "")}, x.source === "ours" ? "הצעה שלנו" : "מהמאמר / הדיווח")),
        h("h3", null, rich(x.name)),
        h("div", {class:"covers"}, covered.map(function(t){ return h("a", {href:"#th-" + t.id, class:"sb " + t.cat, title:t.title, onclick:function(e){ e.preventDefault(); goTo("th-" + t.id); }}, t.id); })),
        h("details", null, h("summary", null, "איך זה עובד, ומה המגבלה"),
          Desk.p(x.desc), x.limit ? h("p", {class:"limit"}, h("b", null, "המגבלה: "), rich(x.limit)) : null,
          h("p", {class:"small muted"}, "באחריות: ", rich(x.owner))));
      observe(el);
      g.append(el);
    });
    w.append(g);
    if (m.rule) w.append(terminal(m.rule));
    w.append(h("div", {class:"residual card"}, h("span", {class:"stamp"}, "Still open"), h("div", null, h("h3", {style:{margin:"0 0 6px"}}, termBtn("residual-risk", "סיכון שיורי")), Desk.p(m.residual))));
    return sec;
  }
  function terminal(rule){
    var lines = String(rule.code).split("\n");
    var notes = rule.notes || [], byLine = {};
    notes.forEach(function(n, i){ byLine[n.line] = i + 1; });
    var pre = h("pre", {class:"code-lines", tabindex:"0", "aria-label":"קוד הכלל"});
    lines.forEach(function(l, i){
      var no = i + 1, mk = byLine[no];
      var ln = h("span", {class:"ln" + (/^\s*--/.test(l) ? " cm" : ""), "data-l":no, style:{transitionDelay:(reduce ? 0 : i * 45) + "ms"}},
        h("span", {class:"no"}, no), l || " ", mk ? h("span", {class:"mk"}, mk) : null);
      pre.append(ln);
    });
    pre.append(h("span", {class:"ln", style:{transitionDelay:(reduce ? 0 : lines.length * 45) + "ms"}}, h("span", {class:"no"}, ""), h("span", {class:"cursor"})));
    var copy = h("button", {type:"button"}, "copy");
    Desk.copy(copy, function(){ return rule.code; });
    var body = h("div", {class:"term-body"}, pre);
    if (notes.length){
      body.classList.add("has-notes");
      var an = h("ol", {class:"anno", "aria-label":"הסבר לשורות"});
      notes.forEach(function(n, i){
        var li = h("li", {"data-l":n.line}, h("span", {class:"mk"}, i + 1), h("span", null, rich(n.text)));
        li.addEventListener("mouseenter", function(){ var el = pre.querySelector('.ln[data-l="' + n.line + '"]'); if (el) el.classList.add("hot"); });
        li.addEventListener("mouseleave", function(){ pre.querySelectorAll(".hot").forEach(function(x){ x.classList.remove("hot"); }); });
        an.append(li);
      });
      body.append(an);
    }
    var win = h("div", {class:"term-win"}, h("div", {class:"term-bar"}, h("i"), h("i"), h("i"), h("span", null, "detect_rule.sql"), copy), body);
    var wrap = h("div", null, h("h3", {style:{marginTop:"1.6em"}}, rich(rule.title)), Desk.p(rule.intro), win, rule.note ? Desk.p(rule.note, "term-note") : null);
    observe(win);
    return wrap;
  }

  /* ---------- 07 ATT&CK ---------- */
  function attackSection(){
    var a = item.attack;
    var sec = section("attack", "07", a.title, a.intro);
    var g = h("div", {class:"atk"});
    var mapped = {};
    a.items.forEach(function(x){
      x.threats.forEach(function(id){ mapped[id] = true; });
      var el = h("article", {class:"atile card rv"}, h("div", {class:"tid2"}, x.id), h("div", {class:"tn2"}, x.name), Desk.p(x.where),
        h("div", {class:"tlinks"}, x.threats.map(function(id){ var t = threatsById[id]; return h("a", {href:"#th-" + id, class:"sb " + t.cat, title:t.title, onclick:function(e){ e.preventDefault(); goTo("th-" + id); }}, id); })));
      observe(el); g.append(el);
    });
    var gaps = item.threats.filter(function(t){ return !mapped[t.id]; });
    if (gaps.length || a.caveat){
      var el2 = h("article", {class:"atile card gap rv"}, h("div", {class:"tid2"}, "— —"), h("div", {class:"tn2"}, "Not in ATT&CK"),
        a.caveat ? Desk.p(a.caveat) : null,
        h("div", {class:"tlinks"}, gaps.map(function(t){ return h("a", {href:"#th-" + t.id, class:"sb " + t.cat, title:t.title, onclick:function(e){ e.preventDefault(); goTo("th-" + t.id); }}, t.id); })));
      observe(el2); g.append(el2);
    }
    sec._w.append(g);
    return sec;
  }

  /* ---------- closing ---------- */
  function recapSection(){
    var sec = section("recap", null, "לבנות את זה בעצמכם");
    var w = sec._w;
    w.append(h("p", {class:"sec-intro"}, "שבעת הצעדים שעשינו, ומה כל אחד מהם הוציא בתיק הזה. אפשר לקחת את הטבלה הזאת כתבנית למערכת אחרת."));
    var d = item.dfd, T = item.threats, M = item.mitigations.items;
    var cats = CATS.map(function(c){ var n = T.filter(function(t){ return t.cat === c; }).length; return n ? n + " " + CAT_HE[c] : ""; }).filter(Boolean).join(" · ");
    var hiB = T.filter(function(t){ return t.l * t.i >= 10; }).length, hiA = T.filter(function(t){ return t.res.l * t.res.i >= 10; }).length;
    var cut = minimalCut(item.tree.root, treeMits(item.tree.root));
    var top = item.assets.items.filter(function(a){ return a.value === 3; }).map(function(a){ return a.name; });
    var mapped = {}; item.attack.items.forEach(function(x){ x.threats.forEach(function(id){ mapped[id] = 1; }); });
    var rows = [
      ["01", "dfd", "לשרטט את המערכת", d.nodes.length + " רכיבים, " + d.flows.length + " זרימות, " + d.boundaries.length + " גבולות אמון"],
      ["02", "assets", "לשאול מה שווה הגנה", item.assets.items.length + " נכסים. החשובים ביותר: " + top.join(", ")],
      ["03", "stride", "לשאול שש שאלות על כל רכיב", T.length + " איומים: " + cats],
      ["04", "tree", "לבנות עץ סביב המטרה", "חסימה מינימלית: " + cut.map(function(m){ return m + " " + (mitsById[m].short || ""); }).join(" + ")],
      ["05", "risk", "לדרג לפני ואחרי", "גבוה וקריטי: " + hiB + " לפני, " + hiA + " אחרי"],
      ["06", "mitigations", "להתאים הגנות ולבדוק כיסוי", M.length + " הגנות, " + M.filter(function(m){ return m.source === "ours"; }).length + " מהן תוספת שלנו"],
      ["07", "attack", "למפות לשפה משותפת", item.attack.items.length + " טכניקות. " + T.filter(function(t){ return !mapped[t.id]; }).length + " איומים בלי מיפוי"]
    ];
    var ol = h("ol", {class:"recap"});
    rows.forEach(function(r){
      var li = h("li", {class:"rv"}, h("span", {class:"rn", dir:"ltr"}, r[0]),
        h("div", null, h("b", null, h("a", {href:"#" + r[1], onclick:function(e){ e.preventDefault(); goTo(r[1]); }}, r[2])), h("span", {class:"out"}, r[3])));
      observe(li); ol.append(li);
    });
    w.append(ol);
    return sec;
  }
  function takeawaysSection(){
    var sec = section("takeaways", null, "מה לקחתי מזה");
    var g = h("div", {class:"takes"});
    item.takeaways.forEach(function(t, i){
      var el = h("div", {class:"take hud rv"}, h("span", {class:"ix", dir:"ltr"}, ("0" + (i + 1)).slice(-2)), h("div", null, h("span", {class:"kd"}, (ICON.tk[t.kind] || "•") + " " + t.kind), Desk.p(t.text)));
      observe(el); g.append(el);
    });
    sec._w.append(g);
    return sec;
  }
  function docsSection(){
    var sec = section("docs", null, "המסמך המקצועי");
    sec._w.append(Desk.p(item.docsIntro || "אותו מודל איומים, כמסמך עבודה להורדה."));
    var g = h("div", {class:"docs"});
    (item.docs || []).forEach(function(d){
      var pv = d.preview ? h("div", {class:"pv"}, h("img", {src:d.preview, alt:"", loading:"lazy", onerror:function(){ this.parentNode.remove(); }})) : null;
      g.append(h("a", {class:"doc", href:d.href, download:""}, pv, h("span", {class:"t"}, h("span", {class:"ext"}, d.ext), h("span", null, d.label, h("small", null, d.lang)))));
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
    (item.characters || []).forEach(function(c){ charsById[c.id] = c; });
    Desk.terms.init(Object.assign({}, BASE_GLOSSARY, item.glossary));
    document.title = item.title + " · Attack Surface";
    if (reduce) document.documentElement.classList.add("reduce");
    var app = document.getElementById("app");
    app.innerHTML = "";
    var parts = [h("div", {class:"classif", dir:"ltr"}, "TLP:CLEAR · ", h("b", null, "Defensive analysis only"), " · Case TM-" + item.id),
      banner(), trailer(), minute(), bridge("dfd"), dfdSection(), bridge("assets"), assetsSection(), bridge("stride"), strideSection(),
      bridge("tree"), treeSection(), bridge("risk"), riskSection(), bridge("mitigations"), mitSection(), bridge("attack"), attackSection(),
      recapSection(), bridge("takeaways"), takeawaysSection(), docsSection()];
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
