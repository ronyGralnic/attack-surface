/* Attack Surface · home v2: animated four-question hero, STRIDE cards, seven-step path, case-file gallery.
   Reads window.DESK_INDEX (items/data.js), falls back to fetch over http. */
(function(){
  "use strict";
  var h = Desk.h, NS = "http://www.w3.org/2000/svg";
  var reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  var STRIDE = [
    {c:"S", en:"Spoofing", he:"התחזות", q:"מישהו יכול להעמיד פנים שהוא מישהו אחר?", ex:"מייל בשם המנכ\"ל שמבקש להעביר כסף דחוף.", fix:"אימות זהות חזק",
     ico:'<svg viewBox="0 0 58 58" fill="none" stroke="currentColor" stroke-width="2"><circle cx="22" cy="22" r="9"/><path d="M6 50c2-10 9-15 16-15s14 5 16 15"/><rect class="mask" x="12" y="17" width="20" height="9" rx="4" fill="currentColor" opacity=".35"/></svg>'},
    {c:"T", en:"Tampering", he:"שיבוש", q:"מישהו יכול לשנות נתונים או תהליך בלי שנדע?", ex:"המחיר בעגלת הקניות משתנה בדרך לשרת.", fix:"שלמות: חתימות, בדיקות, הפרדת תפקידים",
     ico:'<svg viewBox="0 0 58 58" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="10" width="30" height="38" rx="2"/><path d="M12 20h18M12 28h18M12 36h10"/><path class="pen" d="M40 44l12-24 4 2-12 24-5 3z"/></svg>'},
    {c:"R", en:"Repudiation", he:"הכחשה", q:"מישהו יכול להכחיש שעשה משהו, ואין איך להוכיח?", ex:"פעולה נמחקה, ואין יומן שמראה מי עשה אותה.", fix:"תיעוד שאי אפשר לזייף",
     ico:'<svg viewBox="0 0 58 58" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 8h28l10 10v32H10z"/><path d="M16 24h24M16 32h24"/><path class="gone" d="M16 40h18" stroke-dasharray="3 3"/></svg>'},
    {c:"I", en:"Information disclosure", he:"חשיפת מידע", q:"מידע יכול להגיע למי שאסור לו?", ex:"קובץ גיבוי עם פרטי לקוחות נשאר פתוח ברשת.", fix:"סודיות: הצפנה, מידור, צמצום גישה",
     ico:'<svg viewBox="0 0 58 58" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 29s9-15 25-15 25 15 25 15-9 15-25 15S4 29 4 29z"/><circle class="pupil" cx="29" cy="29" r="7"/></svg>'},
    {c:"D", en:"Denial of service", he:"מניעת שירות", q:"אפשר להשבית את זה או להציף אותו?", ex:"הצפה של בקשות משביתה את האתר ביום מבצע.", fix:"זמינות: קיבולת, תעדוף, הגבלת קצב",
     ico:'<svg viewBox="0 0 58 58" fill="none" stroke="currentColor" stroke-width="2"><path d="M29 6v20"/><path d="M17 14a18 18 0 1 0 24 0"/><path class="bolt" d="M44 40l-6 8h6l-4 8" stroke-width="2.4"/></svg>'},
    {c:"E", en:"Elevation of privilege", he:"הסלמת הרשאות", q:"מישהו יכול לקבל יותר כוח ממה שמגיע לו?", ex:"משתמש רגיל משנה כתובת וקורא נתונים של מנהל.", fix:"הרשאה מינימלית ובדיקה בכל גבול",
     ico:'<svg viewBox="0 0 58 58" fill="none" stroke="currentColor" stroke-width="2"><path d="M8 48h12V36h12V24h12V12"/><path class="up" d="M44 30V8M37 15l7-7 7 7"/></svg>'}
  ];
  var STEPS = [
    {t:"מודל המערכת", s:"מי מדבר עם מי, ואיפה עוברים הגבולות.", svg:'<rect class="an" x="6" y="22" width="30" height="20" rx="3"/><rect class="an" x="84" y="22" width="30" height="20" rx="10"/><path class="dr" d="M36 32h46"/><path class="dr" d="M58 6v52" stroke="var(--boundary)" stroke-dasharray="4 3"/>'},
    {t:"נכסים", s:"מה שווה הגנה, ולמי.", svg:'<path class="dr" d="M60 6l22 14v24L60 58 38 44V20z"/><circle class="an" cx="60" cy="32" r="7" fill="currentColor"/>'},
    {t:"STRIDE", s:"שש שאלות על כל רכיב.", svg:'<g class="an"><rect x="20" y="8" width="24" height="20" rx="2"/><rect x="48" y="8" width="24" height="20" rx="2"/><rect x="76" y="8" width="24" height="20" rx="2"/><rect x="20" y="34" width="24" height="20" rx="2"/><rect x="48" y="34" width="24" height="20" rx="2" fill="var(--boundary)" opacity=".5"/><rect x="76" y="34" width="24" height="20" rx="2"/></g>'},
    {t:"עץ תקיפה", s:"כל הדרכים למטרה של התוקף.", svg:'<rect class="an" x="46" y="4" width="28" height="14" rx="2" stroke="var(--boundary)"/><path class="dr" d="M60 18v8M30 26h60M30 26v8M90 26v8M60 26v8"/><rect class="an" x="18" y="34" width="24" height="12" rx="2"/><rect class="an" x="48" y="34" width="24" height="12" rx="2"/><rect class="an" x="78" y="34" width="24" height="12" rx="2"/><path class="dr" d="M14 54l32-6" stroke="var(--accent)"/>'},
    {t:"מטריצת סיכון", s:"מה דחוף, לפני ואחרי ההגנות.", svg:'<path class="dr" d="M24 6v50h76"/><circle class="an" cx="88" cy="16" r="5" fill="var(--boundary)"/><circle class="an" cx="44" cy="40" r="5" fill="var(--accent)"/><path class="dr" d="M83 20L50 37" stroke-dasharray="3 3"/>'},
    {t:"הגנות", s:"מה מכסה מה, ומה נשאר פתוח.", svg:'<path class="dr" d="M60 4l22 8v16c0 14-9 24-22 28-13-4-22-14-22-28V12z"/><path class="dr" d="M50 30l7 7 14-14" stroke="var(--accent)"/>'},
    {t:"המסמך", s:"אותו מודל כמסמך עבודה, בעברית ובאנגלית.", svg:'<path class="dr" d="M38 4h32l12 12v42H38z"/><path class="an" d="M46 24h28M46 32h28M46 40h18"/>'}
  ];
  var data = window.DESK_INDEX || {items:[]};
  var items = data.items || [];

  /* ---------- hero: tiny system, four states ---------- */
  function sv(tag, a){ var e = document.createElementNS(NS, tag); for (var k in a) e.setAttribute(k, a[k]); for (var i = 2; i < arguments.length; i++) e.append(arguments[i]); return e; }
  function hero(){
    var svg = document.getElementById("sys"), list = document.getElementById("qsteps");
    if (!svg || !list) return;
    var N = {u:[70,80,"משתמש"], s:[230,210,"שרת"], db:[380,320,"מאגר"], v:[380,80,"ספק"]};
    svg.append(sv("rect", {class:"zone", x:150, y:150, width:290, height:230, rx:14}), sv("text", {class:"zl", x:430, y:172, "text-anchor":"end", direction:"ltr"}, "TRUST BOUNDARY"));
    var paths = {a:"M108 98 L194 188", b:"M268 232 L344 300", c:"M344 98 L266 188"};
    Object.keys(paths).forEach(function(k){
      var p = sv("path", {class:"fl", d:paths[k], id:"p-" + k}); svg.append(p);
      var c = sv("circle", {class:"pk", r:5});
      if (!reduce){ var m = sv("animateMotion", {dur:(2.2 + Object.keys(paths).indexOf(k) * .5) + "s", repeatCount:"indefinite", path:paths[k]}); c.append(m); }
      else { c.setAttribute("cx", 151); c.setAttribute("cy", 143); }
      svg.append(c);
    });
    Object.keys(N).forEach(function(k){
      var n = N[k], g = sv("g", {class:"nd" + (k === "s" ? " hit" : "")});
      g.append(sv("rect", {x:n[0] - 46, y:n[1] - 22, width:92, height:44, rx:k === "s" ? 22 : 4}), sv("text", {x:n[0], y:n[1] + 5, "text-anchor":"middle"}, n[2]));
      svg.append(g);
    });
    var probe = sv("circle", {class:"probe", cx:150, cy:150, r:14});
    if (!reduce) probe.append(sv("animate", {attributeName:"r", values:"10;22;10", dur:"1.6s", repeatCount:"indefinite"}));
    svg.append(probe, sv("path", {class:"crack", d:"M222 188l8 10-6 6 10 10"}));
    var sh = sv("g", {class:"shield"}); sh.append(sv("path", {d:"M290 160l20 7v14c0 12-8 20-20 24-12-4-20-12-20-24v-14z"}), sv("path", {d:"M281 180l6 6 12-12", fill:"none", stroke:"var(--accent)", "stroke-width":2.5}));
    svg.append(sh);
    var CAP = ["", "הנתונים זורמים בין הרכיבים", "כאן עובר גבול אמון", "בודקים כל רכיב: השרת נפרץ", "ההגנה במקום. השרת מוגן"];
    var cap = sv("text", {class:"cap", x:230, y:392, "text-anchor":"middle"}, "");
    svg.append(cap);
    var cur = 1, timer = null, lis = list.querySelectorAll("li");
    function set(n){
      cur = n; svg.setAttribute("class", "sys s" + n); cap.textContent = CAP[n];
      lis.forEach(function(li){ var on = +li.getAttribute("data-s") === n; li.classList.toggle("on", on); li.querySelector("button").setAttribute("aria-pressed", on ? "true" : "false"); });
    }
    lis.forEach(function(li){ li.querySelector("button").addEventListener("click", function(){ clearInterval(timer); timer = null; set(+li.getAttribute("data-s")); }); });
    set(1);
    if (!reduce) timer = setInterval(function(){ set(cur % 4 + 1); }, 3200);
  }

  /* ---------- STRIDE cards ---------- */
  function stride(){
    var box = document.getElementById("stride6"); if (!box) return;
    STRIDE.forEach(function(x){
      var withIt = items.filter(function(it){ return it.cats && it.cats[x.c]; });
      var n = withIt.reduce(function(a, it){ return a + it.cats[x.c]; }, 0);
      box.append(h("article", {class:"s6 rv c-" + x.c},
        h("span", {class:"ico", "aria-hidden":"true", html:x.ico}),
        h("div", {class:"big", dir:"ltr", "aria-hidden":"true"}, x.c),
        h("h3", null, x.he), h("div", {class:"en", dir:"ltr"}, x.en),
        h("p", {class:"q"}, x.q),
        h("p", {class:"ex"}, h("b", null, "לדוגמה: "), x.ex),
        h("p", {class:"fx"}, h("b", null, "ההגנה הקלאסית: "), x.fix + "."),
        n ? h("p", {class:"small muted", style:{margin:"8px 0 0"}}, "באתר: " + n + " איומים ב-" + withIt.length + " תיקים") : null));
    });
  }

  /* ---------- seven steps ---------- */
  function path(){
    var ol = document.getElementById("path7"); if (!ol) return;
    STEPS.forEach(function(st, i){
      ol.append(h("li", {class:"rv"}, h("span", {class:"pn", dir:"ltr"}, "STEP " + (i + 1)),
        h("span", {"aria-hidden":"true", html:'<svg viewBox="0 0 120 62" fill="none" stroke="currentColor" stroke-width="2">' + st.svg + '</svg>'}),
        h("b", null, st.t), h("span", null, st.s)));
    });
  }

  /* ---------- reveal ---------- */
  function reveal(){
    var els = document.querySelectorAll(".rv");
    if (reduce || !("IntersectionObserver" in window)){ els.forEach(function(e){ e.classList.add("in"); }); return; }
    var io = new IntersectionObserver(function(es){
      es.forEach(function(e){ if (e.isIntersecting){
        var sibs = Array.prototype.indexOf.call(e.target.parentNode.children, e.target);
        setTimeout(function(){ e.target.classList.add("in"); }, sibs * 90);
        io.unobserve(e.target); } });
    }, {rootMargin:"0px 0px -10% 0px"});
    els.forEach(function(e){ io.observe(e); });
  }

  /* ---------- gallery ---------- */
  var sel = {domain:null, region:null, cat:null};
  function uniq(key){ var o = []; items.forEach(function(it){ if (it[key] && o.indexOf(it[key]) < 0) o.push(it[key]); }); return o; }
  function filters(){
    var f = document.getElementById("filters"); if (!f || items.length < 2) return;
    function row(label, key, values, fmt){
      if (values.length < 2) return null;
      var r = h("div", {class:"row", role:"group", "aria-label":label}, h("span", {class:"lbl"}, label));
      [null].concat(values).forEach(function(v){
        var b = h("button", {type:"button", class:"chip", "aria-pressed":String(sel[key] === v), onclick:function(){ sel[key] = v; draw(); }}, v == null ? "הכל" : (fmt ? fmt(v) : v));
        b._v = v; r.append(b);
      });
      r._key = key; return r;
    }
    var cats = []; items.forEach(function(it){ Object.keys(it.cats || {}).forEach(function(c){ if (cats.indexOf(c) < 0) cats.push(c); }); });
    cats.sort(function(a, b){ return "STRIDE".indexOf(a) - "STRIDE".indexOf(b); });
    [row("תחום", "domain", uniq("domain")), row("אזור", "region", uniq("region")),
     row("STRIDE", "cat", cats, function(c){ var s = STRIDE.filter(function(x){ return x.c === c; })[0]; return c + " · " + s.he; })]
      .forEach(function(r){ if (r) f.append(r); });
  }
  function card(it){
    var risk = it.risk || {};
    return h("a", {class:"item-card", href:"items/" + it.id + "/index.html"},
      h("div", {class:"shot"}, h("span", {class:"caseid", dir:"ltr"}, "CASE TM-" + it.id), h("img", {src:it.og, alt:"", loading:"lazy", width:"1200", height:"630"})),
      h("div", {class:"body"},
        h("div", {class:"meta"}, h("span", {class:"risk r" + (risk.n || 3)}, risk.label || ""), h("span", {class:"tag"}, it.domain), h("span", {class:"tag"}, it.country || it.region)),
        h("h3", null, it.title),
        h("p", {class:"muted small", style:{margin:0}}, it.summary),
        h("div", {class:"meta", "aria-label":"קטגוריות STRIDE"}, "STRIDE".split("").filter(function(c){ return it.cats && it.cats[c]; }).map(function(c){ return h("span", {class:"sb " + c, title:it.cats[c] + " איומים"}, c); })),
        it.keyMetric ? h("div", {class:"km"}, h("b", {dir:Desk.autoDir(it.keyMetric.value)}, it.keyMetric.value), h("span", null, it.keyMetric.label)) : null));
  }
  function draw(){
    document.querySelectorAll("#filters .row").forEach(function(r){ r.querySelectorAll(".chip").forEach(function(b){ b.setAttribute("aria-pressed", String(sel[r._key] === b._v)); }); });
    var g = document.getElementById("gallery"); if (!g) return;
    g.innerHTML = "";
    var shown = items.filter(function(it){
      return (!sel.domain || it.domain === sel.domain) && (!sel.region || it.region === sel.region) && (!sel.cat || (it.cats && it.cats[sel.cat]));
    });
    if (!shown.length) g.append(h("div", {class:"empty"}, "אין תיקים שמתאימים לסינון הזה."));
    shown.forEach(function(it){ g.append(card(it)); });
  }
  function boot(){
    if (reduce) document.documentElement.classList.add("reduce");
    hero(); stride(); path(); filters(); draw(); reveal();
    document.documentElement.setAttribute("data-ready", "1");
  }
  document.addEventListener("DOMContentLoaded", function(){
    if (!window.DESK_INDEX && location.protocol !== "file:"){
      fetch("items/index.json").then(function(r){ return r.json(); }).then(function(d){ data = d; items = d.items || []; boot(); }).catch(boot);
      return;
    }
    boot();
  });
})();
