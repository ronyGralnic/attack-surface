/* =========================================================================
   Desk kit · shared JS (no dependencies)
   Desk.h()        tiny DOM builder
   Desk.rich()     inline markup → DOM: **bold**, [[termId]] / [[termId|label]]
   Desk.terms      accessible glossary popovers (bottom sheet on mobile)
   Desk.theme      light/dark toggle, persisted (storage wrapped in try/catch)
   Desk.copy()     copy-to-clipboard buttons
   Desk.goat()     GoatCounter, only on the production host
   ========================================================================= */
(function(){
  "use strict";
  var Desk = window.Desk = window.Desk || {};

  /* ---------- DOM ---------- */
  Desk.h = function(tag, attrs){
    var el = document.createElement(tag), i, k, c;
    if (attrs) for (k in attrs){
      var v = attrs[k];
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else if (k === "html") el.innerHTML = v;
      else if (k.slice(0,2) === "on" && typeof v === "function") el.addEventListener(k.slice(2), v);
      else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (i = 2; i < arguments.length; i++){
      c = arguments[i];
      if (c == null || c === false) continue;
      if (Array.isArray(c)) c.forEach(function(x){ if (x != null && x !== false) el.append(x.nodeType ? x : document.createTextNode(String(x))); });
      else el.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return el;
  };

  /* LTR for values with no Hebrew letters ("~43%", "$850M") so signs don't jump */
  Desk.autoDir = function(s){ return /[\u0590-\u05FF]/.test(String(s)) ? null : "ltr"; };

  Desk.esc = function(s){ return String(s).replace(/[&<>"']/g, function(c){ return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]; }); };

  /* ---------- rich inline text ---------- */
  Desk.glossary = {};
  Desk.rich = function(text){
    var frag = document.createDocumentFragment();
    if (text == null) return frag;
    var re = /\[\[([a-z0-9\-]+)(?:\|([^\]]+))?\]\]|\*\*([^*]+)\*\*/g, last = 0, m;
    text = String(text);
    while ((m = re.exec(text))){
      if (m.index > last) frag.append(document.createTextNode(text.slice(last, m.index)));
      if (m[1]){
        var g = Desk.glossary[m[1]];
        var label = m[2] || (g ? g.term : m[1]);
        if (g) frag.append(Desk.h("span", {class:"term", role:"button", tabindex:"0", "data-term":m[1], "aria-expanded":"false", "aria-haspopup":"dialog"}, label));
        else { frag.append(document.createTextNode(label)); if (window.console) console.warn("Desk: missing glossary term", m[1]); }
      } else frag.append(Desk.h("strong", null, m[3]));
      last = re.lastIndex;
    }
    if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
    return frag;
  };
  Desk.p = function(text, cls){ return Desk.h("p", cls ? {class:cls} : null, Desk.rich(text)); };

  /* ---------- glossary popovers ---------- */
  var pop = null, popFor = null;
  function closePop(focusBack){
    if (!pop) return;
    pop.remove(); pop = null;
    if (popFor){ popFor.setAttribute("aria-expanded","false"); if (focusBack) popFor.focus(); }
    popFor = null;
  }
  function openPop(btn){
    var id = btn.getAttribute("data-term"), g = Desk.glossary[id];
    if (!g) return;
    if (popFor === btn){ closePop(true); return; }
    closePop(false);
    var h = Desk.h;
    pop = h("div", {class:"term-pop", role:"dialog", "aria-modal":"false", "aria-labelledby":"term-pop-h", tabindex:"-1"},
      h("button", {type:"button", class:"close", "aria-label":"סגירה", onclick:function(){ closePop(true); }}, "×"),
      h("h4", {id:"term-pop-h"}, h("span", null, g.term), g.en ? h("span", {class:"en", dir:"ltr"}, g.en) : null),
      h("p", null, Desk.rich(g.def)),
      g.example ? h("p", {class:"ex"}, h("b", null, "לדוגמה: "), Desk.rich(g.example)) : null
    );
    document.body.append(pop);
    popFor = btn; btn.setAttribute("aria-expanded","true");
    if (window.matchMedia("(min-width:601px)").matches){
      var r = btn.getBoundingClientRect(), pw = pop.offsetWidth, ph = pop.offsetHeight;
      var vw = document.documentElement.clientWidth;
      var left = r.left + r.width/2 - pw/2 + window.scrollX;
      left = Math.max(12 + window.scrollX, Math.min(left, window.scrollX + vw - pw - 12));
      var top = r.bottom + 10 + window.scrollY;
      if (r.bottom + ph + 20 > window.innerHeight && r.top - ph - 10 > 0) top = r.top - ph - 10 + window.scrollY;
      pop.style.left = left + "px"; pop.style.top = top + "px";
    }
    pop.focus({preventScroll:true});
  }
  Desk.terms = {
    init: function(glossary){
      Object.assign(Desk.glossary, glossary || {});
      if (Desk.terms._bound) return; Desk.terms._bound = true;
      document.addEventListener("click", function(e){
        var t = e.target.closest && e.target.closest(".term");
        if (t){ e.preventDefault(); openPop(t); return; }
        if (pop && !pop.contains(e.target)) closePop(false);
      });
      document.addEventListener("keydown", function(e){
        if (e.key === "Escape" && pop) { closePop(true); return; }
        var t = e.target.closest && e.target.closest(".term");
        if (t && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); openPop(t); }
      });
      var lastW = window.innerWidth;
      window.addEventListener("resize", function(){ if (window.innerWidth !== lastW){ lastW = window.innerWidth; closePop(false); } });
    }
  };

  /* ---------- theme ---------- */
  var KEY = "desk-theme";
  Desk.theme = {
    get: function(){ return document.documentElement.getAttribute("data-theme") || "light"; },
    set: function(t){
      document.documentElement.setAttribute("data-theme", t);
      try { localStorage.setItem(KEY, t); } catch(e){}
      document.querySelectorAll(".theme-toggle").forEach(function(b){ b.setAttribute("aria-pressed", t === "dark" ? "true" : "false"); });
      document.dispatchEvent(new CustomEvent("desk:theme", {detail:t}));
    },
    toggle: function(){ Desk.theme.set(Desk.theme.get() === "dark" ? "light" : "dark"); },
    init: function(){
      document.querySelectorAll(".theme-toggle").forEach(function(b){
        b.setAttribute("aria-pressed", Desk.theme.get() === "dark" ? "true" : "false");
        b.addEventListener("click", Desk.theme.toggle);
      });
    }
  };
  Desk.themeButton = function(){
    return '<button type="button" class="icon-btn theme-toggle" aria-label="מצב כהה">' +
      '<svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>' +
      '<svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button>';
  };

  /* ---------- copy ---------- */
  Desk.copy = function(btn, getText){
    btn.addEventListener("click", function(){
      var txt = getText();
      var done = function(){ var o = btn.textContent; btn.textContent = "הועתק ✓"; setTimeout(function(){ btn.textContent = o; }, 1400); };
      try {
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(txt).then(done, function(){});
        else { var ta = Desk.h("textarea", {style:{position:"fixed",opacity:"0"}}); ta.value = txt; document.body.append(ta); ta.select(); document.execCommand("copy"); ta.remove(); done(); }
      } catch(e){}
    });
  };

  /* ---------- analytics (GoatCounter) ---------- */
  Desk.goat = function(code, prodHostSuffix){
    var host = location.hostname;
    if (!code || !host || (prodHostSuffix && host.slice(-prodHostSuffix.length) !== prodHostSuffix)) return;
    var s = document.createElement("script");
    s.async = true; s.src = "https://gc.zgo.at/count.js";
    s.setAttribute("data-goatcounter", "https://" + code + ".goatcounter.com/count");
    document.head.append(s);
  };

  /* ---------- formatting ---------- */
  Desk.fmtDate = function(iso, opts){
    try { return new Date(iso + "T12:00:00Z").toLocaleDateString("he-IL", Object.assign({day:"numeric", month:"long", year:"numeric", timeZone:"UTC"}, opts || {})); }
    catch(e){ return iso; }
  };
  Desk.daysBetween = function(a, b){ return Math.round((Date.parse(b + "T00:00:00Z") - Date.parse(a + "T00:00:00Z")) / 864e5); };

  document.addEventListener("DOMContentLoaded", function(){ Desk.theme.init(); Desk.terms.init(); });
})();
