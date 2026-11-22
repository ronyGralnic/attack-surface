/* Attack Surface · home: STRIDE explainer + filtered gallery. Reads window.DESK_INDEX (items/data.js). */
(function(){
  "use strict";
  var h = Desk.h;
  var STRIDE = [
    {c:"S", en:"Spoofing", he:"התחזות", q:"מישהו יכול להעמיד פנים שהוא מישהו אחר?", fix:"אימות זהות חזק"},
    {c:"T", en:"Tampering", he:"שיבוש", q:"מישהו יכול לשנות נתונים או תהליך בלי שנדע?", fix:"שלמות: חתימות, ביקורת, הפרדת תפקידים"},
    {c:"R", en:"Repudiation", he:"הכחשה", q:"מישהו יכול לטעון שהוא לא עשה את מה שעשה?", fix:"תיעוד שאי אפשר לזייף"},
    {c:"I", en:"Information disclosure", he:"חשיפת מידע", q:"מידע יכול להגיע למי שאסור לו?", fix:"סודיות: הצפנה, מידור, צמצום גישה"},
    {c:"D", en:"Denial of service", he:"מניעת שירות", q:"אפשר להשבית או להציף את המערכת?", fix:"זמינות: קיבולת, תעדוף, הגבלות"},
    {c:"E", en:"Elevation of privilege", he:"הסלמת הרשאות", q:"מישהו יכול לקבל יותר כוח ממה שמגיע לו?", fix:"הרשאה מינימלית ובדיקה בכל גבול"}
  ];
  var data = window.DESK_INDEX || {items:[]};
  var items = data.items || [];

  function tiles(){
    var box = document.getElementById("stride-tiles"), out = document.getElementById("stride-explain");
    if (!box) return;
    STRIDE.forEach(function(x){
      var b = h("button", {type:"button", class:"stride-tile c-" + x.c, "aria-pressed":"false", "data-c":x.c},
        h("b", null, x.c), h("span", {class:"en", dir:"ltr"}, x.en), h("span", {class:"he"}, x.he));
      b.addEventListener("click", function(){
        box.querySelectorAll(".stride-tile").forEach(function(o){ o.setAttribute("aria-pressed", o === b ? "true" : "false"); });
        var withIt = items.filter(function(it){ return it.cats && it.cats[x.c]; });
        out.innerHTML = "";
        out.append(h("p", null, h("b", null, x.he + ": "), x.q),
          h("p", null, h("b", null, "ההגנה הקלאסית: "), x.fix + "."),
          h("p", {class:"small", style:{margin:0}}, withIt.length ?
            withIt.reduce(function(acc, it, i){ if (i) acc.push(" · "); acc.push(h("a", {href:"items/" + it.id + "/index.html#stride"}, it.title + " (" + it.cats[x.c] + ")")); return acc; }, ["מופיע ב-" + withIt.length + " פריטים: "]) :
            "עדיין לא מופיע באף פריט."));
      });
      box.append(b);
    });
  }

  var sel = {domain:null, region:null, cat:null};
  function uniq(key){ var o = []; items.forEach(function(it){ if (it[key] && o.indexOf(it[key]) < 0) o.push(it[key]); }); return o; }
  function filters(){
    var f = document.getElementById("filters"); if (!f) return;
    function row(label, key, values, fmt){
      if (values.length < 1) return null;
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
      h("img", {src:it.og, alt:"", loading:"lazy", width:"1200", height:"630"}),
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
    if (!shown.length) g.append(h("div", {class:"empty"}, "אין פריטים שמתאימים לסינון הזה."));
    shown.forEach(function(it){ g.append(card(it)); });
  }
  document.addEventListener("DOMContentLoaded", function(){
    if (!window.DESK_INDEX && location.protocol !== "file:"){
      fetch("items/index.json").then(function(r){ return r.json(); }).then(function(d){ data = d; items = d.items || []; tiles(); filters(); draw(); });
      return;
    }
    tiles(); filters(); draw();
    document.documentElement.setAttribute("data-ready", "1");
  });
})();
