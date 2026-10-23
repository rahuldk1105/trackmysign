// sign.rahuldk.in — theme, signing bench demo, downloads.

(function () {
  "use strict";
  var REPO = "rahuldk1105/trackmysign";
  var root = document.documentElement;
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var $ = function (s, el) { return (el || document).querySelector(s); };
  var $$ = function (s, el) { return Array.prototype.slice.call((el || document).querySelectorAll(s)); };

  // ------------------------------------------------------------ theme
  var media = window.matchMedia("(prefers-color-scheme: dark)");
  var themeBtn = $("#theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", function () {
      var cur = root.dataset.theme || (media.matches ? "dark" : "light");
      var next = cur === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try { localStorage.setItem("tms-theme", next); } catch (e) {}
    });
  }

  // ------------------------------------------- hero background engraving
  // Guilloché rosettes and wave bands, as on certificates and stamp paper,
  // plus one large signature stroke. Drawn once per size/theme; no animation.
  var bg = $("[data-hero-bg]");
  function drawHeroBg() {
    if (!bg) return;
    var w = bg.clientWidth, h = bg.clientHeight;
    if (!w || !h) return;
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    bg.width = Math.round(w * dpr);
    bg.height = Math.round(h * dpr);
    var ctx = bg.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    var ink = getComputedStyle(root).getPropertyValue("--hero-line").trim() || "#1b3a8c";
    ctx.strokeStyle = ink;
    ctx.lineJoin = "round";

    // Rosette: a family of rotated hypotrochoids.
    function rosette(cx, cy, R, r, d, copies, width, alpha) {
      ctx.lineWidth = width;
      ctx.globalAlpha = alpha;
      var steps = 1400, k = (R - r) / r;
      for (var c = 0; c < copies; c++) {
        var rot = (c / copies) * (Math.PI * 2) / 9;
        ctx.beginPath();
        for (var i = 0; i <= steps; i++) {
          var t = (i / steps) * Math.PI * 2 * r / gcd(R, r);
          var x = (R - r) * Math.cos(t) + d * Math.cos(k * t);
          var y = (R - r) * Math.sin(t) - d * Math.sin(k * t);
          var xr = x * Math.cos(rot) - y * Math.sin(rot);
          var yr = x * Math.sin(rot) + y * Math.cos(rot);
          if (i === 0) ctx.moveTo(cx + xr, cy + yr);
          else ctx.lineTo(cx + xr, cy + yr);
        }
        ctx.stroke();
      }
    }
    function gcd(a, b) { return b ? gcd(b, a % b) : a; }

    var u = Math.max(w, 900) / 1440;
    rosette(w * 0.06, h * 0.18, 300 * u, 45 * u, 120 * u, 3, 0.7, 0.9);
    rosette(w * 0.06, h * 0.18, 170 * u, 34 * u, 70 * u, 2, 0.6, 0.7);
    rosette(w * 0.98, h * 0.94, 340 * u, 51 * u, 130 * u, 3, 0.7, 0.8);
    rosette(w * 0.5, h * 0.06, 120 * u, 24 * u, 50 * u, 2, 0.6, 0.6);

    // Wave band across the lower part of the hero.
    ctx.globalAlpha = 0.75;
    ctx.lineWidth = 0.7;
    var base = h * 0.78;
    for (var j = 0; j < 22; j++) {
      ctx.beginPath();
      for (var x = -10; x <= w + 10; x += 6) {
        var y = base + j * 4.2 +
          Math.sin(x * 0.006 + j * 0.28) * 26 * u +
          Math.sin(x * 0.017 - j * 0.15) * 9 * u;
        if (x === -10) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();
    }

    // One large signature stroke (the mark's own curve), sweeping behind the headline.
    var sig = new Path2D("M14 40c6-10 10-14 13-14 4 0-2 12 2 12s6-8 9-8 1 6 4 6 5-3 8-5");
    ctx.save();
    var sc = 10 * u;
    ctx.translate(w * 0.01, h * 0.38);
    ctx.scale(sc, sc);
    ctx.globalAlpha = 0.9;
    ctx.lineWidth = 2.2 / sc * 1.6;
    ctx.lineCap = "round";
    ctx.stroke(sig);
    ctx.restore();
    ctx.globalAlpha = 1;
  }
  if (bg) {
    var redraw = function () { window.requestAnimationFrame(drawHeroBg); };
    if (window.ResizeObserver) new ResizeObserver(redraw).observe(bg);
    else window.addEventListener("resize", redraw);
    new MutationObserver(redraw).observe(root, { attributes: true, attributeFilter: ["data-theme"] });
    media.addEventListener ? media.addEventListener("change", redraw) : media.addListener(redraw);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(redraw);
    redraw();
  }

  // ------------------------------------------------------ OS detection
  var ua = navigator.userAgent || "";
  var plat = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
  var mobile = /Android|iPhone|iPad|iPod/i.test(ua);
  var os = /Win/i.test(plat) || /Windows/i.test(ua) ? "win" : /Mac/i.test(plat) || /Mac OS X/i.test(ua) ? "mac" : null;

  // ------------------------------------------------------ download tabs
  function selectTab(name) {
    $$("[data-tab]").forEach(function (t) { t.setAttribute("aria-selected", String(t.dataset.tab === name)); });
    $$("[data-pane]").forEach(function (p) { p.hidden = p.dataset.pane !== name; });
  }
  $$("[data-tab]").forEach(function (t) {
    t.addEventListener("click", function () { selectTab(t.dataset.tab); });
    t.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      var tabs = $$("[data-tab]");
      var i = tabs.indexOf(t) + (e.key === "ArrowRight" ? 1 : -1);
      var next = tabs[(i + tabs.length) % tabs.length];
      next.focus();
      selectTab(next.dataset.tab);
    });
  });
  if (os && !mobile) {
    selectTab(os);
    var pane = $('[data-pane="' + os + '"] a.btn');
    var primary = $("[data-dl-primary]");
    if (pane && primary) {
      primary.href = pane.href;
      $("[data-dl-label]").textContent = os === "win" ? "Download for Windows" : "Download for macOS";
    }
  }

  // ------------------------------------- live data from GitHub (public API)
  fetch("https://api.github.com/repos/" + REPO + "/releases/latest")
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (rel) {
      if (!rel) return;
      if (rel.tag_name) $$("[data-version]").forEach(function (el) { el.textContent = rel.tag_name; });
      (rel.assets || []).forEach(function (a) {
        var el = $('[data-sum="' + a.name + '"]');
        if (!el || !a.digest) return;
        var hex = a.digest.replace(/^sha256:/, "");
        el.textContent = "SHA-256 " + hex.slice(0, 16) + "…" + hex.slice(-8);
        el.title = hex;
        var b = document.createElement("button");
        b.type = "button";
        b.textContent = "Copy";
        b.addEventListener("click", function () {
          var done = function () { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1500); };
          if (navigator.clipboard) navigator.clipboard.writeText(hex).then(done, function () {});
        });
        el.appendChild(b);
      });
    })
    .catch(function () {});
  fetch("https://api.github.com/repos/" + REPO)
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (repo) {
      var el = $("[data-stars]");
      if (!repo || !el || !(repo.stargazers_count > 0)) return;
      el.textContent = "★ " + repo.stargazers_count.toLocaleString("en-IN");
      el.hidden = false;
    })
    .catch(function () {});

  // --------------------------------------------------------- signing bench
  var page = $(".doc-page");
  var box = $("[data-box]");
  var log = $("[data-log]");
  var signBtn = $("[data-sign]");
  var resetBtn = $("[data-reset]");
  var verdict = $("[data-verdict]");
  var hint = $("[data-hint]");
  if (!page || !box) return;

  // Position the box as fractions of the page so it survives resizes.
  var pos = { x: 0.62, y: 0.76 };
  var signed = false;
  var busy = false;

  function apply() {
    box.style.left = pos.x * 100 + "%";
    box.style.top = pos.y * 100 + "%";
    box.style.right = "auto";
    box.style.bottom = "auto";
  }
  function clamp() {
    var bw = box.offsetWidth / page.clientWidth;
    var bh = box.offsetHeight / page.clientHeight;
    pos.x = Math.min(Math.max(pos.x, 0.02), 0.98 - bw);
    pos.y = Math.min(Math.max(pos.y, 0.02), 0.98 - bh);
  }
  apply();

  var drag = null;
  box.addEventListener("pointerdown", function (e) {
    if (signed || busy) return;
    var r = page.getBoundingClientRect();
    drag = { dx: e.clientX - r.left - pos.x * r.width, dy: e.clientY - r.top - pos.y * r.height };
    box.setPointerCapture(e.pointerId);
    box.classList.add("dragging");
  });
  box.addEventListener("pointermove", function (e) {
    if (!drag) return;
    var r = page.getBoundingClientRect();
    pos.x = (e.clientX - r.left - drag.dx) / r.width;
    pos.y = (e.clientY - r.top - drag.dy) / r.height;
    clamp();
    apply();
  });
  function endDrag() {
    if (!drag) return;
    drag = null;
    box.classList.remove("dragging");
  }
  box.addEventListener("pointerup", endDrag);
  box.addEventListener("pointercancel", endDrag);
  box.addEventListener("keydown", function (e) {
    if (signed || busy) return;
    var step = e.shiftKey ? 0.05 : 0.01;
    var moves = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] };
    if (e.key === "Enter") { e.preventDefault(); run(); return; }
    if (!moves[e.key]) return;
    e.preventDefault();
    pos.x += moves[e.key][0];
    pos.y += moves[e.key][1];
    clamp();
    apply();
  });
  // Click on the page places the box there.
  page.addEventListener("pointerdown", function (e) {
    if (e.target.closest("[data-box]") || signed || busy) return;
    var r = page.getBoundingClientRect();
    pos.x = (e.clientX - r.left) / r.width - box.offsetWidth / r.width / 2;
    pos.y = (e.clientY - r.top) / r.height - box.offsetHeight / r.height / 2;
    clamp();
    apply();
  });

  // Sizes from a real signing run: 48,213-byte original, 21,604 bytes appended.
  var ORIG = 48213, HEAD = 707, GAP = 16386, TAIL = 4511, TOTAL = ORIG + HEAD + GAP + TAIL;
  var seg = {};
  $$("[data-seg]").forEach(function (s) { seg[s.dataset.seg] = s; });
  var appendedEl = $("[data-appended]");

  function setBytes(head, gap, tail) {
    var total = ORIG + head + gap + tail;
    seg.orig.style.width = (ORIG / total) * 100 + "%";
    seg.head.style.width = (head / total) * 100 + "%";
    seg.gap.style.width = (gap / total) * 100 + "%";
    seg.tail.style.width = (tail / total) * 100 + "%";
    appendedEl.textContent = "+" + (head + gap + tail).toLocaleString("en-IN") + " B";
  }
  setBytes(0, 0, 0);

  function fmt(n) { return n.toLocaleString("en-IN"); }
  function hexStr(n) {
    var s = "", c = "0123456789abcdef";
    for (var i = 0; i < n; i++) s += c[Math.floor(Math.random() * 16)];
    return s;
  }
  function stamp() {
    var d = new Date();
    var p = function (n) { return String(n).padStart(2, "0"); };
    return d.getFullYear() + "." + p(d.getMonth() + 1) + "." + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes()) + " " + tz(d);
  }
  function tz(d) {
    var o = -d.getTimezoneOffset(), s = o >= 0 ? "+" : "-";
    o = Math.abs(o);
    return s + String(Math.floor(o / 60)).padStart(2, "0") + ":" + String(o % 60).padStart(2, "0");
  }
  var t0 = 0;
  function line(key, text, cls) {
    var li = document.createElement("li");
    var ms = (performance.now() - t0) / 1000;
    li.innerHTML = '<span class="t">' + ms.toFixed(2).padStart(5, " ") + "s</span>  " + '<span class="k">' + key + "</span>" + (cls ? '<span class="' + cls + '">' + text + "</span>" : text);
    log.appendChild(li);
    return li;
  }
  function wait(ms) { return new Promise(function (r) { setTimeout(r, reduced ? 0 : ms); }); }

  function run() {
    if (busy || signed) return;
    busy = true;
    signBtn.disabled = true;
    hint.textContent = "Signing…";
    log.innerHTML = "";
    t0 = performance.now();
    line("token", "HYP2003 · slot 0 · 1 signing certificate");
    wait(450)
      .then(function () {
        line("read", fmt(ORIG) + " B · 2 pages · 1 existing signature");
        return wait(500);
      })
      .then(function () {
        setBytes(HEAD, GAP, TAIL);
        line("append", "sig dict, widget, appearance, xref  +" + fmt(HEAD + GAP + TAIL) + " B");
        return wait(600);
      })
      .then(function () {
        var li = line("hash", "SHA-256 ");
        var a = ORIG + HEAD, b = a + GAP;
        li.title = "ByteRange [0 " + a + " " + b + " " + TAIL + "]";
        var n = 0;
        return new Promise(function (resolve) {
          var tick = function () {
            n += 8;
            li.lastChild.nodeValue = "SHA-256 " + hexStr(Math.min(n, 32)) + (n < 32 ? "" : "…");
            if (n < 32 && !reduced) setTimeout(tick, 60);
            else resolve();
          };
          tick();
        }).then(function () {
          line("range", "[0 " + fmt(a) + " " + fmt(b) + " " + fmt(TAIL) + "]");
        });
      })
      .then(function () { return wait(500); })
      .then(function () {
        line("sign", "RSA-2048 on token · PIN verified, not stored");
        return wait(550);
      })
      .then(function () {
        box.classList.add("signed");
        $("[data-stamp-time]", box).textContent = "Date: " + stamp();
        line("verify", "Signature is valid · earlier signature intact", "ok");
        verdict.hidden = false;
        resetBtn.hidden = false;
        signBtn.hidden = true;
        hint.textContent = "Saved board-resolution_signed.pdf";
        signed = true;
        busy = false;
      });
  }

  signBtn.addEventListener("click", run);
  resetBtn.addEventListener("click", function () {
    signed = false;
    box.classList.remove("signed");
    $("[data-stamp-time]", box).textContent = "Date: — awaiting PIN";
    log.innerHTML = '<li class="log-idle">Ready. Token: HYP2003 · DSC: YOUR NAME (Class 3)</li>';
    setBytes(0, 0, 0);
    verdict.hidden = true;
    resetBtn.hidden = true;
    signBtn.hidden = false;
    signBtn.disabled = false;
    hint.textContent = "Drag the signature, then press Sign";
    signBtn.focus();
  });
})();
