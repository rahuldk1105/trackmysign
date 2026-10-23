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
