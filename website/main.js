// sign.rahuldk.in — theme toggle, OS-aware download button, latest version.

(function () {
  var REPO = "rahuldk1105/trackmysign";
  var root = document.documentElement;

  // ---- theme: light / dark, defaulting to the OS setting
  var media = window.matchMedia("(prefers-color-scheme: dark)");
  function current() {
    return root.dataset.theme || (media.matches ? "dark" : "light");
  }
  var toggle = document.querySelector(".theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("sd-theme", next);
      } catch (e) {}
    });
  }

  // ---- download button for the visitor's OS
  var ua = navigator.userAgent || "";
  var platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
  var os = /Win/i.test(platform) || /Windows/i.test(ua) ? "windows" : /Mac/i.test(platform) || /Mac OS X/i.test(ua) ? "mac" : null;
  var mobile = /Android|iPhone|iPad|iPod/i.test(ua);

  var primary = document.querySelector('[data-dl="primary"]');
  var label = document.querySelector("[data-dl-label]");
  if (primary && label && os && !mobile) {
    var card = document.querySelector('.dl[data-os="' + os + '"]');
    var link = card && card.querySelector("a.btn");
    if (link) {
      primary.href = link.href;
      label.textContent = os === "windows" ? "Download for Windows" : "Download for macOS";
      card.classList.add("is-current");
    }
  }

  // ---- show the latest release tag (works once the repository is public)
  fetch("https://api.github.com/repos/" + REPO + "/releases/latest", { headers: { Accept: "application/vnd.github+json" } })
    .then(function (r) {
      return r.ok ? r.json() : null;
    })
    .then(function (rel) {
      if (!rel || !rel.tag_name) return;
      document.querySelectorAll("[data-version]").forEach(function (el) {
        el.textContent = rel.tag_name;
      });
    })
    .catch(function () {});
})();
