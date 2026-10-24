// sign.rahuldk.in/changelog — release notes from the GitHub API.
// Release bodies are Markdown written on GitHub. Everything is escaped first;
// only headings, lists, links, bold and code become markup.

(function () {
  "use strict";
  var REPO = "rahuldk1105/trackmysign";
  var list = document.querySelector("[data-releases]");
  var status = document.querySelector("[data-releases-status]");
  if (!list || !status) return;

  function esc(s) {
    return s.replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function link(href, text) {
    return '<a href="' + esc(href) + '" target="_blank" rel="noopener">' + text + "</a>";
  }

  // [text](https://…), bare https://… addresses and **bold**, outside code spans.
  var LINK = /\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)|(https?:\/\/[^\s<>]*[^\s<>.,;:!?)\]'"])/g;
  function plain(s) {
    var out = "", last = 0, m;
    LINK.lastIndex = 0;
    while ((m = LINK.exec(s))) {
      out += bold(esc(s.slice(last, m.index)));
      out += m[2] ? link(m[2], bold(esc(m[1]))) : link(m[3], esc(m[3]));
      last = LINK.lastIndex;
    }
    return out + bold(esc(s.slice(last)));
  }
  function bold(html) {
    return html.replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
  }
  function inline(s) {
    return s
      .split(/(`[^`\n]+`)/)
      .map(function (part, i) {
        return i % 2 ? "<code>" + esc(part.slice(1, -1)) + "</code>" : plain(part);
      })
      .join("");
  }

  function render(md) {
    var html = [], para = [], listTag = null, code = null;
    function flush() {
      if (para.length) html.push("<p>" + para.map(inline).join(" ") + "</p>");
      para = [];
      if (listTag) html.push("</" + listTag + ">");
      listTag = null;
    }
    md.replace(/\r\n?/g, "\n").split("\n").forEach(function (line) {
      if (code) {
        if (/^\s*```/.test(line)) {
          html.push("<pre><code>" + esc(code.join("\n")) + "</code></pre>");
          code = null;
        } else code.push(line);
        return;
      }
      var m;
      if (/^\s*```/.test(line)) {
        flush();
        code = [];
      } else if ((m = /^(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line))) {
        flush();
        var tag = m[1].length <= 2 ? "h3" : "h4";
        html.push("<" + tag + ">" + inline(m[2]) + "</" + tag + ">");
      } else if ((m = /^\s*(?:([-*+])|\d+[.)])\s+(.*)$/.exec(line))) {
        var want = m[1] ? "ul" : "ol";
        if (para.length || listTag !== want) {
          flush();
          html.push("<" + want + ">");
          listTag = want;
        }
        html.push("<li>" + inline(m[2]) + "</li>");
      } else if (!line.trim()) {
        flush();
      } else {
        if (listTag) flush();
        para.push(line.trim());
      }
    });
    if (code) html.push("<pre><code>" + esc(code.join("\n")) + "</code></pre>");
    flush();
    return html.join("");
  }

  function date(iso) {
    var d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
  }

  function fail() {
    status.innerHTML =
      "Couldn't load the release notes. Read them on " +
      link("https://github.com/" + REPO + "/releases", "github.com/" + REPO + "/releases") + ".";
  }

  fetch("https://api.github.com/repos/" + REPO + "/releases?per_page=50")
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (rels) {
      if (!Array.isArray(rels)) return fail();
      // The rolling "test-build" pre-release is not a version.
      rels = rels.filter(function (r) { return !r.draft && !r.prerelease; });
      if (!rels.length) return fail();
      list.innerHTML = rels
        .map(function (r) {
          var tag = r.tag_name || "";
          var url = /^https:\/\/github\.com\//.test(r.html_url || "") ? r.html_url : "https://github.com/" + REPO + "/releases";
          return (
            '<article class="release" id="' + esc(tag) + '">' +
            '<div class="release-meta mono">' +
            '<a class="release-tag" href="#' + esc(tag) + '">' + esc(tag) + "</a>" +
            '<time datetime="' + esc(r.published_at || "") + '">' + esc(date(r.published_at)) + "</time>" +
            "</div>" +
            '<div class="release-body">' +
            "<h2>" + esc(r.name || tag) + "</h2>" +
            '<div class="notes">' + (r.body ? render(r.body) : '<p class="muted">No notes for this release.</p>') + "</div>" +
            '<p class="release-link">' + link(url, "Downloads and details on GitHub") + "</p>" +
            "</div>" +
            "</article>"
          );
        })
        .join("");
      if (location.hash) {
        var el = document.getElementById(decodeURIComponent(location.hash.slice(1)));
        if (el) el.scrollIntoView();
      }
    })
    .catch(fail);
})();
