# sign.rahuldk.in

The TrackMy Sign website: plain HTML, CSS and a little JavaScript, no build
step. `.github/workflows/pages.yml` publishes this folder to GitHub Pages on
every push to `main` that touches it; `CNAME` holds the custom domain.

| Path | What it is |
|---|---|
| `index.html` | Home page: hero, how it works, features, specification, download, FAQ |
| `features/` | All features in detail, one section per group |
| `changelog/` | Release notes, loaded from the GitHub releases API by `releases.js` |
| `code-signing/` | Code signing policy |
| `404.html` | Served by GitHub Pages for any missing path; links are root-relative |
| `style.css`, `main.js` | Shared by every page (theme, download tabs, live version and stars) |
| `robots.txt`, `sitemap.xml` | For search engines |
| `site.webmanifest`, `favicon.ico`, `assets/*.png` | Icons |
| `assets/og.png` | 1200×630 image shown when a page is shared |
| `tools/` | Sources for the generated images (not linked from the site) |

## On each release

Nothing in CI changes the website, so after tagging a release:

1. `index.html`: set `"softwareVersion"` in the `application/ld+json` block in
   `<head>` to the new version (e.g. `0.7.0`). Search engines read this; it is
   not updated by JavaScript.
2. `index.html`: change the two `data-version` spans (`v0.6.0`). `main.js`
   replaces them with the latest release tag in the browser, but the HTML is
   what search engines and visitors without JavaScript see.
3. If the release adds features: add a card to the matching group on the home
   page (`#features`) and an `<article>` with the same drawing to
   `features/index.html`, and update the "All N features" count and the
   `Features · v0.x` labels on both pages.
4. Download sizes in the Specification and Download sections, if they changed.
5. `sitemap.xml`: set `<lastmod>` of every page you changed to the release date.

## Icons and the social image

```sh
python3 website/tools/build_assets.py          # both
python3 website/tools/build_assets.py icons    # favicon.ico, favicon-32, apple-touch-icon, icon-192/512
python3 website/tools/build_assets.py og       # assets/og.png from tools/og.html
```

Icons are resized from the app icon (`apps/desktop/src-tauri/icons/icon.png`)
and need Pillow. The social image is a screenshot of `tools/og.html` taken with
headless Chrome or Chromium; set `CHROME` to its path if it is not found. Edit
`tools/og.html` to change the image, then run the script and commit
`assets/og.png`.

## Google Search Console

Either way works; DNS needs no change to the site.

- **Domain property (recommended)**: in Search Console add the property
  `sign.rahuldk.in` (or `rahuldk.in` for every subdomain) and add the TXT record
  it shows at your DNS provider.
- **URL-prefix property** `https://sign.rahuldk.in/` with the *HTML tag*
  method: paste the `<meta name="google-site-verification" …>` tag where the
  comment says so in the `<head>` of `index.html`, push, then press *Verify*.
  Keep the tag in place afterwards.

Then submit `https://sign.rahuldk.in/sitemap.xml` under *Sitemaps*, and use
*URL inspection → Request indexing* for the home and features pages. Bing
Webmaster Tools can import the verified site from Search Console.

The Rich Results Test (search.google.com/test/rich-results) checks the
structured data: `SoftwareApplication`, `Organization`, `WebSite` and
`FAQPage` on the home page and `BreadcrumbList` on the other pages. The FAQ
answers in the JSON-LD must stay word for word the same as the visible FAQ:
change both together.

## Microsoft Store

The Store listing (ID `9NV4G85VML2K`) is not live yet. When it is, add
Microsoft's official badge where the comment in the Download section of
`index.html` says, linking to `https://apps.microsoft.com/detail/9NV4G85VML2K`.
