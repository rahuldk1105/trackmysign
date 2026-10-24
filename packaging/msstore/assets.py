"""Images for the Microsoft Store package and listing.

Usage:
  python3 packaging/msstore/assets.py logos
  python3 packaging/msstore/assets.py screenshots OUT_DIR

logos renders apps/desktop/src-tauri/icons/logo.svg into Assets/, the images
AppxManifest.xml names (the files are committed; run this again after the logo
changes). screenshots converts the website's app screenshots to PNG for the
Store listing (not committed). Needs cairosvg and Pillow.
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
LOGO = os.path.join(ROOT, "apps", "desktop", "src-tauri", "icons", "logo.svg")
ASSETS = os.path.join(HERE, "Assets")

# (file, width, height, share of the height the logo takes). The square icons
# are the logo itself; tiles get it smaller, centred on a transparent tile
# (the Start menu draws the tile background).
LOGOS = [
    ("StoreLogo.png", 50, 50, 1.0),
    ("Square44x44Logo.png", 44, 44, 1.0),
    # Taskbar, Start and title bar sizes, shown without a plate.
    *[(f"Square44x44Logo.targetsize-{n}_altform-unplated.png", n, n, 1.0) for n in (16, 24, 32, 48, 256)],
    ("Square150x150Logo.png", 150, 150, 0.5),
    ("Wide310x150Logo.png", 310, 150, 0.5),
]

SCREENSHOTS = [
    os.path.join(ROOT, "website", "assets", "app-light.webp"),
    os.path.join(ROOT, "website", "assets", "app-dark.webp"),
]


def render(svg, width, height, share):
    import cairosvg
    from PIL import Image

    side = round(height * share)
    png = cairosvg.svg2png(bytestring=svg, output_width=side, output_height=side)
    mark = Image.open(io.BytesIO(png)).convert("RGBA")
    out = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    out.paste(mark, ((width - side) // 2, (height - side) // 2), mark)
    return out


def logos():
    with open(LOGO, "rb") as f:
        svg = f.read()
    os.makedirs(ASSETS, exist_ok=True)
    for name, width, height, share in LOGOS:
        render(svg, width, height, share).save(os.path.join(ASSETS, name), optimize=True)
        print(name)


def screenshots(out):
    from PIL import Image

    os.makedirs(out, exist_ok=True)
    for src in SCREENSHOTS:
        img = Image.open(src).convert("RGB")
        # The Store takes desktop screenshots from 1366x768 up to 3840x2160.
        if img.width < 1366 or img.height < 768:
            raise SystemExit(f"{src} is smaller than 1366x768")
        dest = os.path.join(out, os.path.splitext(os.path.basename(src))[0] + ".png")
        img.save(dest, optimize=True)
        print(dest, f"{img.width}x{img.height}")


def main(argv):
    if argv[:1] == ["logos"]:
        logos()
    elif argv[:1] == ["screenshots"] and len(argv) == 2:
        screenshots(argv[1])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
