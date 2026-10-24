#!/usr/bin/env python3
"""Builds the website's icons and social image.

    python3 website/tools/build_assets.py

icons: favicon.ico, assets/favicon-32.png, assets/apple-touch-icon.png and
       assets/icon-192.png / icon-512.png, resized from the app icon
       (apps/desktop/src-tauri/icons/icon.png). Needs Pillow.
og:    assets/og.png (1200x630) is a screenshot of tools/og.html taken with
       headless Chrome or Chromium; set CHROME to its path if it is not found.
       Extra Chrome flags (e.g. --proxy-server=...) go in CHROME_ARGS.

Run with "icons" or "og" to build only one of them.
"""

import os
import shlex
import shutil
import subprocess
import sys

from PIL import Image

SITE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(SITE)
APP_ICON = os.path.join(ROOT, "apps", "desktop", "src-tauri", "icons", "icon.png")
ACCENT = (0x1B, 0x3A, 0x8C, 255)


def icons():
    src = Image.open(APP_ICON).convert("RGBA")
    out = lambda *p: os.path.join(SITE, *p)
    src.save(out("favicon.ico"), sizes=[(16, 16), (32, 32), (48, 48)])
    src.resize((32, 32), Image.LANCZOS).save(out("assets", "favicon-32.png"))
    src.resize((192, 192), Image.LANCZOS).save(out("assets", "icon-192.png"))
    src.resize((512, 512), Image.LANCZOS).save(out("assets", "icon-512.png"))
    # iOS fills transparent corners with black: put the icon on its own colour.
    touch = Image.new("RGBA", src.size, ACCENT)
    touch.alpha_composite(src)
    touch.convert("RGB").resize((180, 180), Image.LANCZOS).save(out("assets", "apple-touch-icon.png"))
    print("icons written")


def find_chrome():
    if os.environ.get("CHROME"):
        return os.environ["CHROME"]
    for name in ("google-chrome", "chromium", "chromium-browser", "chrome"):
        if shutil.which(name):
            return shutil.which(name)
    mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if os.path.exists(mac):
        return mac
    sys.exit("Chrome not found; set CHROME to its path")


def og():
    target = os.path.join(SITE, "assets", "og.png")
    cmd = [
        find_chrome(),
        "--headless=new",
        "--hide-scrollbars",
        "--force-device-scale-factor=1",
        # New headless mode keeps room for window chrome, so the viewport is
        # shorter than the window: render taller and crop.
        "--window-size=1200,800",
        "--virtual-time-budget=8000",
        "--screenshot=" + target,
        *shlex.split(os.environ.get("CHROME_ARGS", "")),
        "file://" + os.path.join(SITE, "tools", "og.html"),
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with Image.open(target) as im:
        im = im.convert("RGB").crop((0, 0, 1200, 630))
    im.save(target, optimize=True)
    print("og.png written")


if __name__ == "__main__":
    what = sys.argv[1:] or ["icons", "og"]
    if "icons" in what:
        icons()
    if "og" in what:
        og()
