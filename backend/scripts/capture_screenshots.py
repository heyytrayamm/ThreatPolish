"""Capture the README screenshots from a seeded demo instance.

Requires a running API that serves the built dashboard and a demo account:

    TP_DATA_DIR=/tmp/tp-shots python -m app.cli seed-demo
    TP_DATA_DIR=/tmp/tp-shots python -m uvicorn app.main:app --port 8099
    python scripts/capture_screenshots.py --base http://127.0.0.1:8099 \
        --email demo@threatpolish.local --password ...

Each view is framed from the top of the card it documents, so a screenshot never
starts mid-sentence.  Captures are taken at twice the display resolution and
downscaled to a fixed width, which keeps the artwork sharp at the size the
README renders it.

The theme is pinned per pass instead of being left to the host: a browser that
reports a light colour scheme would otherwise render the daylight variant, and
the artwork would depend on who ran the script.  The console pass keeps the
plain names the README references; the daylight pass adds a `-daylight` suffix
and captures only the overview the README shows beside the console one.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

VIEWPORT = {"width": 1560, "height": 1000}
# The dashboard reads `prefers-color-scheme` when no choice is stored.  The
# capture pass leaves no choice stored, so each pass gets the theme it pins.
SCHEMES = {"console": "dark", "daylight": "light"}


def _launch(browser_type):
    """Prefer a system browser; CI images often skip `playwright install`."""
    for options in ({"channel": "chrome"}, {"executable_path": "/usr/bin/chromium"}, {}):
        try:
            return browser_type.launch(headless=True, **options)
        except Exception:  # noqa: BLE001 - try the next known browser location
            continue
    raise SystemExit("no Chromium build available for Playwright")


def _card(page, title: str):
    card = page.locator(".card").filter(has=page.get_by_role("heading", name=title, exact=True)).first
    card.wait_for(state="visible")
    return card


def _shrink(path: Path, width: int) -> None:
    """Downscale a capture to the documented width when Pillow is available."""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - Pillow is the docs toolchain
        return
    with Image.open(path) as image:
        if image.width <= width:
            return
        height = round(image.height * width / image.width)
        image.convert("RGB").resize((width, height), Image.LANCZOS).save(path, optimize=True)


def capture(base: str, email: str, password: str, out: Path, width: int = 1400,
            theme: str = "console") -> None:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    suffix = "" if theme == "console" else f"-{theme}"

    def shot(name: str) -> None:
        stem, _, extension = name.partition(".")
        path = out / f"{stem}{suffix}.{extension}"
        page.screenshot(path=str(path))
        written.append(path)

    with sync_playwright() as play:
        browser = _launch(play.chromium)
        page = browser.new_page(
            viewport=VIEWPORT, device_scale_factor=2, color_scheme=SCHEMES[theme]
        )
        page.goto(base, wait_until="networkidle")
        if theme == "console":
            shot("login.png")

        page.fill("input[type=email]", email)
        page.fill("input[type=password]", password)
        page.click("button[type=submit]")
        page.wait_for_selector(".app-shell, main.app, nav", timeout=15000)
        page.wait_for_timeout(1200)
        shot("dashboard-overview.png")

        if theme == "console":
            page.goto(f"{base}/?view=campaigns", wait_until="networkidle")
            page.wait_for_timeout(1200)

            candidates = page.locator(".list .list-item")
            if candidates.count():
                candidates.first.click()
                page.wait_for_timeout(1500)
                shot("campaigns.png")
                # These cards are captured whole: a viewport capture of a short
                # card cannot be framed without repeating the same region twice.
                for title, name in (
                    ("Evidence matrix", "evidence-matrix.png"),
                    ("Kill-chain coverage", "kill-chain.png"),
                    ("Evidence acquisition plan", "evidence-plan.png"),
                ):
                    if page.get_by_role("heading", name=title, exact=True).count():
                        path = out / name
                        _card(page, title).screenshot(path=str(path))
                        written.append(path)

            page.goto(f"{base}/?view=deception", wait_until="networkidle")
            page.wait_for_timeout(1000)
            shot("deception.png")

            page.goto(f"{base}/?view=events", wait_until="networkidle")
            page.wait_for_timeout(1000)
            shot("events.png")
        browser.close()

    for path in written:
        _shrink(path, width)
        print(f"{path} {path.stat().st_size // 1024} KiB")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8099")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--out", type=Path, default=Path("../docs/assets"))
    parser.add_argument("--width", type=int, default=1400)
    parser.add_argument(
        "--themes",
        default="console,daylight",
        help="comma-separated themes to capture (console, daylight)",
    )
    args = parser.parse_args()
    for theme in args.themes.split(","):
        theme = theme.strip()
        if theme not in SCHEMES:
            raise SystemExit(f"unknown theme {theme!r}; expected one of {', '.join(SCHEMES)}")
        capture(args.base, args.email, args.password, args.out, args.width, theme)


if __name__ == "__main__":
    main()
