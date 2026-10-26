"""Capture the README screenshots from a seeded demo instance.

Requires a running API that serves the built dashboard and a demo account:

    TP_DATA_DIR=/tmp/tp-shots python -m app.cli seed-demo
    TP_DATA_DIR=/tmp/tp-shots python -m uvicorn app.main:app --port 8099
    python scripts/capture_screenshots.py --base http://127.0.0.1:8099 \
        --email demo@threatpolish.local --password ...
"""

from __future__ import annotations

import argparse
from pathlib import Path

from playwright.sync_api import sync_playwright

VIEWPORT = {"width": 1560, "height": 1000}


def _launch(browser_type):
    """Prefer a system browser; CI images often skip `playwright install`."""
    for options in ({"channel": "chrome"}, {"executable_path": "/usr/bin/chromium"}, {}):
        try:
            return browser_type.launch(headless=True, **options)
        except Exception:  # noqa: BLE001 - try the next known browser location
            continue
    raise SystemExit("no Chromium build available for Playwright")


def capture(base: str, email: str, password: str, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as play:
        browser = _launch(play.chromium)
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=2)
        page.goto(base, wait_until="networkidle")
        page.screenshot(path=str(out / "login.png"))

        page.fill("input[type=email]", email)
        page.fill("input[type=password]", password)
        page.screenshot(path=str(out / "login-filled.png"))
        page.click("button[type=submit]")
        page.wait_for_selector(".app-shell, main.app, nav", timeout=15000)
        page.wait_for_timeout(1200)
        page.screenshot(path=str(out / "dashboard-overview.png"))

        page.goto(f"{base}/?view=campaigns", wait_until="networkidle")
        page.wait_for_timeout(1200)
        page.screenshot(path=str(out / "campaigns-list.png"))

        candidates = page.locator(".list .list-item")
        if candidates.count():
            candidates.first.click()
            page.wait_for_timeout(1500)
            page.screenshot(path=str(out / "campaigns.png"), full_page=True)
            matrix = page.locator("text=Evidence matrix").first
            if matrix.count():
                matrix.scroll_into_view_if_needed()
                page.wait_for_timeout(600)
                page.screenshot(path=str(out / "evidence-matrix.png"))
            killchain = page.locator("text=Kill-chain coverage").first
            if killchain.count():
                killchain.scroll_into_view_if_needed()
                page.wait_for_timeout(500)
                page.screenshot(path=str(out / "kill-chain.png"))
            plan = page.locator("text=Evidence acquisition plan").first
            if plan.count():
                plan.scroll_into_view_if_needed()
                page.wait_for_timeout(400)
                page.screenshot(path=str(out / "evidence-plan.png"))

        page.goto(f"{base}/?view=deception", wait_until="networkidle")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(out / "deception.png"))

        page.goto(f"{base}/?view=events", wait_until="networkidle")
        page.wait_for_timeout(1000)
        page.screenshot(path=str(out / "events.png"))
        browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8099")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--out", type=Path, default=Path("../docs/assets"))
    args = parser.parse_args()
    capture(args.base, args.email, args.password, args.out)
    for path in sorted(args.out.glob("*.png")):
        print(f"{path} {path.stat().st_size // 1024} KiB")


if __name__ == "__main__":
    main()
