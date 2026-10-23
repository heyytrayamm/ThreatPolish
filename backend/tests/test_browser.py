"""End-to-end dashboard test in a real browser.

This is the only test that exercises the built React bundle: it starts the API
(which also serves `frontend/dist`), signs in through the form, changes the
password through the Account page and checks that the tab keeps working with
the replacement token while a token issued earlier is refused.

It is skipped when Playwright or a built dashboard is unavailable, so the
default suite stays dependency-free.  `.github/workflows/ci.yml` runs it in the
`Dashboard end-to-end` job after building the bundle.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from .conftest import ADMIN_EMAIL, ADMIN_PASSWORD

playwright_api = pytest.importorskip(
    "playwright.sync_api", reason="playwright is not installed"
)

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "frontend" / "dist"
NEW_PASSWORD = "browser-flow-password-1"

def _dist_is_stale() -> bool:
    """True when the bundle predates its sources, which would test old assets."""
    sources = [path for path in (ROOT / "frontend" / "src").rglob("*") if path.is_file()]
    sources.append(ROOT / "frontend" / "index.html")
    newest_source = max(path.stat().st_mtime for path in sources)
    newest_build = max((path.stat().st_mtime for path in DIST.rglob("*") if path.is_file()), default=0)
    return newest_build < newest_source


pytestmark = pytest.mark.skipif(
    not (DIST / "index.html").is_file() or _dist_is_stale(),
    reason="frontend/dist is missing or stale; run `npm run build` in frontend/",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    data_dir = tmp_path_factory.mktemp("browser")
    port = _free_port()
    env = {
        **os.environ,
        "TP_ENV": "test",
        "TP_DB_URL": f"sqlite:///{data_dir / 'browser.db'}",
        "TP_DATA_DIR": str(data_dir),
        "TP_JWT_SECRET": "browser-test-secret-that-is-long-enough",
        "TP_BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL,
        "TP_BOOTSTRAP_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "TP_WEB_SEC_ALLOW_LOOPBACK": "true",
    }
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=ROOT / "backend",
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 40
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                output = process.stdout.read() if process.stdout else ""
                raise RuntimeError(f"API exited during startup:\n{output}")
            try:
                if httpx.get(f"{base}/api/v1/health/ready", timeout=2.0).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        else:
            raise RuntimeError("API did not become ready for the browser test")
        yield base
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _launch(browser_type):
    """Prefer the installed Google Chrome, fall back to Playwright's build."""
    failures: list[str] = []
    for options in ({"channel": "chrome"}, {}):
        try:
            return browser_type.launch(headless=True, **options)
        except playwright_api.Error as exc:  # pragma: no cover - environment dependent
            failures.append(str(exc).splitlines()[0])
    raise RuntimeError("no usable Chromium build: " + " | ".join(failures))


def test_dashboard_password_change_keeps_this_tab_and_revokes_the_others(live_server: str):
    other_session = httpx.post(
        f"{live_server}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert other_session.status_code == 200, other_session.text
    other_token = other_session.json()["access_token"]

    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page()
            console_errors: list[str] = []
            page.on(
                "console",
                lambda message: console_errors.append(message.text)
                if message.type == "error"
                else None,
            )
            page.on("pageerror", lambda error: console_errors.append(str(error)))
            # The duplicate-resolution note needs a superseded row, which the
            # schema now prevents from arising naturally: serve a pair that
            # mirrors what migration 7 leaves behind.
            page.route(
                "**/api/v1/investigations",
                lambda route: route.fulfill(
                    json={
                        "items": [
                            {
                                "id": "inv_1111111111111111",
                                "created_at": "2026-10-24T11:00:00+00:00",
                                "campaign_id": "camp_demo",
                                "edge_id": "edg_demo",
                                "status": "planned",
                                "chosen_profile": "http-admin-console",
                                "missing_evidence": ["identity"],
                                "outcome": None,
                                "notes": "",
                            },
                            {
                                "id": "inv_2222222222222222",
                                "created_at": "2026-10-24T10:00:00+00:00",
                                "campaign_id": "camp_demo",
                                "edge_id": "edg_demo",
                                "status": "superseded",
                                "chosen_profile": "http-wordpress",
                                "missing_evidence": [],
                                "outcome": None,
                                "notes": "",
                            },
                        ]
                    }
                ),
            )
            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            # Every view must render against the live API without console
            # errors, including the Deception page's superseded-investigation
            # note and the Account page's session table.
            for view in (
                "Overview",
                "Events",
                "Campaigns",
                "Deception",
                "Web findings",
                "Asset risk",
                "Responses",
                "Administration",
            ):
                page.get_by_role("button", name=view, exact=True).click()
                page.wait_for_selector(".page h1")
                if view == "Deception":
                    note = page.get_by_text("Closed because another investigation", exact=False)
                    note.wait_for()
                    assert "replaced by inv_1111" in note.inner_text()
                    badge = page.locator(".badge.status-superseded")
                    assert badge.count() == 1, badge.count()
            assert console_errors == [], console_errors

            page.get_by_role("button", name="Account").click()
            page.wait_for_selector("text=Recent sessions")
            page.wait_for_selector("td:has-text('Sign-in')")

            page.get_by_label("Current password").fill(ADMIN_PASSWORD)
            page.get_by_label("New password", exact=True).fill(NEW_PASSWORD)
            page.get_by_label("Confirm new password").fill(NEW_PASSWORD)
            page.get_by_role("button", name="Change password").click()
            page.wait_for_selector("text=Every other session was signed out")
            page.wait_for_selector("td:has-text('Password changed')")

            # The replacement token was stored: a reload restores the session
            # instead of returning to the sign-in screen.
            page.reload(wait_until="domcontentloaded")
            page.wait_for_selector(".sidebar")
            assert page.locator(".login-card").count() == 0

            page.get_by_role("button", name="Account").click()
            page.wait_for_selector("td:has-text('Sign-in')")
            assert page.locator("text=revoked").count() >= 1
        finally:
            browser.close()

    # The token captured before the change is refused, and the new password
    # signs in normally.
    stale = httpx.get(
        f"{live_server}/api/v1/events",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert stale.status_code == 401, stale.text
    assert httpx.post(
        f"{live_server}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": NEW_PASSWORD},
    ).status_code == 200
