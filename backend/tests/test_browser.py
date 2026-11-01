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
import re
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
VIEWER_EMAIL = "viewer@threatpolish.test"
VIEWER_PASSWORD = "browser-viewer-password-1"
ANALYST_EMAIL = "analyst-browser@threatpolish.test"
ANALYST_PASSWORD = "browser-analyst-password-1"

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


@pytest.fixture()
def live_server(tmp_path: Path) -> Iterator[str]:
    data_dir = tmp_path
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


def _applied_theme(page) -> str:
    return page.evaluate("document.documentElement.dataset.theme")


def _wait_for_theme(page, expected: str, timeout: float = 5.0) -> None:
    """Poll for the applied theme.

    `page.wait_for_function` cannot be used here: it evaluates the expression
    with `eval`, which the dashboard's `script-src 'self'` forbids.
    """
    deadline = time.monotonic() + timeout
    seen = None
    while time.monotonic() < deadline:
        seen = _applied_theme(page)
        if seen == expected:
            return
        page.wait_for_timeout(50)
    raise AssertionError(f"the theme stayed on {seen!r}, expected {expected!r}")


def _launch(browser_type):
    """Prefer the installed Google Chrome, fall back to Playwright's build."""
    failures: list[str] = []
    for options in ({"channel": "chrome"}, {}):
        try:
            return browser_type.launch(headless=True, **options)
        except playwright_api.Error as exc:  # pragma: no cover - environment dependent
            failures.append(str(exc).splitlines()[0])
    raise RuntimeError("no usable Chromium build: " + " | ".join(failures))


_HTTP_PATHS = ["/admin", "/console", "/config", "/backup"]


def _seed_campaign(base: str) -> str:
    """Create telemetry that correlates into one campaign, as a sensor would."""
    from datetime import datetime, timedelta, timezone

    login = httpx.post(
        f"{base}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert login.status_code == 200, login.text
    admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
    token = httpx.post(
        f"{base}/api/v1/auth/tokens",
        headers=admin,
        json={"name": "browser-sensor", "role": "sensor"},
    )
    assert token.status_code == 201, token.text
    sensor = token.json()["token"]

    now = datetime.now(timezone.utc)
    events = []
    for index in range(2):
        for offset, path in enumerate(_HTTP_PATHS):
            events.append(
                {
                    "schema_version": "1.0",
                    "occurred_at": (now - timedelta(minutes=40 - offset - index)).isoformat(),
                    "source_module": "honeypot",
                    "event_type": "honeypot.http.request",
                    "source_ip": f"203.0.113.{31 + index}",
                    "session_id": f"sess-browser-{index}",
                    "target_id": "decoy-http-1",
                    "severity": "medium",
                    "provenance": {
                        "collector": "browser-test",
                        "source": "http-decoy",
                        "reliability": 0.8,
                        "synthetic": True,
                        "indicators": ["ja3:browser-test"],
                    },
                    "features": {
                        "method": "GET",
                        "path": path,
                        "status": 200,
                        "user_agent": "curl/8.4.0",
                    },
                }
            )

    ingested = httpx.post(
        f"{base}/api/v1/ingest/events", json=events, headers={"X-Agent-Token": sensor}
    )
    assert ingested.status_code == 202, ingested.text
    assert ingested.json()["rejected"] == 0, ingested.text
    run = httpx.post(f"{base}/api/v1/correlate", headers=admin, json={})
    assert run.status_code == 200, run.text
    campaigns = httpx.get(f"{base}/api/v1/campaigns", headers=admin).json()["items"]
    assert campaigns, "seeded telemetry did not produce a campaign"
    return campaigns[0]["id"]


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
            page.context.grant_permissions(
                ["clipboard-read", "clipboard-write"], origin=live_server
            )
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
            page.route(
                re.compile(r".*/api/v1/retention(?:\?.*)?$"),
                lambda route: route.fulfill(
                    json={
                        "generated_at": "2026-10-24T10:00:00+00:00",
                        "overdue": False,
                        "grace_days": 2,
                        "history_total": 16,
                        "history_counts": {"manual": 1, "scheduled": 15},
                        "events": {
                            "retention_days": 90,
                            "total": 12,
                            "expired": 1,
                            "oldest_occurred_at": "2026-07-24T00:00:00+00:00",
                            "oldest_retention_until": "2026-10-22T00:00:00+00:00",
                        },
                        "graph": {
                            "retention_days": 30,
                            "cutoff": "2026-09-24T00:00:00+00:00",
                            "nodes": 8,
                            "edges": 6,
                            "retired_edges": 1,
                            "stale_observations": 1,
                            "orphan_nodes": 0,
                        },
                        "history": [
                            {
                                "id": "rtn_2",
                                "ran_at": "2026-10-24T09:00:00+00:00",
                                "trigger": "scheduled",
                                "duration_ms": 12,
                                "events_removed": 2,
                                "edges_removed": 1,
                                "observations_removed": 1,
                                "nodes_removed": 1,
                                "events_expired": 2,
                                "retired_edges": 1,
                                "stale_observations": 1,
                                "graph_nodes": 8,
                                "graph_edges": 6,
                                "overdue": False,
                            },
                            {
                                "id": "rtn_1",
                                "ran_at": "2026-10-23T09:00:00+00:00",
                                "trigger": "scheduled",
                                "duration_ms": 10,
                                "events_removed": 4,
                                "edges_removed": 2,
                                "observations_removed": 0,
                                "nodes_removed": 2,
                                "events_expired": 4,
                                "retired_edges": 2,
                                "stale_observations": 0,
                                "graph_nodes": 9,
                                "graph_edges": 8,
                                "overdue": True,
                            },
                        ],
                    }
                ),
            )

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
                "Retention",
                "Administration",
            ):
                page.get_by_role("button", name=view, exact=True).click()
                page.wait_for_selector(".page h1")
                if view == "Events":
                    page.get_by_label("Module").select_option("honeypot")
                    page.get_by_label("Severity").select_option("medium")
                    page.get_by_label("Window").select_option("72")
                    page.get_by_label("Search").fill("203.0.113")
                    page.get_by_label("Search").press("Enter")
                    page.wait_for_function(
                        "location.search.includes('event_q=203.0.113')"
                    )
                    assert "event_module=honeypot" in page.url
                    assert "event_severity=medium" in page.url
                    assert "event_hours=72" in page.url
                    assert "event_q=203.0.113" in page.url

                    page.get_by_role("button", name="Copy link").click()
                    page.wait_for_selector("text=Link copied to the clipboard")
                    copied = page.evaluate("navigator.clipboard.readText()")
                    assert "event_module=honeypot" in copied
                    assert "event_q=203.0.113" in copied

                    # Committed filters are history entries: back clears the
                    # search, forward puts it back.
                    with page.expect_request(
                        lambda request: "q=203.0.113" not in request.url
                    ):
                        page.go_back()
                    page.wait_for_function("!location.search.includes('event_q=')")
                    assert page.get_by_label("Search").input_value() == ""
                    with page.expect_request(
                        lambda request: "q=203.0.113" in request.url
                    ):
                        page.go_forward()
                    assert page.get_by_label("Search").input_value() == "203.0.113"

                    # A reload restores the same Events view and filters.
                    page.reload(wait_until="domcontentloaded")
                    page.wait_for_selector(".sidebar")
                    page.wait_for_selector(".page h1:has-text('Events')")
                    assert page.get_by_label("Module").input_value() == "honeypot"
                    assert page.get_by_label("Severity").input_value() == "medium"
                    assert page.get_by_label("Window").input_value() == "72"
                    assert page.get_by_label("Search").input_value() == "203.0.113"
                if view == "Deception":
                    note = page.get_by_text("Closed because another investigation", exact=False)
                    note.wait_for()
                    assert "replaced by inv_1111" in note.inner_text()
                    badge = page.locator(".badge.status-superseded")
                    assert badge.count() == 1, badge.count()
                if view == "Administration":
                    # The retention card reads the admin-only endpoint; the
                    # horizon row and trend only exist once that response landed.
                    page.get_by_text("Graph horizon").wait_for()
                    page.get_by_text("Backlog before each run").wait_for()
                    page.get_by_role("button", name="Run retention now").wait_for()
                    page.get_by_text(
                        "Showing the last 2 of 16 recorded runs", exact=False
                    ).wait_for()
                    page.get_by_text("1 manual · 15 scheduled", exact=False).wait_for()

                    # The run-history filter is applied explicitly and drives
                    # both the table count and the export request.
                    page.get_by_label("Runs from (UTC)").fill("2026-10-20")
                    page.get_by_label("Runs to (UTC)").fill("2026-10-24")
                    page.get_by_label("Trigger").select_option("scheduled")
                    with page.expect_request(
                        lambda request: "history_since=2026-10-20" in request.url
                        and "history_until=2026-10-24" in request.url
                        and "history_trigger=scheduled" in request.url
                    ):
                        page.get_by_role("button", name="Apply", exact=True).click()
                    page.get_by_text(
                        "Showing the last 2 of 16 matching runs", exact=False
                    ).wait_for()
                    assert "view=admin" in page.url
                    assert "history_since=2026-10-20" in page.url
                    assert "history_until=2026-10-24" in page.url
                    assert "history_trigger=scheduled" in page.url

                    # The card copies the current URL, filters included.
                    page.get_by_role("button", name="Copy link").click()
                    page.wait_for_selector("text=Link copied to the clipboard")
                    copied = page.evaluate("navigator.clipboard.readText()")
                    assert "view=admin" in copied
                    assert "history_since=2026-10-20" in copied
                    assert "history_trigger=scheduled" in copied

                    # The URL is the sharing state: reloading restores the
                    # filtered view instead of dropping back to the defaults.
                    page.reload(wait_until="domcontentloaded")
                    page.wait_for_selector(".sidebar")
                    page.get_by_text(
                        "Showing the last 2 of 16 matching runs", exact=False
                    ).wait_for()
                    assert page.get_by_label("Trigger").input_value() == "scheduled"
                    assert (
                        page.get_by_label("Runs from (UTC)").input_value()
                        == "2026-10-20"
                    )

                    # A denied Clipboard API still copies through the fallback.
                    page.evaluate("navigator.clipboard.writeText('sentinel')")
                    page.evaluate(
                        "Object.defineProperty(navigator.clipboard, 'writeText', {"
                        " configurable: true,"
                        " value: () => Promise.reject(new Error('denied')) })"
                    )
                    page.get_by_role("button", name="Copy link").click()
                    page.wait_for_selector("text=Link copied to the clipboard")
                    copied = page.evaluate("navigator.clipboard.readText()")
                    assert "sentinel" not in copied
                    assert "history_since=2026-10-20" in copied

                    with page.expect_download() as download_info:
                        with page.expect_request(
                            lambda request: "history.csv" in request.url
                            and "history_since=2026-10-20" in request.url
                            and "history_trigger=scheduled" in request.url
                        ):
                            page.get_by_role("button", name="Export CSV").click()
                    download = download_info.value
                    assert download.suggested_filename.startswith(
                        "threatpolish-retention-"
                    ), download.suggested_filename
                    assert download.suggested_filename.endswith(".csv")
                    page.wait_for_selector("text=Retention history exported as CSV")

                    # A quick range sends exact UTC timestamps rather than
                    # day boundaries, so it covers the last 24/168/720 hours.
                    with page.expect_request(
                        lambda request: "history_since=" in request.url
                        and "T" in request.url
                        and "history_trigger=scheduled" in request.url
                    ):
                        page.get_by_role("button", name="7 days", exact=True).click()
                    page.get_by_text(
                        "Showing the last 2 of 16 matching runs", exact=False
                    ).wait_for()

                    page.get_by_role("button", name="Clear", exact=True).click()
                    assert page.get_by_label("Trigger").input_value() == ""
                    assert "history_since" not in page.url
                    assert "history_trigger" not in page.url
                    page.get_by_text(
                        "Showing the last 2 of 16 recorded runs", exact=False
                    ).wait_for()

            # Filter changes are history entries too: back restores the quick
            # range, then the date range, then the unfiltered view.
            with page.expect_request(
                lambda request: "history_since=" in request.url
                and "T" in request.url
                and "history_trigger=scheduled" in request.url
            ):
                page.go_back()
            page.wait_for_function("location.search.includes('history_since=')")
            # The day filter is a bare date; the quick range is a full
            # timestamp that happens to start with the same day once "7 days
            # ago" is 2026-10-20, so compare the delimiter, not the prefix.
            assert "history_since=2026-10-20&" not in page.url
            page.get_by_text(
                "Showing the last 2 of 16 matching runs", exact=False
            ).wait_for()

            with page.expect_request(
                lambda request: "history_since=2026-10-20" in request.url
                and "history_until=2026-10-24" in request.url
            ):
                page.go_back()
            page.wait_for_function(
                "location.search.includes('history_since=2026-10-20')"
            )
            assert page.get_by_label("Runs from (UTC)").input_value() == "2026-10-20"
            assert page.get_by_label("Runs to (UTC)").input_value() == "2026-10-24"
            assert page.get_by_label("Trigger").input_value() == "scheduled"

            with page.expect_request(
                lambda request: "history_since" not in request.url
                and "history_trigger" not in request.url
            ):
                page.go_back()
            assert "history_since" not in page.url
            assert "history_trigger" not in page.url
            assert "view=admin" in page.url

            # The sidebar's history follows the browser's back and forward
            # buttons instead of only changing React state.
            page.go_back()
            page.wait_for_selector(".page h1:has-text('Retention')")
            assert "view=retention" in page.url
            page.go_forward()
            page.wait_for_selector(".page h1:has-text('Administration')")
            assert "view=admin" in page.url

            with page.expect_request(
                lambda request: "history_since=2026-10-20" in request.url
            ):
                page.go_forward()
            page.wait_for_function(
                "location.search.includes('history_since=2026-10-20')"
            )
            assert page.get_by_label("Runs from (UTC)").input_value() == "2026-10-20"
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


def test_analyst_sees_read_only_retention_history(live_server: str):
    admin_login = httpx.post(
        f"{live_server}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert admin_login.status_code == 200, admin_login.text
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
    account = httpx.post(
        f"{live_server}/api/v1/auth/users",
        headers=admin_headers,
        json={
            "email": ANALYST_EMAIL,
            "name": "Retention Analyst",
            "role": "analyst",
            "password": ANALYST_PASSWORD,
        },
    )
    assert account.status_code == 201, account.text
    run = httpx.post(f"{live_server}/api/v1/retention/run", headers=admin_headers)
    assert run.status_code == 200, run.text

    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page()
            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ANALYST_EMAIL)
            page.get_by_label("Password", exact=True).fill(ANALYST_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            retention = page.get_by_role("button", name="Retention", exact=True)
            retention.wait_for()
            assert (
                page.get_by_role("button", name="Administration", exact=True).count()
                == 0
            )
            retention.click()
            page.get_by_text("Graph horizon").wait_for()
            page.get_by_text("1 recorded run", exact=False).wait_for()
            page.get_by_role("button", name="Export CSV").wait_for()
            assert page.get_by_role("button", name="Run retention now").count() == 0

            # A link with malformed filters is explained and cleaned up rather
            # than producing a validation error from the API.
            page.goto(
                f"{live_server}/?view=retention&history_since=not-a-date"
                "&history_trigger=hourly",
                wait_until="domcontentloaded",
            )
            page.wait_for_selector("text=The shared link has an invalid")
            page.wait_for_function("!location.search.includes('history_since')")
            assert page.get_by_label("Trigger").input_value() == ""
            page.get_by_text("Graph horizon").wait_for()

            # An inverted window is treated the same way instead of reaching
            # the API as a validation error.
            page.goto(
                f"{live_server}/?view=retention&history_since=2026-10-24"
                "&history_until=2026-10-20",
                wait_until="domcontentloaded",
            )
            page.get_by_text(
                "The shared link's start date is after its end date", exact=False
            ).wait_for()
            page.wait_for_function("!location.search.includes('history_since')")
            page.get_by_text("Graph horizon").wait_for()

            # Analysts now receive the Overview alert, and its link opens
            # their own read-only page rather than Administration.
            retention_pattern = re.compile(r".*/api/v1/retention(?:\?.*)?$")
            page.route(
                retention_pattern,
                lambda route: route.fulfill(
                    json={
                        "generated_at": "2026-10-24T10:00:00+00:00",
                        "overdue": True,
                        "grace_days": 2,
                    }
                ),
            )
            page.get_by_role("button", name="Overview", exact=True).click()
            page.wait_for_selector("text=Retention is overdue")
            page.unroute(retention_pattern)
            page.get_by_role("button", name="Open Retention").click()
            page.wait_for_selector(".page h1:has-text('Retention')")
            assert "view=retention" in page.url
            page.get_by_text("Graph horizon").wait_for()

            # A hand-edited link to an administrator view must fall back to the
            # analyst's Overview instead of mounting the administration page.
            page.goto(f"{live_server}/?view=admin", wait_until="domcontentloaded")
            page.wait_for_selector(".page h1:has-text('Overview')")
            page.wait_for_function("!location.search.includes('view=admin')")
            assert (
                page.get_by_role("button", name="Administration", exact=True).count()
                == 0
            )
        finally:
            browser.close()


def test_session_history_signs_out_one_device_and_admins_can_inspect_it(live_server: str):
    second = httpx.post(
        f"{live_server}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        headers={"User-Agent": "browser-second-device/1.0"},
    )
    assert second.status_code == 200, second.text
    second_token = second.json()["access_token"]

    # A second account gives the administrator someone else's device to sign out.
    admin_login = httpx.post(
        f"{live_server}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert admin_login.status_code == 200, admin_login.text
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
    account = httpx.post(
        f"{live_server}/api/v1/auth/users",
        headers=admin_headers,
        json={
            "email": VIEWER_EMAIL,
            "name": "Viewer",
            "role": "viewer",
            "password": VIEWER_PASSWORD,
        },
    )
    assert account.status_code == 201, account.text

    def viewer_sign_in(agent: str) -> str:
        response = httpx.post(
            f"{live_server}/api/v1/auth/login",
            json={"email": VIEWER_EMAIL, "password": VIEWER_PASSWORD},
            headers={"User-Agent": agent},
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]

    desk_token = viewer_sign_in("viewer-desk/1.0")
    cloud_token = viewer_sign_in("viewer-cloud/1.0")

    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page()
            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            page.get_by_role("button", name="Account").click()
            page.wait_for_selector("td:has-text('Sign-in')")
            assert page.get_by_text("this device").count() >= 1

            other = page.locator("tr", has_text="browser-second-device/1.0")
            other.wait_for()
            other.get_by_role("button", name="Sign out").click()
            page.wait_for_selector("text=That device was signed out")
            page.wait_for_selector(
                "tr:has-text('browser-second-device/1.0') .badge:has-text('revoked')"
            )

            # The administrator can open another account's history. This
            # deployment has the bootstrap administrator only.
            page.get_by_role("button", name="Administration").click()
            page.get_by_role("button", name="Sessions", exact=True).first.click()
            page.wait_for_selector("text=/Sessions\\s[-—]\\sAdministrator/")
            page.wait_for_selector("#main td:has-text('Sign-in')")

            # The administrator signs one device out of another account without
            # touching that account's other session.
            account_row = page.locator("#main tr", has_text=VIEWER_EMAIL)
            account_row.get_by_role("button", name="Sessions", exact=True).click()
            page.wait_for_selector("text=/Sessions\\s[-—]\\sViewer/")
            desk_row = page.locator("#main tr", has_text="viewer-desk/1.0")
            desk_row.wait_for()
            desk_row.get_by_role("button", name="Sign out").click()
            page.wait_for_selector(f"text=That device was signed out of {VIEWER_EMAIL}")
            page.wait_for_selector(
                "tr:has-text('viewer-desk/1.0') .badge:has-text('revoked')"
            )

            # Sensor credentials are created and revoked from the same page.
            page.get_by_label("Token name").fill("browser-sensor-ui")
            page.get_by_role("button", name="Create token").click()
            page.wait_for_selector("text=was created. Copy the token now")
            sensor_token = page.locator(".notice pre").inner_text().strip()
            assert sensor_token.startswith("tp_"), sensor_token
            token_row = page.locator("#main tr", has_text="browser-sensor-ui")
            token_row.wait_for()
            assert "active" in token_row.inner_text()

            live = httpx.get(
                f"{live_server}/api/v1/auth/me", headers={"X-Agent-Token": sensor_token}
            )
            assert live.status_code == 200, live.text

            token_row.get_by_role("button", name="Revoke").click()
            page.wait_for_selector("text=browser-sensor-ui was revoked")
            page.wait_for_selector(
                "tr:has-text('browser-sensor-ui') .badge:has-text('revoked')"
            )

            # An account-level alert must reach the Overview page as well.
            page.route(
                "**/api/v1/auth/sessions*",
                lambda route: route.fulfill(
                    json={
                        "user_id": "usr_demo",
                        "current_session_version": 1,
                        "note": "demo",
                        "sessions": [
                            {
                                "id": "aud_demo",
                                "occurred_at": "2026-10-24T10:00:00+00:00",
                                "event": "sign_in",
                                "ip": "198.51.100.7",
                                "client": "browser",
                                "outcome": "success",
                                "session_version": 1,
                                "state": "active",
                                "jti": "jti_demo",
                                "current": True,
                                "expires_at": None,
                                "anomaly": {
                                    "kind": "distant_signin",
                                    "previous_ip": "203.0.113.10",
                                    "previous_at": "2026-10-24T09:56:00+00:00",
                                    "detected_at": "2026-10-24T10:00:00+00:00",
                                    "distance_km": 5570,
                                    "threshold_km": 500,
                                    "window_minutes": 30,
                                },
                            }
                        ],
                    }
                ),
            )
            page.route(
                "**/api/v1/retention",
                lambda route: route.fulfill(
                    json={
                        "generated_at": "2026-10-24T10:00:00+00:00",
                        "overdue": True,
                        "grace_days": 2,
                        "history_total": 0,
                        "history_counts": {"manual": 0, "scheduled": 0},
                        "history": [],
                        "events": {
                            "retention_days": 90,
                            "total": 10,
                            "expired": 3,
                            "oldest_occurred_at": "2026-07-01T00:00:00+00:00",
                            "oldest_retention_until": "2026-09-29T00:00:00+00:00",
                        },
                        "graph": {
                            "retention_days": 30,
                            "cutoff": "2026-09-24T00:00:00+00:00",
                            "nodes": 5,
                            "edges": 4,
                            "retired_edges": 1,
                            "stale_observations": 1,
                            "orphan_nodes": 0,
                        },
                    }
                ),
            )
            page.get_by_role("button", name="Overview").click()
            page.wait_for_selector("text=Retention is overdue")
            page.wait_for_selector("text=Sign-in attention")
            page.wait_for_selector("text=Unusual sign-in")
            assert "5,570 km" in page.inner_text("#main")

            # The administrator's alert opens the same Retention page as the
            # sidebar entry, not the Administration credentials panel.
            page.get_by_role("button", name="Open Retention").click()
            page.wait_for_selector(".page h1:has-text('Retention')")
            assert "view=retention" in page.url
            page.get_by_text("Graph horizon").wait_for()
        finally:
            browser.close()

    stale = httpx.get(
        f"{live_server}/api/v1/events",
        headers={"Authorization": f"Bearer {second_token}"},
    )
    assert stale.status_code == 401, stale.text

    # The device the administrator signed out is refused; the account's other
    # device and its password are unaffected.
    assert httpx.get(
        f"{live_server}/api/v1/events",
        headers={"Authorization": f"Bearer {desk_token}"},
    ).status_code == 401
    assert httpx.get(
        f"{live_server}/api/v1/events",
        headers={"Authorization": f"Bearer {cloud_token}"},
    ).status_code == 200

    # The token revoked through the dashboard is refused immediately.
    assert httpx.get(
        f"{live_server}/api/v1/auth/me", headers={"X-Agent-Token": sensor_token}
    ).status_code == 401


def test_dashboard_plans_and_activates_an_investigation(live_server: str):
    _seed_campaign(live_server)

    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page()
            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            page.get_by_role("button", name="Campaigns").click()
            page.locator(".list-item").first.wait_for()
            page.locator(".list-item").first.click()
            page.get_by_role("button", name="Plan investigation").click()
            page.wait_for_selector("text=planned with profile")

            notice = page.locator(".notice").first.inner_text()
            investigation_id = notice.split("Investigation ")[1].split(" ")[0]
            assert investigation_id.startswith("inv_"), notice

            page.get_by_role("button", name="Deception").click()
            # The decoy session read model is a dashboard view in its own right.
            page.wait_for_selector("text=Decoy sessions (24h)")
            decoy_session = page.locator("#main tr", has_text="sess-browser-0").first
            decoy_session.wait_for()
            assert "203.0.113.31" in decoy_session.inner_text()

            row = page.locator(".list-item", has_text=investigation_id[:16]).first
            row.wait_for()
            assert "planned" in row.inner_text()

            row.locator("input[placeholder='source IP']").fill("203.0.113.50")
            row.get_by_role("button", name="Activate").click()
            page.wait_for_selector("text=active for 203.0.113.50")
            page.wait_for_selector(
                f".list-item:has-text('{investigation_id[:16]}') .badge:has-text('active')"
            )
        finally:
            browser.close()


def test_campaign_detail_explains_its_evidence(live_server: str):
    """The campaign view must show the evidence, its gaps and its tactic spread.

    The matrix is built from stored edges, so a two-session campaign must render
    exactly two linked cells and two diagonal markers. The acquisition plan and
    the tactic rail are derived from the same components; the seeded HTTP probes
    are reconnaissance, so at least one tactic has to be lit.
    """
    _seed_campaign(live_server)
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

            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            page.goto(f"{live_server}/?view=campaigns", wait_until="domcontentloaded")
            page.wait_for_selector(".list .list-item")
            page.locator(".list .list-item").first.click()

            page.get_by_text("Evidence matrix").wait_for()
            matrix = page.locator("table.evidence-matrix")
            assert matrix.count() == 1
            assert matrix.locator("td.matrix-cell").count() == 2
            assert matrix.locator("td.matrix-self").count() == 2
            assert page.get_by_text("observations / link").count() == 1

            page.get_by_text("Evidence acquisition plan").wait_for()
            page.get_by_text("Kill-chain coverage").wait_for()
            rail = page.locator(".killchain-rail li")
            assert rail.count() == 11
            assert page.locator(".killchain-rail li.observed").count() >= 1
            assert page.get_by_text("Reconnaissance", exact=True).count() >= 1
            assert page.get_by_text("risk-weighted coverage").count() >= 1

            # The empty cells are a finding, not a rendering accident.
            assert page.get_by_text("no stored edge", exact=False).count() >= 1
            assert console_errors == []
        finally:
            browser.close()


def test_campaign_graph_labels_stay_apart_and_inside_the_frame(live_server: str):
    """Campaign labels share a prefix, so placement has to separate them.

    Both candidates are named "cross-IP campaign candidate <hash>".  Rendering
    the full name cut to a fixed length produced two identical labels drawn on
    top of each other, one of them running out of the graph.  The labels must
    keep the discriminating suffix, avoid each other and stay in the viewBox.
    """
    graph = {
        "window_hours": 72,
        "note": "synthetic graph for label placement",
        "edges": [],
        "nodes": [
            {"id": f"campaign:cmp_{suffix}", "kind": "campaign",
             "label": f"cross-IP campaign candidate {suffix}", "props": {}, "last_seen": "2026-10-24T10:00:00+00:00"}
            for suffix in ("5a9676", "4bad6a")
        ]
        + [
            {"id": f"session:sess-{index}", "kind": "session", "label": f"sess-{index}",
             "props": {}, "last_seen": "2026-10-24T10:00:00+00:00"}
            for index in range(4)
        ]
        + [
            {"id": f"ip:203.0.113.{index}", "kind": "ip", "label": f"203.0.113.{index}",
             "props": {}, "last_seen": "2026-10-24T10:00:00+00:00"}
            for index in (10, 11)
        ],
    }
    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page(viewport={"width": 1560, "height": 1000})
            page.route(
                re.compile(r".*/api/v1/graph\?.*$"),
                lambda route: route.fulfill(json=graph),
            )
            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")
            page.goto(f"{live_server}/?view=campaigns", wait_until="domcontentloaded")
            page.wait_for_selector("svg.graph .node-label")

            measured = page.evaluate(
                """() => {
                    const svg = document.querySelector('svg.graph').getBoundingClientRect();
                    const labels = [...document.querySelectorAll('.node-label')].map((node) => {
                        const box = node.getBoundingClientRect();
                        return { text: node.textContent, x: box.x, y: box.y,
                                 right: box.right, bottom: box.bottom };
                    });
                    const overlaps = [];
                    for (let i = 0; i < labels.length; i += 1) {
                        for (let j = i + 1; j < labels.length; j += 1) {
                            const a = labels[i];
                            const b = labels[j];
                            if (!(a.right < b.x || b.right < a.x || a.bottom < b.y || b.bottom < a.y)) {
                                overlaps.push([a.text, b.text]);
                            }
                        }
                    }
                    return { labels, overlaps, svg: { x: svg.x, y: svg.y, right: svg.right, bottom: svg.bottom } };
                }"""
            )
            labels = measured["labels"]
            assert len(labels) == 2, labels
            assert labels[0]["text"] != labels[1]["text"], labels
            assert measured["overlaps"] == [], measured["overlaps"]
            for label in labels:
                assert label["x"] >= measured["svg"]["x"] - 1, label
                assert label["right"] <= measured["svg"]["right"] + 1, label
                assert label["y"] >= measured["svg"]["y"] - 1, label
                assert label["bottom"] <= measured["svg"]["bottom"] + 1, label
        finally:
            browser.close()


def test_theme_choice_follows_the_host_and_is_remembered(live_server: str):
    """The console ships two themes and the choice has to stick.

    A host that reports a light colour scheme must start on the daylight
    variant, and a switch made in the ribbon must survive a reload instead of
    snapping back to what the host prefers.  The toggle is a real control, so
    its pressed state has to agree with the theme it applied.
    """
    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            for scheme, expected in (("dark", "console"), ("light", "daylight")):
                # Each page gets its own context, so the stored choice from the
                # first pass cannot be what decides the second.
                page = browser.new_page(
                    color_scheme=scheme, viewport={"width": 1400, "height": 900}
                )
                page.goto(live_server, wait_until="domcontentloaded")
                assert (
                    _applied_theme(page) == expected
                ), f"a {scheme} host should start on {expected}"

                page.get_by_label("Email").fill(ADMIN_EMAIL)
                page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
                page.get_by_role("button", name="Sign in").click()
                page.wait_for_selector(".sidebar")

                toggle = page.get_by_role("button", name="Daylight theme")
                assert toggle.get_attribute("aria-pressed") == str(
                    expected == "daylight"
                ).lower()

                flipped = "console" if expected == "daylight" else "daylight"
                toggle.click()
                _wait_for_theme(page, flipped)
                page.reload(wait_until="domcontentloaded")
                page.wait_for_selector(".sidebar")
                assert (
                    _applied_theme(page) == flipped
                ), "the stored choice must outrank the host preference"
                page.close()
        finally:
            browser.close()


def test_theme_follows_the_host_until_a_switch_is_stored(live_server: str):
    """A console left open must follow the room, not the state it loaded in.

    With nothing stored, a host that flips between light and dark has to move
    the theme without a reload.  Once a switch is made in the ribbon the host
    loses that control, because the analyst's choice outranks it.
    """
    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page(
                color_scheme="dark", viewport={"width": 1400, "height": 900}
            )
            page.goto(live_server, wait_until="domcontentloaded")
            assert _applied_theme(page) == "console"

            page.emulate_media(color_scheme="light")
            _wait_for_theme(page, "daylight")
            page.emulate_media(color_scheme="dark")
            _wait_for_theme(page, "console")

            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            # The host is dark, so the ribbon switch stores the daylight theme.
            page.get_by_role("button", name="Daylight theme").click()
            _wait_for_theme(page, "daylight")
            assert page.evaluate("window.localStorage.getItem('tp-theme')") == "daylight"

            # A host that now reports a light scheme agrees, so flip it back to
            # dark: the stored choice has to hold either way.
            page.emulate_media(color_scheme="light")
            page.emulate_media(color_scheme="dark")
            page.wait_for_timeout(250)
            assert (
                _applied_theme(page) == "daylight"
            ), "a stored switch must outrank a later host change"
            page.close()
        finally:
            browser.close()


def test_landing_page_explains_the_product_and_signs_in_from_the_hero(live_server: str):
    """The signed-out root is the landing page, not a bare login form."""
    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page()
            page.goto(live_server, wait_until="domcontentloaded")

            # The public page says what the platform does before it asks for a
            # credential, and the workspace is not mounted behind it.
            page.locator(".landing-page-white").wait_for()
            page.get_by_text("Attract. Detect. Investigate.").wait_for()
            assert page.locator(".app").count() == 0
            # `Retention` only exists in the workspace navigation.
            assert page.get_by_role("button", name="Retention").count() == 0

            # The legal pages open without an account and lead back to it.
            page.get_by_role("button", name="Privacy Policy").first.click()
            page.get_by_role("heading", name="Privacy Policy").wait_for()
            assert page.locator(".landing-page-white").count() == 0
            page.get_by_role("button", name="Back to Platform").click()
            page.locator(".landing-page-white").wait_for()

            # The sign-in card is part of the page, so a visitor who already has
            # an account lands in the console without a second page load.
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")
            page.locator(".sidebar .nav-item").first.wait_for()
            assert page.locator(".landing-page-white").count() == 0
            page.close()
        finally:
            browser.close()


def test_administration_creates_an_account_that_signs_in_with_its_password(live_server: str):
    """A created account can sign in with the password typed in the form."""
    created_email = "created-browser@threatpolish.test"
    created_password = "created-browser-password-1"

    with playwright_api.sync_playwright() as p:
        browser = _launch(p.chromium)
        try:
            page = browser.new_page()
            page.goto(live_server, wait_until="domcontentloaded")
            page.get_by_label("Email").fill(ADMIN_EMAIL)
            page.get_by_label("Password", exact=True).fill(ADMIN_PASSWORD)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")

            page.get_by_role("button", name="Administration").click()
            page.get_by_label("Full name").fill("Created Analyst")
            page.get_by_label("Email address").fill(created_email)
            page.get_by_label("Temporary password").fill(created_password)
            page.get_by_label("Account role").select_option("analyst")
            page.get_by_role("button", name="Create user").click()
            page.wait_for_selector(f"[role=status]:has-text('{created_email}')")

            # The account appears in the inventory the administrator is reading.
            page.wait_for_selector(f"td:has-text('{created_email}')")

            # Signing out and back in with the typed password proves the form
            # stored what it said it did, and the new role's navigation applies.
            page.get_by_role("button", name="Sign out").click()
            page.locator(".landing-page-white").wait_for()
            page.get_by_label("Email").fill(created_email)
            page.get_by_label("Password", exact=True).fill(created_password)
            page.get_by_role("button", name="Sign in").click()
            page.wait_for_selector(".sidebar")
            assert page.get_by_role("button", name="Administration").count() == 0
            assert page.locator(".role-chip:has-text('analyst')").count() == 1
            page.close()
        finally:
            browser.close()
