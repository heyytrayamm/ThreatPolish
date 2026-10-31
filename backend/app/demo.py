"""Development-only demo data.

The retention chart needs history, and a fresh installation has none until the
scheduled service has run for several days.  This seeds a small synthetic
telemetry set, one correlation run and a week of illustrative retention history
so a local review can exercise the real dashboard.
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from typing import Any

from sqlalchemy import select, text

from .core.config import get_settings
from .core.security import iso, utcnow
from .db.database import connection
from .db.schema import retention_runs


def seed_demo_data(*, seed: int = 7) -> dict[str, Any]:
    """Populate a development database; disabled in production.

    Ingestion is idempotent, and demo retention rows use fixed identifiers, so
    running this twice does not duplicate either telemetry or history.
    """
    settings = get_settings()
    if settings.is_production:
        raise RuntimeError("seed-demo is disabled when TP_ENV=production")

    from .correlation.engine import correlate
    from .evaluation.scenarios import generate_dataset
    from .telemetry.ingest import Ingestor

    dataset = generate_dataset(
        seed=seed,
        campaign_groups=3,
        sessions_per_group=3,
        benign_sessions=4,
        same_ip_pairs=1,
        incomplete_groups=1,
        delayed_sessions=1,
        generic_groups=0,
    )
    events = [
        event
        for session in dataset["sessions"]
        for event in session["events"]
    ]
    # Session identifiers are deterministic, so an existing one means a previous
    # seed already ran.  Re-ingesting with fresh timestamps would otherwise
    # duplicate the whole demo set.
    marker = dataset["sessions"][0]["id"]
    with connection() as conn:
        already_seeded = bool(
            conn.execute(
                text("SELECT COUNT(*) FROM events WHERE session_id = :session"),
                {"session": marker},
            ).scalar_one()
        )
    if already_seeded:
        accepted = duplicates = 0
    else:
        report = Ingestor(settings).ingest(events, actor="demo-seed")
        accepted, duplicates = report.accepted, report.duplicates
    login = _ensure_demo_login()
    correlation = correlate(window_hours=6, trigger="demo", actor="demo-seed")
    history_added = _seed_retention_history()
    return {
        "seed": seed,
        "login": login,
        "sessions_generated": len(dataset["sessions"]),
        "events_accepted": accepted,
        "events_duplicate": duplicates,
        "edges_created": correlation["edges_created"],
        "campaigns": correlation["campaigns"],
        "retention_runs_added": history_added,
    }


def _seed_retention_history() -> int:
    with connection() as conn:
        existing = set(
            conn.execute(
                select(retention_runs.c.id).where(
                    retention_runs.c.id.like("rtn_demo_%")
                )
            ).scalars()
        )
        if existing:
            return 0
        nodes = int(conn.execute(text("SELECT COUNT(*) FROM graph_nodes")).scalar_one() or 0)
        edges = int(conn.execute(text("SELECT COUNT(*) FROM graph_edges")).scalar_one() or 0)
        now = utcnow()
        backlogs = [9, 7, 8, 5, 6, 3, 2]
        retired = [4, 3, 3, 2, 2, 1, 1]
        stale = [2, 1, 2, 1, 1, 0, 0]
        for index, expired in enumerate(backlogs):
            days_ago = len(backlogs) - index
            conn.execute(
                retention_runs.insert().values(
                    id=f"rtn_demo_{index + 1}",
                    ran_at=iso(now - timedelta(days=days_ago)),
                    trigger="scheduled",
                    duration_ms=6 + index,
                    events_removed=max(0, expired - 2),
                    edges_removed=retired[index],
                    observations_removed=stale[index],
                    nodes_removed=max(0, retired[index] - 1),
                    events_expired=expired,
                    retired_edges=retired[index],
                    stale_observations=stale[index],
                    graph_nodes=max(0, nodes - (len(backlogs) - index) * 2),
                    graph_edges=max(0, edges - (len(backlogs) - index) * 3),
                    overdue=1 if index == 0 else 0,
                )
            )
    return len(backlogs)


def _ensure_demo_login() -> dict[str, str] | None:
    """Create one known sign-in when the database has no accounts.

    A generated password is printed once by the CLI.  An explicitly supplied
    ``TP_DEMO_PASSWORD`` is honoured so a reviewer can choose it; use of a
    weak value is the operator's choice in a development environment.
    """
    from .auth.users import count_users, create_user

    if count_users() > 0:
        return None
    email = os.environ.get("TP_DEMO_EMAIL", "demo@threatpolish.local").strip()
    password = os.environ.get("TP_DEMO_PASSWORD") or secrets.token_urlsafe(12)
    create_user(email=email, name="Demo Administrator", role="admin", password=password)
    return {"email": email, "password": password}
