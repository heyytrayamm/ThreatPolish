from __future__ import annotations

import pytest


def test_demo_seed_populates_telemetry_and_retention_history(client):
    from app.db.retention import retention_history
    from app.demo import seed_demo_data

    first = seed_demo_data(seed=7)
    assert first["events_accepted"] > 0
    assert first["campaigns"] >= 1
    assert first["retention_runs_added"] == 7

    history = retention_history()
    assert len(history) == 7
    assert all(run["id"].startswith("rtn_demo_") for run in history)
    assert history[0]["trigger"] == "scheduled"

    second = seed_demo_data(seed=7)
    assert second["events_accepted"] == 0
    assert second["events_duplicate"] == 0
    assert second["retention_runs_added"] == 0
    assert len(retention_history()) == 7


def test_demo_seed_refuses_production(client, monkeypatch):
    from app.core.config import reset_settings_cache
    from app.demo import seed_demo_data

    monkeypatch.setenv("TP_ENV", "production")
    reset_settings_cache()
    with pytest.raises(RuntimeError, match="disabled"):
        seed_demo_data()
