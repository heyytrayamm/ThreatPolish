#!/usr/bin/env python3
"""Measure end-to-end correlation cost at increasing session counts.

The engine scores every pair of sessions in the window, so its runtime grows
with the square of the session count.  This script builds a scratch SQLite
database, fills it with the laballed synthetic telemetry from the evaluation
scenarios, and times ``correlate`` at each requested size.  The numbers it
prints are the evidence behind ``MAX_SESSIONS_PER_RUN``.

Usage:
    python scripts/benchmark_correlation.py
    python scripts/benchmark_correlation.py --sessions 400 800 --repeat 2
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _dataset_sizes(target: int) -> dict[str, int]:
    """Scale the benchmark shape to roughly ``target`` sessions."""
    campaign_groups = max(2, round(target * 0.60 / 3))
    generic_groups = max(0, round(target * 0.10 / 3))
    benign_sessions = max(2, round(target * 0.20))
    same_ip_pairs = max(0, round(target * 0.03))
    incomplete_groups = max(1, round(target * 0.01))
    delayed_sessions = 3
    return {
        "campaign_groups": campaign_groups,
        "generic_groups": generic_groups,
        "benign_sessions": benign_sessions,
        "same_ip_pairs": same_ip_pairs,
        "incomplete_groups": incomplete_groups,
        "delayed_sessions": delayed_sessions,
    }


def _rows(payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from app.db.database import dumps
    from app.schemas.event import EventIn
    from app.telemetry.normalize import normalize_event

    received = "2026-01-01T00:00:00+00:00"
    rows: list[dict[str, Any]] = []
    for payload in payloads:
        event = EventIn.model_validate(payload)
        normalized = normalize_event(event)
        event_id = f"evt_bench_{len(rows):07d}"
        digest = hashlib.sha256(
            f"{event_id}|{dumps(normalized)}".encode("utf-8")
        ).hexdigest()
        rows.append(
            {
                "id": event_id,
                "schema_version": event.schema_version,
                "occurred_at": event.occurred_at.isoformat(),
                "received_at": received,
                "source_module": event.source_module,
                "event_type": event.event_type,
                "source_ip": event.source_ip,
                "session_id": event.session_id,
                "target_id": event.target_id,
                "severity": event.severity,
                "provenance": dumps(event.provenance.model_dump(mode="json")),
                "features": dumps(normalized),
                "evidence_refs": dumps(event.evidence_refs),
                "raw": dumps(event.raw),
                "dedup_key": digest,
                "status": "processed",
                "correlation_state": "pending",
                "synthetic": 1,
                "retention_until": None,
            }
        )
    return rows


def _load(path: str, payloads: list[dict[str, Any]]) -> None:
    from app.db.database import connection, init_db
    from app.db.schema import events

    init_db(path)
    with connection() as conn:
        for row in _rows(payloads):
            conn.execute(events.insert().values(**row))


def measure(
    target: int, seed: int, repeat: int, cap: int | None = None, edge_cap: int | None = None
) -> dict[str, Any]:
    sizes = _dataset_sizes(target)
    channel = tempfile.TemporaryDirectory(prefix="tp-benchmark-")
    path = os.path.join(channel.name, "benchmark.db")
    url = f"sqlite:///{path}"

    os.environ["TP_ENV"] = "test"
    os.environ["TP_DB_URL"] = url
    os.environ["TP_DATA_DIR"] = channel.name
    os.environ["TP_JWT_SECRET"] = "benchmark-secret-that-is-long-enough"

    from app.core.config import reset_settings_cache
    from app.db import database

    database.dispose_engine()
    reset_settings_cache()

    from app.correlation import engine
    from app.evaluation.scenarios import generate_dataset

    if cap is not None:
        # Measuring a candidate cap is the point of this script; the engine
        # itself still enforces whatever constant it ships with.
        engine.MAX_SESSIONS_PER_RUN = cap
    if edge_cap is not None:
        engine.MAX_EDGES_PER_RUN = edge_cap
    correlate = engine.correlate

    dataset = generate_dataset(seed=seed, **sizes)
    payloads = [event for session in dataset["sessions"] for event in session["events"]]
    load_started = time.perf_counter()
    _load(url, payloads)
    load_seconds = time.perf_counter() - load_started

    timings: list[float] = []
    last: dict[str, Any] = {}
    for index in range(max(1, repeat)):
        started = time.perf_counter()
        last = correlate(window_hours=24, trigger="benchmark")
        timings.append(time.perf_counter() - started)
        if index + 1 < repeat:
            # A second run measures the steady state: the first also writes
            # session, IP and asset nodes that later runs only update.
            time.sleep(0.05)

    database.dispose_engine()
    channel.cleanup()
    return {
        "target_sessions": target,
        "session_cap": engine.MAX_SESSIONS_PER_RUN,
        "edge_cap": engine.MAX_EDGES_PER_RUN,
        "sessions": last["sessions"],
        "events": last["events"],
        "pairs": last["pairs_scored"],
        "edges": last["edges_created"] + last["edges_updated"],
        "campaigns": last["campaigns"],
        "pairs_dropped_by_cap": last["pairs_dropped_by_cap"],
        "links_dropped_by_cap": last["links_dropped_by_cap"],
        "truncated": last["truncated"],
        "load_seconds": round(load_seconds, 3),
        "seconds": [round(value, 3) for value in timings],
        "first_seconds": round(timings[0], 3),
        "median_seconds": round(statistics.median(timings), 3),
        "worst_seconds": round(max(timings), 3),
        "milliseconds_per_pair": round(
            1000 * statistics.median(timings) / max(1, last["pairs_scored"]), 3
        ),
        "pairs_per_second": round(last["pairs_scored"] / max(1e-9, statistics.median(timings))),
        "engine_reported_ms": last["duration_ms"],
    }


def _markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Correlation runtime by session count",
        "",
        "Generated by `backend/scripts/benchmark_correlation.py` on a single host",
        "using SQLite and the synthetic evaluation dataset. Each size is a fresh",
        "database; the reported time is the median of the repeated runs. Rows up",
        "to 800 sessions run with the shipped limits (`MAX_SESSIONS_PER_RUN` 800,",
        "`MAX_EDGES_PER_RUN` 8,000); the 1,000-session row raises the session cap",
        "to show where the edge limit starts discarding linked pairs.",
        "",
        "`Dropped links` is the number of pairs the engine would have linked but",
        "did not persist because the per-run edge cap was reached. Zero is the",
        "requirement that sets the session cap.",
        "",
        "| Target sessions | Actual sessions | Events | Pairs | Dropped pairs | Dropped links | Edges | Campaigns | Median wall | Per pair |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['target_sessions']} | {row['sessions']} | {row['events']} | "
            f"{row['pairs']} | {row['pairs_dropped_by_cap']} | "
            f"{row['links_dropped_by_cap']} | {row['edges']} | "
            f"{row['campaigns']} | {row['median_seconds']:.2f}s | "
            f"{row['milliseconds_per_pair']:.3f}ms |"
        )
    lines += [
        "",
        "## Reproducing",
        "",
        "```bash",
        "cd backend",
        "python scripts/benchmark_correlation.py \\",
        "  --sessions 400 600 800 1000 --cap 1200 --edge-cap 8000 --repeat 2",
        "```",
        "",
        "The synthetic dataset takes its wall-clock base from the run, so timings",
        "move slightly between hosts and runs. The per-pair cost and the",
        "dropped-link counts are the stable figures.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sessions", type=int, nargs="+", default=[250, 400, 600, 800, 1000])
    parser.add_argument("--seed", type=int, default=99)
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument(
        "--cap",
        type=int,
        default=None,
        help="Override the engine session cap while measuring (default: engine value)",
    )
    parser.add_argument(
        "--edge-cap",
        type=int,
        default=None,
        help="Override the engine per-run edge cap while measuring (default: engine value)",
    )
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args()

    rows = []
    for target in args.sessions:
        row = measure(
            target, args.seed, args.repeat, cap=args.cap, edge_cap=args.edge_cap
        )
        rows.append(row)
        print(json.dumps(row, sort_keys=True))

    report = args.report or ROOT.parent / "docs" / "research" / "correlation-runtime.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(_markdown(rows), encoding="utf-8")
    print(f"wrote {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
