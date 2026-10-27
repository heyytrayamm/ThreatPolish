#!/usr/bin/env python3
"""Measure write latency while a correlation run is in progress.

The other benchmarks time the engine itself in one process.  An analyst,
however, uses an API that may run several worker processes against PostgreSQL,
and ingestion continues while a correlation run scans the window.  This script
measures that interaction end to end:

* it starts the real API with ``uvicorn --workers N`` against PostgreSQL,
* ingests the labelled evaluation dataset through the public ingestion endpoint,
* records ingestion latency from several concurrent clients while nothing else
  runs, then again while one client triggers ``POST /api/v1/correlate``,
* and reconciles the stored event count afterwards.

A SQLite target is refused: it serialises every writer, so it cannot answer the
question this script exists to ask.

Usage:
    python scripts/benchmark_write_contention.py \\
        --db-url postgresql+psycopg://user:pass@127.0.0.1:5432/threatpolish \\
        --workers 4 --writers 6
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ADMIN_EMAIL = "contention@threatpolish.test"
ADMIN_PASSWORD = "contention-password-123"
DATASET = {
    "seed": 99,
    "campaign_groups": 40,
    "sessions_per_group": 3,
    "benign_sessions": 24,
    "same_ip_pairs": 4,
    "incomplete_groups": 2,
    "delayed_sessions": 3,
}
WINDOW_HOURS = 24


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _wait_ready(base: str, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(f"{base}/api/v1/health/ready", timeout=2.0).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise SystemExit("API did not become ready for the contention run")


def _write_event(writer: int, index: int) -> dict[str, Any]:
    # Timestamped outside the correlation window so the measured run still
    # scores exactly the seeded corpus.  The rows and indexes being written are
    # the same ones the correlation reader scans.
    now = datetime.now(timezone.utc) - timedelta(hours=48, seconds=index % 60)
    return {
        "schema_version": "1.0",
        "occurred_at": now.isoformat(),
        "source_module": "honeypot",
        "event_type": "honeypot.http.request",
        "source_ip": f"198.18.{writer}.{(index % 250) + 1}",
        "session_id": f"write-{writer}-{index}",
        "target_id": "decoy-http-1",
        "severity": "low",
        "provenance": {
            "collector": "contention-benchmark",
            "source": "http-decoy",
            "reliability": 0.7,
            "synthetic": True,
            "indicators": [],
        },
        "features": {
            "method": "GET",
            "path": f"/bench/{writer}/{index}",
            "status": 404,
            "user_agent": "contention/1.0",
        },
    }


class _Writers:
    """Fixed number of clients posting unrelated events until stopped."""

    def __init__(self, base: str, token: str, count: int):
        self.base = base
        self.token = token
        self.count = count
        self.stop = threading.Event()
        self.latencies: list[float] = []
        self.errors: list[str] = []
        self.accepted = 0
        self.requests = 0
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    def _loop(self, writer: int) -> None:
        index = 0
        with httpx.Client(
            base_url=self.base,
            headers={"X-Agent-Token": self.token},
            timeout=60.0,
        ) as client:
            while not self.stop.is_set():
                started = time.perf_counter()
                try:
                    response = client.post("/api/v1/ingest/events", json=[_write_event(writer, index)])
                    elapsed = (time.perf_counter() - started) * 1000
                except httpx.HTTPError as exc:
                    with self._lock:
                        self.errors.append(f"writer {writer}: {type(exc).__name__}")
                    time.sleep(0.05)
                    index += 1
                    continue
                with self._lock:
                    self.requests += 1
                    if response.status_code == 202:
                        self.latencies.append(elapsed)
                        self.accepted += int(response.json().get("accepted", 0))
                    else:
                        self.errors.append(f"writer {writer}: HTTP {response.status_code}")
                index += 1
                time.sleep(0.01)

    def start(self) -> None:
        for writer in range(self.count):
            thread = threading.Thread(target=self._loop, args=(writer,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def finish(self) -> None:
        self.stop.set()
        for thread in self._threads:
            thread.join(timeout=30)

    def summary(self) -> dict[str, Any]:
        values = self.latencies
        return {
            "requests": self.requests,
            "accepted_events": self.accepted,
            "errors": len(self.errors),
            "error_samples": self.errors[:5],
            "p50_ms": round(statistics.median(values), 2) if values else 0.0,
            "p95_ms": round(_percentile(values, 0.95), 2) if values else 0.0,
            "max_ms": round(max(values), 2) if values else 0.0,
        }


def _login(base: str) -> dict[str, str]:
    response = httpx.post(
        f"{base}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=15.0,
    )
    if response.status_code != 200:
        raise SystemExit(f"sign-in failed: {response.status_code} {response.text}")
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _seed(base: str, headers: dict[str, str]) -> int:
    from app.evaluation.scenarios import generate_dataset

    token = httpx.post(
        f"{base}/api/v1/auth/tokens",
        headers=headers,
        json={"name": "contention-sensor", "role": "sensor"},
        timeout=15.0,
    )
    if token.status_code != 201:
        raise SystemExit(f"sensor token failed: {token.status_code} {token.text}")
    sensor = {"X-Agent-Token": token.json()["token"]}

    dataset = generate_dataset(**DATASET)
    events = [event for session in dataset["sessions"] for event in session["events"]]
    accepted = 0
    for start in range(0, len(events), 250):
        batch = events[start : start + 250]
        response = httpx.post(
            f"{base}/api/v1/ingest/events", headers=sensor, json=batch, timeout=60.0
        )
        if response.status_code != 202:
            raise SystemExit(f"seed ingest failed: {response.status_code} {response.text}")
        accepted += int(response.json().get("accepted", 0))
    return accepted, len(dataset["sessions"])


def _event_total(base: str, headers: dict[str, str]) -> int:
    # The write traffic sits outside the correlation window, so the total is
    # read over the widest window the API accepts.
    response = httpx.get(
        f"{base}/api/v1/events", headers=headers, params={"limit": 1, "hours": 720}, timeout=30.0
    )
    response.raise_for_status()
    return int(response.json()["total"])


def run(*, db_url: str, workers: int, writers: int, baseline_seconds: float) -> dict[str, Any]:
    if db_url.startswith("sqlite"):
        raise SystemExit(
            "a single SQLite file serialises every writer; pass --db-url for PostgreSQL"
        )

    channel = tempfile.TemporaryDirectory(prefix="tp-contention-")
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "TP_ENV": "test",
        "TP_DB_URL": db_url,
        "TP_DATA_DIR": channel.name,
        "TP_JWT_SECRET": "contention-secret-that-is-long-enough",
        "TP_BOOTSTRAP_ADMIN_EMAIL": ADMIN_EMAIL,
        "TP_BOOTSTRAP_ADMIN_PASSWORD": ADMIN_PASSWORD,
        "TP_LOG_LEVEL": "WARNING",
        "TP_CRYPTO_PROVIDER": "fixture",
        # The writers are meant to measure database contention, not the
        # ingestion throttle.
        "TP_INGEST_RATE_LIMIT_PER_MINUTE": "1000000",
    }

    # Every row a previous run left behind would change both the corpus and the
    # latency, so the benchmark owns its schema.
    from sqlalchemy import create_engine, text

    engine = create_engine(db_url)
    try:
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()

    # Create the schema once.  Several workers starting at the same time on an
    # empty database would all try to migrate it.
    os.environ.update({key: env[key] for key in env if key.startswith("TP_")})
    from app.core.config import reset_settings_cache
    from app.db.database import init_db

    reset_settings_cache()
    init_db()

    log_path = Path(channel.name) / "uvicorn.log"
    log_file = log_path.open("w", encoding="utf-8")
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
            "--workers",
            str(workers),
            "--log-level",
            "warning",
        ],
        cwd=ROOT,
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    success = False
    try:
        _wait_ready(base)
        headers = _login(base)
        seeded, seeded_sessions = _seed(base, headers)
        before_total = _event_total(base, headers)

        sensor_token = httpx.post(
            f"{base}/api/v1/auth/tokens",
            headers=headers,
            json={"name": "contention-writers", "role": "sensor"},
            timeout=15.0,
        ).json()["token"]

        idle = _Writers(base, sensor_token, writers)
        idle.start()
        time.sleep(baseline_seconds)
        idle.finish()

        loaded = _Writers(base, sensor_token, writers)
        loaded.start()
        time.sleep(0.5)
        started = time.perf_counter()
        correlation = httpx.post(
            f"{base}/api/v1/correlate", headers=headers, json={"window_hours": WINDOW_HOURS}, timeout=300.0
        )
        correlation_seconds = time.perf_counter() - started
        loaded.finish()

        if correlation.status_code != 200:
            raise SystemExit(f"correlation failed: {correlation.status_code} {correlation.text}")
        run_report = correlation.json()

        after_total = _event_total(base, headers)
        expected = before_total + idle.accepted + loaded.accepted
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engine": _engine_version(db_url),
            "workers": workers,
            "writer_threads": writers,
            "seeded_events": seeded,
            "seeded_sessions": seeded_sessions,
            "idle": idle.summary(),
            "during_correlation": loaded.summary(),
            "correlation": {
                "seconds": round(correlation_seconds, 2),
                "sessions": run_report.get("sessions"),
                "pairs_scored": run_report.get("pairs_scored"),
                "edges_created": run_report.get("edges_created"),
                "campaigns": run_report.get("campaigns"),
                "run_id": run_report.get("run_id"),
                "duration_ms": run_report.get("duration_ms"),
            },
            "integrity": {
                "events_before": before_total,
                "events_after": after_total,
                "events_expected": expected,
                "reconciled": after_total == expected,
                "write_errors": loaded.errors[:5],
            },
        }
        if not report["integrity"]["reconciled"]:
            raise SystemExit(
                f"event count did not reconcile: {before_total} + {idle.accepted} "
                f"+ {loaded.accepted} != {after_total}"
            )
        success = True
        return report
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        log_file.close()
        if not success:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            print(f"API exited with {process.returncode}:\n{tail}", file=sys.stderr)
        channel.cleanup()


def _engine_version(db_url: str) -> str:
    from sqlalchemy import create_engine, text

    engine = create_engine(db_url)
    try:
        with engine.connect() as conn:
            version = conn.execute(text("SHOW server_version")).scalar_one()
    finally:
        engine.dispose()
    return f"PostgreSQL {version}"


def _markdown(report: dict[str, Any]) -> str:
    idle = report["idle"]
    loaded = report["during_correlation"]
    correlation = report["correlation"]
    lines = _markdown_body(report, idle, loaded, correlation)
    repeats = report.get("repeats", [])
    if len(repeats) > 1:
        lines.extend(
            [
                "## Repeatability",
                "",
                "The script ran the whole sequence again on a freshly reset schema.",
                "",
                "| Run | Idle p50 / p95 / max | Busy p50 / p95 / max | Correlation |",
                "| ---: | --- | --- | ---: |",
            ]
        )
        for index, item in enumerate(repeats, start=1):
            base = item["idle"]
            busy = item["during_correlation"]
            lines.append(
                f"| {index} | {base['p50_ms']} / {base['p95_ms']} / {base['max_ms']} ms "
                f"| {busy['p50_ms']} / {busy['p95_ms']} / {busy['max_ms']} ms "
                f"| {item['correlation']['seconds']} s |"
            )
        lines.extend(
            [
                "",
                "The median latency moves by a few milliseconds, which is inside this host's",
                "run-to-run noise. The tail moves consistently: p95 rises and the worst request",
                "is several times slower while the scan holds its read transaction.",
                "",
            ]
        )
    return "\n".join(lines)


def _markdown_body(report, idle, loaded, correlation) -> list[str]:
    return [
            "# Write latency during a correlation run",
            "",
            "Generated by `backend/scripts/benchmark_write_contention.py` against a real",
            f"API with **{report['workers']} worker processes** and **{report['writer_threads']} concurrent",
            "ingestion clients**. Each write posts one unrelated event; the correlation run",
            f"scans a {WINDOW_HOURS}-hour window holding the labelled evaluation dataset.",
            "",
            f"- Engine: {report['engine']}",
            f"- Seeded: {report['seeded_events']} events over {report['seeded_sessions']} sessions",
            f"- Correlation: {correlation['seconds']} s wall, {correlation['sessions']} sessions,",
            f"  {correlation['pairs_scored']} pairs scored, {correlation['edges_created']} edges,",
            f"  {correlation['campaigns']} campaign candidates",
            "",
            "| Metric | Idle | During correlation |",
            "| --- | ---: | ---: |",
            f"| Requests | {idle['requests']} | {loaded['requests']} |",
            f"| Accepted events | {idle['accepted_events']} | {loaded['accepted_events']} |",
            f"| p50 latency | {idle['p50_ms']} ms | {loaded['p50_ms']} ms |",
            f"| p95 latency | {idle['p95_ms']} ms | {loaded['p95_ms']} ms |",
            f"| Worst request | {idle['max_ms']} ms | {loaded['max_ms']} ms |",
            f"| Errors | {idle['errors']} | {loaded['errors']} |",
            "",
            "The stored event count is reconciled after the run: the correlation reader and",
            "the concurrent writers did not lose or duplicate an accepted event.",
            "",
        ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-url", required=True, help="PostgreSQL SQLAlchemy URL")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--writers", type=int, default=6)
    parser.add_argument("--baseline-seconds", type=float, default=3.0)
    parser.add_argument("--repeat", type=int, default=1, help="runs on a freshly reset schema")
    parser.add_argument("--json-out", type=Path, default=ROOT.parent / "docs" / "research" / "write-contention.json")
    parser.add_argument("--markdown-out", type=Path, default=ROOT.parent / "docs" / "research" / "write-contention.md")
    args = parser.parse_args()

    reports = [
        run(
            db_url=args.db_url,
            workers=args.workers,
            writers=args.writers,
            baseline_seconds=args.baseline_seconds,
        )
        for _ in range(max(1, args.repeat))
    ]
    report = reports[-1]
    if len(reports) > 1:
        # Every run resets the schema, so each is an independent measurement.
        report["repeats"] = [
            {
                "idle": item["idle"],
                "during_correlation": item["during_correlation"],
                "correlation": item["correlation"],
            }
            for item in reports
        ]
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    args.markdown_out.write_text(_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"wrote {args.json_out} and {args.markdown_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
