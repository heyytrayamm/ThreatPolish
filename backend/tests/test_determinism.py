"""The seeded benchmark must describe the same dataset on every run.

The report names a seed, so two runs of that seed have to produce the same
telemetry.  The generator used to anchor on ``datetime.now()``, which moved the
hour-of-day features between runs: published counts drifted by a pair or two
depending on when the benchmark was executed.  Anchoring the evaluation dataset
to a fixed instant is what makes the seed mean something.
"""

from __future__ import annotations

from datetime import datetime

from app.evaluation import scenarios
from app.evaluation.runner import BENCHMARK_START, benchmark_dataset


class _WallClockForbidden(datetime):
    """A ``datetime`` whose ``now`` fails, so any clock read is visible."""

    @classmethod
    def now(cls, tz=None):  # pragma: no cover - only reached on regression
        raise AssertionError("benchmark dataset generation read the wall clock")


def test_benchmark_dataset_ignores_the_wall_clock(monkeypatch):
    expected = benchmark_dataset(seed=7)
    monkeypatch.setattr(scenarios, "datetime", _WallClockForbidden)
    regenerated = benchmark_dataset(seed=7)
    assert regenerated == expected


def test_benchmark_dataset_is_stable_across_seeds():
    first = benchmark_dataset(seed=7)
    second = benchmark_dataset(seed=7)
    different = benchmark_dataset(seed=2026)
    assert first["sessions"] == second["sessions"]
    assert first["truth"] == second["truth"]
    assert first["sessions"] != different["sessions"]


def test_benchmark_anchor_is_fixed():
    """The anchor is a constant, not "six hours before whenever this ran"."""
    assert BENCHMARK_START.tzinfo is not None
    dataset = benchmark_dataset(seed=7)
    last = max(
        event["occurred_at"] for session in dataset["sessions"] for event in session["events"]
    )
    assert datetime.fromisoformat(last) <= BENCHMARK_START
