"""The image and the Compose file must agree on the port they use.

A platform that assigns `PORT` starts the container on that port.  If Compose
keeps publishing and probing 8000, the deployment is reported unhealthy while it
is serving, which is what happened before the container read `PORT`.  These
checks fail if the three places drift apart again.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "Dockerfile"
COMPOSE_FILE = ROOT / "docker-compose.yml"


def _instructions(text: str) -> list[str]:
    """Dockerfile lines with continuations joined, so a wrapped CMD reads whole."""
    joined = text.replace("\\\n", " ")
    return [line.strip() for line in joined.splitlines() if line.strip()]


def _compose_config(port: str | None) -> dict[str, Any]:
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    env = {
        **os.environ,
        # Compose refuses to resolve the file while this is unset.
        "TP_DB_PASSWORD": "deployment-test-password",
    }
    env.pop("PORT", None)
    if port is not None:
        env["PORT"] = port
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--format", "json"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        pytest.skip(f"docker compose config is unavailable: {result.stderr.strip()[:300]}")
    return json.loads(result.stdout)


def test_image_binds_and_probes_the_port_it_is_given():
    instructions = _instructions(DOCKERFILE.read_text(encoding="utf-8"))
    command = next(line for line in instructions if line.startswith("CMD"))
    assert "${PORT:-8000}" in command, command
    healthcheck = next(line for line in instructions if line.startswith("HEALTHCHECK"))
    # The probe has to read the same variable the command binds.
    assert "os.getenv('PORT'" in healthcheck, healthcheck


@pytest.mark.parametrize("port", [None, "9099"])
def test_compose_publishes_and_probes_the_port_it_hands_to_the_app(port: str | None):
    app = _compose_config(port)["services"]["app"]
    expected = port or "8000"
    assert app["environment"]["PORT"] == expected
    assert [entry["published"] for entry in app["ports"]] == [expected]
    assert "os.getenv('PORT'" in app["healthcheck"]["test"][1]
