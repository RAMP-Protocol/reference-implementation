"""Shared fixtures for the docker-compose E2E harness.

Scope: a `compose_stack` session fixture that either (a) assumes the stack
is already up (``RAMP_E2E_REUSE_STACK=1``) or (b) runs
``docker compose -f docker-compose.e2e.yml up -d --build --wait`` before tests
and ``down -v`` after.
"""

from __future__ import annotations

import os
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

import httpx
import pytest

def _resolve_compose_file() -> Path:
    """Locate docker-compose.e2e.yml.

    Inside the runner container we bind-mount it at RAMP_E2E_COMPOSE_FILE.
    From the repo root (host run) it lives three dirs up from this file.
    """
    env_path = os.environ.get("RAMP_E2E_COMPOSE_FILE")
    if env_path:
        return Path(env_path)
    return Path(__file__).resolve().parents[3] / "docker-compose.e2e.yml"


COMPOSE_FILE = _resolve_compose_file()
REPO_ROOT = COMPOSE_FILE.parent


class StackURLs(NamedTuple):
    """Host-side URLs for each compose service."""

    exchange: str
    broker: str
    edge: str
    aws_edge: str
    fastly_edge: str
    mcp: str


def _default_urls() -> StackURLs:
    """Resolve the service URLs based on whether we run inside compose or on the host."""
    if os.environ.get("RAMP_E2E_IN_NETWORK") == "1":
        return StackURLs(
            exchange="http://exchange:8081",
            broker="http://broker:8082",
            edge="http://edge:8787",
            aws_edge="http://aws-edge:8788",
            fastly_edge="http://fastly-edge:7676",
            mcp="http://mcp:8000",
        )
    return StackURLs(
        exchange="http://127.0.0.1:18081",
        broker="http://127.0.0.1:18082",
        edge="http://127.0.0.1:18787",
        aws_edge="http://127.0.0.1:18788",
        fastly_edge="http://127.0.0.1:17676",
        mcp="http://127.0.0.1:18000",
    )


STACK_URLS = _default_urls()


def _compose(*args: str) -> None:
    cmd = ["docker", "compose", "-f", str(COMPOSE_FILE), *args]
    subprocess.run(cmd, check=True, cwd=REPO_ROOT)


def _wait_healthy(url: str, timeout_seconds: float = 90.0) -> None:
    """Poll ``url`` until it returns 2xx or timeout."""
    deadline = time.monotonic() + timeout_seconds
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=2.0)
            if 200 <= resp.status_code < 300:
                return
            last_err = f"{resp.status_code} {resp.text[:128]}"
        except (httpx.HTTPError, OSError, socket.timeout) as exc:
            last_err = str(exc)
        time.sleep(1.0)
    msg = f"{url} not healthy after {timeout_seconds}s (last: {last_err})"
    raise TimeoutError(msg)


@pytest.fixture(scope="session")
def compose_stack() -> Iterator[StackURLs]:
    """Bring the docker-compose stack up for the whole test session."""
    if os.environ.get("RAMP_E2E_SKIP") == "1":
        pytest.skip("RAMP_E2E_SKIP=1")

    reuse = os.environ.get("RAMP_E2E_REUSE_STACK") == "1"
    if not reuse:
        _compose("up", "-d", "--build")
    try:
        _wait_healthy(f"{STACK_URLS.exchange}/healthz")
        _wait_healthy(f"{STACK_URLS.broker}/healthz")
        _wait_healthy(f"{STACK_URLS.edge}/healthz")
        _wait_healthy(f"{STACK_URLS.aws_edge}/healthz")
        _wait_healthy(f"{STACK_URLS.fastly_edge}/healthz")
        yield STACK_URLS
    finally:
        if not reuse and os.environ.get("RAMP_E2E_KEEP_UP") != "1":
            _compose("down", "-v")
