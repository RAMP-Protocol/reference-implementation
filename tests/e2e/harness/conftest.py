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

from ._compose import resolve_host_port


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


def _resolve_stack_urls(compose_file: Path) -> StackURLs:
    """Resolve service URLs for the running stack.

    Inside the compose network (``RAMP_E2E_IN_NETWORK=1``) services
    reach each other by docker-DNS name. From the host we ask compose
    for the ephemeral host ports it assigned -- compose project name
    auto-derives from the cwd, so two stacks brought up from different
    cwds (main tree + worktree) report distinct port sets.
    """
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
        exchange=f"http://127.0.0.1:{resolve_host_port(compose_file, 'exchange', 8081)}",
        broker=f"http://127.0.0.1:{resolve_host_port(compose_file, 'broker', 8082)}",
        edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'edge', 8787)}",
        aws_edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'aws-edge', 8788)}",
        fastly_edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'fastly-edge', 7676)}",
        mcp=f"http://127.0.0.1:{resolve_host_port(compose_file, 'mcp', 8000)}",
    )


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
        urls = _resolve_stack_urls(COMPOSE_FILE)
        _wait_healthy(f"{urls.exchange}/healthz")
        _wait_healthy(f"{urls.broker}/healthz")
        _wait_healthy(f"{urls.edge}/healthz")
        _wait_healthy(f"{urls.aws_edge}/healthz")
        # Fastly Compute (Viceroy) has no /healthz; its readiness probe is the
        # well-known manifest. Docker reports the container healthy once its
        # internal 127.0.0.1 probe passes, but Viceroy may not yet be bound on
        # the bridge interface — so PushResources-driven manifest fetches from
        # the Exchange to fastly-edge race connection-refused for the first few
        # seconds on a cold stack. Wait on the bridge-reachable URL too.
        _wait_healthy(f"{urls.fastly_edge}/.well-known/ramp.json")
        yield urls
    finally:
        if not reuse and os.environ.get("RAMP_E2E_KEEP_UP") != "1":
            _compose("down", "-v")


# ---------------------------------------------------------------------------
# ADR-008 D5 — `shared-clean-fixtures` cleanup chain registration.
#
# The peer executor (f6mq) owns the `stack_isolation` marker scaffolding
# itself. This block registers the exchange-health cleanup function
# onto the shared chain with the contract the team-lead pinned:
# (function, autouse=False, ordering not required). The framework's
# per-test hook reads the declared mode and dispatches the chain;
# tests do NOT call ``promote_drifted_exchange_health`` directly.
#
# Module-import-time append rather than a fresh re-bind so the peer
# can land their own cleanup callables in the same list without
# resolving a conftest.py overlap. ``SHARED_CLEAN_FIXTURES`` is a
# tuple-of-callables list. It is consumed by the per-test hook the
# stack_isolation marker installs; if that hook hasn't merged yet the
# list is harmless (no test exercises it).
# ---------------------------------------------------------------------------
from collections.abc import Callable  # noqa: E402

from .fixtures.exchange_health import promote_drifted_exchange_health  # noqa: E402
from .fixtures.obligations import purge_reporting_obligations  # noqa: E402


def _resolve_pg_dsn_for_cleanup() -> str:
    """Resolve the same Postgres DSN the seed module uses, deferred.

    Imported lazily so the cleanup chain doesn't drag the entire seed
    surface (and its docker-compose `port` shell-out) into module
    import time, which would slow every collection.
    """
    from .seed import _resolve_pg_dsn

    return _resolve_pg_dsn(str(COMPOSE_FILE))


def cleanup_obligations() -> int:
    """Cleanup-chain entry for `ramp.reporting_obligations` (ADR-008 D5).

    First entry in the chain because every later gate (signed-URL,
    billing, exchange-health) reads from a baseline this purge
    guarantees.
    """
    dsn = _resolve_pg_dsn_for_cleanup()
    return purge_reporting_obligations(dsn)


def cleanup_exchange_health() -> int:
    """Cleanup-chain entry for exchange.healthy drift (ADR-008 D5)."""
    dsn = _resolve_pg_dsn_for_cleanup()
    return promote_drifted_exchange_health(dsn)


# Chain order is load-bearing: obligations FIRST so subsequent gates run
# against a known baseline, then exchange-health, then anything peers
# add later. Tests do NOT invoke these functions directly — the per-test
# hook below reads the declared mode and dispatches the chain.
SHARED_CLEAN_FIXTURES: list[Callable[[], object]] = [
    cleanup_obligations,
    cleanup_exchange_health,
]


# ---------------------------------------------------------------------------
# ADR-008 D5 — `stack_isolation` marker contract.
#
# Every test under tests/e2e/harness/obligations/ MUST declare a
# `stack_isolation` marker with one of three modes:
#
#   * "isolated"                — the orchestration tears down and rebuilds
#                                 shared infra between this test and the
#                                 next. Reserved for tests that mutate
#                                 persistent state irrecoverably.
#   * "shared-clean-fixtures"   — DEFAULT for the bulk of the suite. The
#                                 `SHARED_CLEAN_FIXTURES` chain runs before
#                                 each such test (obligations purge → market-
#                                 place-health re-promote → …).
#   * "shared-without-cleanup"  — no setup/teardown. Reserved for tests
#                                 that observe stable cross-test invariants
#                                 (service-health probes, version sentinels)
#                                 and are genuinely indifferent to state.
#
# The `--strict-markers` flag in tests/e2e/pyproject.toml makes any
# unknown marker fail the collection. The `pytest_collection_modifyitems`
# hook below additionally requires that every test in the obligations
# tree DECLARE a mode — silence is not a default, it is a collection
# error.
# ---------------------------------------------------------------------------

_STACK_ISOLATION_MODES = frozenset(
    {"isolated", "shared-clean-fixtures", "shared-without-cleanup"},
)
_OBLIGATIONS_DIR_PART = "obligations"


def pytest_configure(config: pytest.Config) -> None:
    """Register the `stack_isolation` marker so --strict-markers accepts it."""
    config.addinivalue_line(
        "markers",
        "stack_isolation(mode): declare per-test isolation contract — one of "
        "'isolated', 'shared-clean-fixtures', 'shared-without-cleanup' (ADR-008 D5)",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,  # noqa: ARG001 — required hook signature
    items: list[pytest.Item],
) -> None:
    """Fail collection when an obligation test omits `stack_isolation`.

    Per ADR-008 D5: every test in the obligations tree MUST declare its
    isolation contract. The default ("shared-clean-fixtures") still
    applies once declared, but silence is treated as a forgotten obligation
    and collection refuses it.
    """
    errors: list[str] = []
    for item in items:
        path = str(getattr(item, "path", "") or item.fspath)
        if f"/{_OBLIGATIONS_DIR_PART}/" not in path and not path.endswith(
            f"/{_OBLIGATIONS_DIR_PART}"
        ):
            continue
        marker = item.get_closest_marker("stack_isolation")
        if marker is None:
            errors.append(
                f"{item.nodeid}: missing @pytest.mark.stack_isolation(...) "
                "(ADR-008 D5 — required for tests under tests/e2e/harness/obligations/)"
            )
            continue
        if not marker.args or marker.args[0] not in _STACK_ISOLATION_MODES:
            valid = ", ".join(sorted(_STACK_ISOLATION_MODES))
            errors.append(
                f"{item.nodeid}: stack_isolation mode "
                f"{marker.args[0] if marker.args else '<missing>'!r} not in {{{valid}}}"
            )
    if errors:
        msg = "ADR-008 D5 stack_isolation contract violations:\n  - " + "\n  - ".join(errors)
        raise pytest.UsageError(msg)


@pytest.fixture(autouse=True)
def _stack_isolation_dispatch(request: pytest.FixtureRequest) -> Iterator[None]:
    """Per-test hook that reads the declared mode and runs the right chain.

    `shared-clean-fixtures` (default for declared tests) runs every callable
    in `SHARED_CLEAN_FIXTURES` before the test — obligations FIRST,
    exchange-health second, etc. `isolated` and `shared-without-cleanup`
    are no-ops at the per-test boundary; `isolated` relies on the
    orchestration layer to rebuild the stack between tests.

    Tests outside the obligations tree without the marker fall through
    silently — the marker is mandatory only inside the obligations tree
    (enforced by the collection hook above).
    """
    marker = request.node.get_closest_marker("stack_isolation")
    mode = marker.args[0] if marker is not None and marker.args else "shared-clean-fixtures"
    if mode == "shared-clean-fixtures":
        for cleanup in SHARED_CLEAN_FIXTURES:
            cleanup()
    yield
