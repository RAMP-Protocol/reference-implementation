"""Shared fixtures for the docker-compose E2E harness.

Scope: a `compose_stack` session fixture that either (a) assumes the stack
is already up (``RAMP_E2E_REUSE_STACK=1``) or (b) runs
``docker compose -f docker-compose.e2e.yml up -d --build --wait`` before tests
and ``down -v`` after.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
import httpx
import pytest

from ._compose import resolve_host_port
from .lambda_edge import wait_ready as wait_lambda_ready

# Re-export: the existing tests import StackURLs from conftest; its home is
# stack_urls.py so non-pytest consumers (smoke_staging.py) can import it
# without touching a pytest-convention file.
from .stack_urls import StackURLs


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


def _resolve_stack_urls(compose_file: Path) -> StackURLs:
    """Resolve service URLs for the running stack.

    Inside the compose network (``RAMP_E2E_IN_NETWORK=1``) services
    reach each other by docker-DNS name. From the host we ask compose
    for the ephemeral host ports it assigned -- compose project name
    auto-derives from the cwd, so two stacks brought up from different
    cwds (main tree + worktree) report distinct port sets.
    """
    # The edges now listen on port 80 so the demo publisher-domain aliases
    # resolve natively for both the manifest fetch and the signed-URL content
    # fetch (Phase 2b). Service-DNS URLs target port 80; host runs discover the
    # ephemeral host port mapped to container port 80.
    if os.environ.get("RAMP_E2E_IN_NETWORK") == "1":
        return StackURLs(
            exchange="http://exchange:8081",
            exchange_b="http://exchange-b:8081",
            exchange_c="http://exchange-c:8081",
            broker="http://broker:8082",
            edge="http://edge:80",
            aws_edge="http://aws-edge:80",
            fastly_edge="http://fastly-edge:80",
            lambda_edge="http://lambda-edge:8080",
            lambda_edge_no_wba="http://lambda-edge-no-wba:8080",
            identity="http://identity",
            zitadel="http://zitadel:8080",
        )
    return StackURLs(
        exchange=f"http://127.0.0.1:{resolve_host_port(compose_file, 'exchange', 8081)}",
        exchange_b=f"http://127.0.0.1:{resolve_host_port(compose_file, 'exchange-b', 8081)}",
        exchange_c=f"http://127.0.0.1:{resolve_host_port(compose_file, 'exchange-c', 8081)}",
        broker=f"http://127.0.0.1:{resolve_host_port(compose_file, 'broker', 8082)}",
        edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'edge', 80)}",
        aws_edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'aws-edge', 80)}",
        fastly_edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'fastly-edge', 80)}",
        lambda_edge=f"http://127.0.0.1:{resolve_host_port(compose_file, 'lambda-edge', 8080)}",
        lambda_edge_no_wba=(
            f"http://127.0.0.1:{resolve_host_port(compose_file, 'lambda-edge-no-wba', 8080)}"
        ),
        identity="",
        zitadel="",
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
        except (httpx.HTTPError, OSError) as exc:
            last_err = str(exc)
        time.sleep(1.0)
    msg = f"{url} not healthy after {timeout_seconds}s (last: {last_err})"
    raise TimeoutError(msg)


@pytest.fixture(scope="session")
def seeded(compose_stack: StackURLs):
    """Seed the demo catalog once per session and expose its resources.

    Runs the production ``ramp-ingest`` binary over the three demo feeds
    (one signed PushResources RPC per feed) after registering the demo tenants,
    buyers, contributor, and broker exchange row. Shared session-wide so the
    ingest runs once; every suite consumes the same demo-catalog resources.
    """
    from .seed import SeededFixture, seed_stack

    fixture: SeededFixture = seed_stack(
        str(COMPOSE_FILE),
        compose_stack.exchange,
        exchange_b_host_url=compose_stack.exchange_b,
        exchange_c_host_url=compose_stack.exchange_c,
    )
    return fixture


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
        # Multi-exchange topology: exchange-b/c must be reachable too.
        _wait_healthy(f"{urls.exchange_b}/healthz")
        _wait_healthy(f"{urls.exchange_c}/healthz")
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
        # The Lambda runtime emulator serves no GET route at all — readiness is
        # an actual function invocation, so it needs its own poller.
        wait_lambda_ready(urls.lambda_edge)
        wait_lambda_ready(urls.lambda_edge_no_wba)
        yield urls
    finally:
        if not reuse and os.environ.get("RAMP_E2E_KEEP_UP") != "1":
            _compose("down", "-v")


# ---------------------------------------------------------------------------
# ADR-008 D5 — `shared-clean-fixtures` cleanup chain registration.
#
# The `stack_isolation` marker scaffolding — the marker registration,
# the collection check and the autouse dispatch fixture — is defined
# further down this same file. This block registers the exchange-health
# cleanup function onto the shared chain under the agreed contract:
# (function, autouse=False, ordering not required). The dispatch fixture
# reads the declared mode and runs the chain; tests do NOT call
# ``promote_drifted_exchange_health`` directly.
#
# Module-import-time append rather than a fresh re-bind, so further
# cleanup callables can be added to the same list without any of them
# having to know about the others. ``SHARED_CLEAN_FIXTURES`` is a plain
# list of zero-argument callables, consumed by the autouse dispatch
# fixture below; a test in any other isolation mode never runs it.
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
# against a known baseline, then exchange-health, then anything added
# later. Tests do NOT invoke these functions directly — the autouse
# dispatch fixture below reads the declared mode and runs the chain.
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


@pytest.fixture
def publish_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A source repo, a bare stand-in for the public remote, and a worktree path.

    Shared by the two publish guard suites. It sits here rather than in
    ``publish_harness`` so both can request it by name without re-exporting a
    fixture, which pytest reads as a redefinition.
    """
    # Imported inside the body on purpose: publish_harness reads REPO_ROOT from
    # this module, so importing it at the top would be circular.
    from .publish_harness import make_public_remote, make_source_repo

    source = tmp_path / "source"
    bare = tmp_path / "public.git"
    worktree = tmp_path / "worktree"
    make_source_repo(source)
    make_public_remote(bare, source)
    return source, bare, worktree
