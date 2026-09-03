"""Reaching the identity service's MCP endpoint as a real agent.

Two suites drive that endpoint — the discover/execute flow and the account
tools — and everything they need to get a session is the same: the endpoint is
in-network only, the container carries no healthcheck, and the bearer has to be
minted with the credentials the compose file gave the service. Kept here because
the duplication budget is zero, and because a second copy of the credential
reading is the copy that goes stale.

THE ORDER IS PART OF IT. Skip first, then wait for identity to answer, then mint:
a test that minted before the service was up would fail as an unexplained
connection error rather than as a wait that timed out. The three are not called
one by one in a test body — conftest wraps them as the ``identity_ready``,
``mcp_agent`` and ``mcp_bearer`` fixtures, so the sequence is stated once instead
of being a contract seven test bodies each had to get right.

WHAT REPEATS AND WHAT DOES NOT. Readiness and sign-up are session-scoped; only
the bearer is minted per test, because only its ten-minute TTL forces that.
"""

from __future__ import annotations

import os

import pytest

from .identity_signup import mint_bearer, provision_agent
from .readiness import wait_healthy
from .stack_urls import StackURLs


def required_env(name: str) -> str:
    """Read ``name`` or fail naming what is supposed to set it.

    Read without a fallback on purpose: a default here would be a second copy of
    a credential, and the failure mode of a stale copy is an unexplained 401
    rather than anything that names the mismatch. Absent env means the stack was
    not brought up as the compose file defines it, which is worth failing on.

    Called inside a test, never at import: a module-level failure would be a
    COLLECTION error, and ``make test-e2e-collect`` enumerates these suites
    deliberately without a stack.
    """
    value = os.environ.get(name)
    if not value:
        pytest.fail(
            f"{name} is not set. docker-compose.e2e.yml sets it on the runner via the "
            f"x-identity-auth anchor, shared with the identity service; run this test "
            f"through `make test-e2e` (or `docker compose --profile test run --rm "
            f"runner`), not a bare pytest."
        )
    return value


def require_in_network(compose_stack: StackURLs) -> None:
    """The MCP endpoint is in-network only: identity publishes no host port."""
    if os.environ.get("RAMP_E2E_IN_NETWORK") != "1" or not compose_stack.identity:
        pytest.skip("identity MCP endpoint is reachable only in-network (RAMP_E2E_IN_NETWORK=1)")


def await_identity(compose_stack: StackURLs) -> None:
    """Wait for identity to answer /healthz (distroless carries no healthcheck).

    Uses the harness's one readiness poller rather than another copy: that one
    also treats a refused connection (OSError) as "not up yet", which is exactly
    the condition here while the container is starting, and it reports the last
    error it saw instead of discarding every diagnostic across the whole wait.
    """
    wait_healthy(f"{compose_stack.identity}/healthz", timeout_seconds=60.0)


def mcp_session_agent(compose_stack: StackURLs) -> str:
    """Provision a real agent through Zitadel sign-up and return its subdomain.

    This is the expensive half and it runs ONCE per session. Sign-up is a dynamic
    client registration, /authorize, the Zitadel login form through two POSTs, a
    redirect chain, /callback and a consent-screen scrape — and it is idempotent
    for the agent, which is why the account-tools suite can treat its
    registrations as accumulating. What is NOT idempotent is the OAuth client the
    flow mints and persists: running this per test left one client row per test
    where one would do.
    """
    return provision_agent(compose_stack.identity, compose_stack.zitadel)


def mcp_session_bearer(subdomain: str) -> str:
    """Mint a bearer for an already-provisioned agent.

    This is the half that has to repeat: the bearer's TTL is ten minutes, so a
    session-scoped one would expire under a long run. It makes no network call —
    it signs a token with the seed the compose file gave the service — so
    repeating it costs nothing.

    The issuer and seed are read from the shared compose env, never defaulted
    here: a default would let a suite pass against a service configured
    differently from the one deployed.
    """
    issuer = required_env("IDENTITY_AUTH_ISSUER")
    seed_b64 = required_env("IDENTITY_TOKEN_SIGNING_KEY")
    return mint_bearer(subdomain, issuer=issuer, audience=issuer, seed_b64=seed_b64)
