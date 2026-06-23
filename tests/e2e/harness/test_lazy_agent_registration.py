"""Lazy agent registration (ADR-009 D2) through the real Agent -> Broker -> Exchange chain.

A fresh agent — absent from RAMP_KEYS_FILE and ramp.agents, serving only its own
ROLE_AGENT /.well-known/ramp.json on the ``lazy-agent-e2e`` network alias (== its
keyID/domain) — discovers and relays an ExecuteTransaction. Both the Broker
(resolve gate + relay sig1) and the Exchange resolve its transport key from that
manifest; the Exchange then lazily persists the ramp.agents row.

This is the only test that exercises the lazy-registration SUCCESS path through
the genuine relay chain: seed.py pre-registers every other signing agent, so the
existing suite never fires the well-known fetch on the relay path.
"""

from pathlib import Path

import httpx
import psycopg
import pytest

from .conftest import COMPOSE_FILE, StackURLs
from .relay import build_resolve_body, relay_execute, resolve
from .seed import SeededFixture, _resolve_pg_dsn, seed_stack

_FIXTURES = Path(__file__).resolve().parent / "fixtures"

# Fresh agent: published manifest on the `lazy-agent-e2e` alias, billing-seeded
# in docker-compose.e2e.yml, but NOT in keys.json and NOT seeded into ramp.agents.
LAZY_AGENT_ID = "lazy-agent-e2e"
LAZY_KEY_PATH = _FIXTURES / "agent_lazy_e2e_key.json"

# Ghost agent: a valid signing key but NO well-known host, so its key can be
# resolved nowhere — the negative control for the per-agent resolver.
GHOST_AGENT_ID = "ghost-agent-e2e"
GHOST_KEY_PATH = _FIXTURES / "agent_ghost_e2e_key.json"


@pytest.fixture(scope="session")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Seed the stack once per session (catalog, tenant, billing-credited agent-e2e)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


def _agent_row_exists(agent_id: str) -> bool:
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM ramp.agents WHERE agent_id = %s", (agent_id,))
        return cur.fetchone() is not None


def test_lazy_registration_through_real_relay(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Happy path: a never-seen agent is admitted via its well-known and registered."""
    assert not _agent_row_exists(LAZY_AGENT_ID), (
        "precondition violated: lazy-agent-e2e is already in ramp.agents"
    )

    # Phase 1 — discovery, signed by the fresh agent. The Broker's resolve gate
    # resolves its key from http://lazy-agent-e2e/.well-known/ramp.json (it is
    # absent from the bootstrap keys file).
    discovery = resolve(
        compose_stack.broker,
        build_resolve_body(LAZY_AGENT_ID, uri=seeded.resource_uri),
        key_path=LAZY_KEY_PATH,
    )
    assert discovery.status_code == httpx.codes.OK, discovery.text
    offers = discovery.json().get("ext", {}).get("ramp.broker.offers", [])
    assert offers, f"no offers returned from discovery: {discovery.text}"
    offer = offers[0]

    # Phase 2 — relay execute. The Broker verifies sig1 via the same well-known
    # fetch and appends sig2; the Exchange verifies both, lazily registers the
    # agent (ramp.agents), and binds the delivery URL to its proven key.
    tx = relay_execute(
        broker_url=compose_stack.broker,
        exchange_endpoint=offer["exchange_endpoint"],
        agent_id=LAZY_AGENT_ID,
        offer_id=offer["offer_id"],
        offer_signature=offer.get("signature"),
        key_path=LAZY_KEY_PATH,
    )
    assert tx.status_code == httpx.codes.OK, tx.text
    assert tx.json().get("retrievalEndpoint"), f"no signed URL: {tx.text}"

    # The side effect that proves lazy registration fired on the real relay path.
    assert _agent_row_exists(LAZY_AGENT_ID), (
        "agent was not lazily registered after a successful relayed execute"
    )


def test_unpublished_agent_refused_at_broker(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Negative control: a fresh agent with NO well-known host is refused at discovery."""
    resp = resolve(
        compose_stack.broker,
        build_resolve_body(GHOST_AGENT_ID, uri=seeded.resource_uri),
        key_path=GHOST_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.UNAUTHORIZED, resp.text
    assert not _agent_row_exists(GHOST_AGENT_ID), "ghost agent must not be registered"
