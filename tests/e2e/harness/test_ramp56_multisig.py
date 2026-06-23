"""RAMP-56 multisig relay E2E tests.

Tests the two-phase flow where:
1. Discovery: Broker.Resolve → offers (no execution, no identity binding)
2. Execute: Agent creates TransactionRequest with offer_id, signs it,
   sends to Broker relay → Broker appends sig2 → Exchange verifies multisig

Per RAMP-56, the agent-originated ExecuteTransaction is the ONLY flow that
enables identity binding (delivery URL bound to agent's proven key). The old
broker-authored flow cannot satisfy multisig requirements and is deprecated.
"""

import httpx
import pytest

from .conftest import COMPOSE_FILE, StackURLs
from .edge_routing import host_url
from .relay import build_resolve_body, relay_execute, resolve
from .seed import SeededFixture, seed_stack
from .signing import build_pop_headers


@pytest.fixture(scope="session")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Seed the stack once per session."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


def test_happy_path_agent_originated_multisig_relay(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56 Scenario 1: Happy path - agent-originated execute, multisig relay, binding, edge enforce.

    Flow:
    1. Agent calls Broker.Resolve (discovery) → receives offers
    2. Agent picks offer, creates TransactionRequest with offer_id, signs it (sig1)
    3. Agent sends to Broker relay endpoint with X-RAMP-Exchange-Endpoint header
    4. Broker preserves agent sig1, appends broker sig2 (multisig)
    5. Exchange receives multisig, verifies both signatures, binds URL to agent
    6. Agent fetches signed URL from edge, edge verifies, delivers content
    """
    # Phase 1: Discovery - broker single-sig, no binding
    discovery_resp = resolve(
        compose_stack.broker, build_resolve_body(seeded.agent_id, uri=seeded.resource_uri)
    )
    assert discovery_resp.status_code == httpx.codes.OK, discovery_resp.text
    discovery_payload = discovery_resp.json()

    # Extract offers from discovery response (now in ext.ramp.broker.offers)
    ext = discovery_payload.get("ext", {})
    offers = ext.get("ramp.broker.offers", [])
    assert len(offers) > 0, f"no offers returned from discovery: {discovery_payload}"

    # Pick first offer
    offer = offers[0]
    offer_id = offer["offer_id"]
    offer_sig = offer.get("signature")
    exchange_endpoint = offer["exchange_endpoint"]  # Full Exchange endpoint URL

    # Phase 2: Execute - agent signs a TransactionRequest with the Exchange URL
    # (final destination) and POSTs to the Broker relay, which appends sig2.
    tx_resp = relay_execute(
        broker_url=compose_stack.broker,
        exchange_endpoint=exchange_endpoint,
        agent_id=seeded.agent_id,
        offer_id=offer_id,
        offer_signature=offer_sig,
    )
    assert tx_resp.status_code == httpx.codes.OK, tx_resp.text
    tx_payload = tx_resp.json()

    # Verify signed URL returned
    signed_url = tx_payload.get("retrievalEndpoint")
    assert signed_url, f"no signed URL in execute response: {tx_payload}"

    # Phase 3: Edge verification and content delivery
    # Replace localhost with compose_stack host for docker network routing
    signed_url_routed = host_url(signed_url, compose_stack)
    # Add proof-of-possession headers for identity binding verification (ADR-013)
    pop_headers = build_pop_headers(url=signed_url)
    content_resp = httpx.get(signed_url_routed, headers=pop_headers, timeout=15.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_broker_originated_discovery_still_works(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56 Scenario 7: Broker-originated discovery - verify discovery path works with single broker sig.

    Discovery phase (DiscoverResources) does NOT require agent signature because
    there's no identity binding happening. The broker can discover on behalf of
    the agent. Only ExecuteTransaction requires multisig.
    """
    # This is the current working flow - discovery via resolve endpoint
    discovery_resp = resolve(
        compose_stack.broker, build_resolve_body(seeded.agent_id, uri=seeded.resource_uri)
    )
    assert discovery_resp.status_code == httpx.codes.OK, discovery_resp.text

    # Verify we got a response (current implementation does full execute)
    payload = discovery_resp.json()
    assert payload is not None

    # Once migrated to two-phase, verify:
    # offers = payload.get("offers", [])
    # assert len(offers) > 0, "discovery should return offers"
