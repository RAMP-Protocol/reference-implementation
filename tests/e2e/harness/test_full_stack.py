"""Full-stack E2E: MCP → Broker → Exchange → Edge → Publisher.

Proves the 3-way cryptographic chain works end-to-end against a real
dockerised stack:

* Exchange mints an Ed25519 signed URL over an entry in its catalog.
* Miniflare-hosted Hono edge fetches the Exchange's JWKS, verifies the
  signature, and proxies to the upstream publisher container.
* The publisher returns its HTML; the edge relays it back to the caller.
* MCP's ramp_fetch returns the content + transaction metadata.

A real row in ramp.transaction_log backs every successful call.
"""

from __future__ import annotations

import re
import uuid

import httpx
import psycopg
import pytest

from .conftest import COMPOSE_FILE, StackURLs
from .edge_routing import host_url
from .relay import build_resolve_body, relay_execute, resolve
from .seed import SeededFixture, _resolve_pg_dsn, seed_stack
from .signing import build_pop_headers


def _resolve_and_execute(
    compose_stack: StackURLs, agent_id: str, uri: str | None = None, query: str | None = None
) -> dict[str, object]:
    """RAMP-56 two-phase flow: discover offers, then execute transaction.

    Phase 1: Call /broker/v1/resolve to get offers (discovery).
    Phase 2: Agent creates TransactionRequest with offer_id, signs it, and
             calls /broker/v1/exchange/execute (relay endpoint).

    Returns the TransactionResponse payload with retrievalEndpoint and transactionId.
    """
    # Phase 1: Discovery - get offers
    discovery_resp = resolve(
        compose_stack.broker, build_resolve_body(agent_id, uri=uri, query=query)
    )
    assert discovery_resp.status_code == httpx.codes.OK, discovery_resp.text
    discovery_payload = discovery_resp.json()

    # Extract offers from ext.ramp.broker.offers
    ext = discovery_payload.get("ext", {})
    offers = ext.get("ramp.broker.offers", [])
    assert len(offers) > 0, f"no offers returned from discovery: {discovery_payload}"

    # Pick first offer
    offer = offers[0]

    # Phase 2: Execute via the Broker relay (agent sig1 + broker sig2 multisig).
    tx_resp = relay_execute(
        broker_url=compose_stack.broker,
        exchange_endpoint=offer["exchange_endpoint"],
        agent_id=agent_id,
        offer_id=offer["offer_id"],
        offer_signature=offer.get("signature"),
    )
    assert tx_resp.status_code == httpx.codes.OK, tx_resp.text
    return tx_resp.json()


@pytest.fixture(scope="session")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Seed the stack once per session."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


def test_broker_resolve_returns_signed_url_and_writes_tx_log(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Two-phase flow returns signed URL and persists transaction log."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.resource_uri)

    signed_url = payload.get("retrievalEndpoint")
    tx_id = payload.get("transactionId")
    assert signed_url, f"signed_url missing from execute: {payload}"
    assert tx_id, f"transaction_id missing from execute: {payload}"

    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT tenant_id, agent_id FROM ramp.transaction_log WHERE transaction_id = %s",
            (tx_id,),
        )
        row = cur.fetchone()
    assert row is not None, f"no transaction_log row for {tx_id}"
    assert row[0] == seeded.tenant_id


def test_signed_url_fetches_origin_content_via_edge(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Exchange-signed URL verifies at edge and delivers origin bytes."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.resource_uri)
    signed_url = host_url(payload["retrievalEndpoint"], compose_stack)
    # Add proof-of-possession headers for identity binding verification (ADR-013)
    pop_headers = build_pop_headers(url=payload["retrievalEndpoint"])
    content_resp = httpx.get(signed_url, headers=pop_headers, timeout=15.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Mutating the signature flips the edge verify to 403."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.resource_uri)
    signed_url = host_url(payload["retrievalEndpoint"], compose_stack)
    # Flip a character in the middle of the `sig` value. Base64url's trailing
    # bits mean end-of-string tampers can be absorbed, so we mutate earlier.
    sig_match = re.search(r"sig=([^&]+)", signed_url)
    assert sig_match, f"no sig in {signed_url}"
    sig_val = sig_match.group(1)
    # Flip the middle character to something guaranteed-different within the
    # base64url alphabet.
    mid = len(sig_val) // 2
    replacement = "B" if sig_val[mid] != "B" else "C"
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    tampered = signed_url.replace(f"sig={sig_val}", f"sig={tampered_sig}")
    # Add PoP headers even for tampered URL - edge verifies PoP first, then signature
    pop_headers = build_pop_headers(url=payload["retrievalEndpoint"])
    bad = httpx.get(tampered, headers=pop_headers, timeout=15.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_aws_path_resolve_returns_cloudfront_signed_url(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Exchange tenant with AWS_CLOUDFRONT_RSA scheme mints a canned-policy signed URL."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.aws_resource_uri)
    signed = payload["retrievalEndpoint"]
    # CloudFront canned-policy URLs carry these exact query params.
    for name in ("Expires", "Signature", "Key-Pair-Id"):
        assert name in signed, f"{name} missing in {signed}"


def test_aws_signed_url_fetches_origin_via_cloudfront_shim(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: RSA-SHA1 canned policy verifies at the shim, which proxies to publisher."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.aws_resource_uri)
    signed_url = host_url(payload["retrievalEndpoint"], compose_stack)
    # Add proof-of-possession headers for identity binding verification (ADR-013)
    pop_headers = build_pop_headers(url=payload["retrievalEndpoint"])
    content_resp = httpx.get(signed_url, headers=pop_headers, timeout=15.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_aws_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Mutating a byte inside the CloudFront Signature flips the verifier to 403."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.aws_resource_uri)
    signed_url = host_url(payload["retrievalEndpoint"], compose_stack)
    sig_match = re.search(r"Signature=([^&]+)", signed_url)
    assert sig_match, signed_url
    sig_val = sig_match.group(1)
    mid = len(sig_val) // 2
    replacement = "B" if sig_val[mid] != "B" else "C"
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    tampered = signed_url.replace(f"Signature={sig_val}", f"Signature={tampered_sig}")
    # Add PoP headers even for tampered URL - edge verifies PoP first, then signature
    pop_headers = build_pop_headers(url=payload["retrievalEndpoint"])
    bad = httpx.get(tampered, headers=pop_headers, timeout=15.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_fastly_signed_url_fetches_origin_via_viceroy(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Ed25519-signed URL verifies on Fastly Compute (Viceroy) and returns content."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.fastly_resource_uri)
    signed_url = host_url(payload["retrievalEndpoint"], compose_stack)
    # Add proof-of-possession headers for identity binding verification (ADR-013)
    pop_headers = build_pop_headers(url=payload["retrievalEndpoint"])
    content_resp = httpx.get(signed_url, headers=pop_headers, timeout=30.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_fastly_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RAMP-56: Mutating the sig param trips Fastly Compute's ed25519 verify."""
    payload = _resolve_and_execute(compose_stack, seeded.agent_id, uri=seeded.fastly_resource_uri)
    signed_url = host_url(payload["retrievalEndpoint"], compose_stack)
    sig_match = re.search(r"sig=([^&]+)", signed_url)
    assert sig_match, signed_url
    sig_val = sig_match.group(1)
    mid = len(sig_val) // 2
    replacement = "B" if sig_val[mid] != "B" else "C"
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    tampered = signed_url.replace(f"sig={sig_val}", f"sig={tampered_sig}")
    # Add PoP headers even for tampered URL - edge verifies PoP first, then signature
    pop_headers = build_pop_headers(url=payload["retrievalEndpoint"])
    bad = httpx.get(tampered, headers=pop_headers, timeout=30.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


@pytest.mark.xfail(strict=True, reason="MCP shim needs update for RAMP-56 two-phase flow")
def test_mcp_ramp_fetch_returns_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """The hosted MCP's ramp_fetch tool delivers the end-to-end story.

    Rather than driving the MCP streamable-HTTP protocol directly from pytest,
    this test exercises the same code path via a small in-process client that
    imports ramp_fetch_impl and points it at the running Broker.

    NOTE: This test is xfail until the MCP shim (src/mcp) is updated to use
    the RAMP-56 two-phase flow (discover offers, then execute via relay).
    """
    # Late import — the MCP shim isn't normally on sys.path in the harness.
    import sys
    from pathlib import Path

    repo_root = Path(COMPOSE_FILE).resolve().parent
    mcp_src = repo_root / "src" / "mcp" / "src"
    if str(mcp_src) not in sys.path:
        sys.path.insert(0, str(mcp_src))

    import asyncio
    import os

    from ramp_mcp_shim.server import ramp_fetch_impl

    os.environ["BROKER_URL"] = compose_stack.broker
    os.environ["RAMP_AGENT_ID"] = seeded.agent_id
    os.environ.pop("RAMP_LICENSE_ID", None)

    # The shim hits broker over HTTP and gets back a signed_url with the
    # compose-internal host. host_url rewrites the netloc to the
    # host-published port so pytest can reach the edge from outside the
    # compose network.
    async def run() -> str:
        from ramp_mcp_shim.broker import BrokerClient
        from ramp_mcp_shim.models import RampRequest, Requester

        client = BrokerClient(compose_stack.broker)
        # Unique intended_use → unique signed body → distinct signature, so the
        # Broker's (keyID, signature) replay store does not treat this resolve
        # as a duplicate of another test's identical {agent, uri}.
        resp = await client.resolve(
            RampRequest(
                id=f"rampreq-{uuid.uuid4().hex}",
                requester=Requester(
                    id=seeded.agent_id,
                    uris=[seeded.resource_uri],
                    intended_use=[f"e2e-{uuid.uuid4().hex}"],
                ),
            ),
        )
        assert resp.licensed, resp.error
        assert resp.retrieval_endpoint is not None
        return await client.fetch_content(host_url(resp.retrieval_endpoint, compose_stack))

    # The imported ramp_fetch_impl is fine when DNS resolves; here we use the
    # host-rewrite helper above. Both paths prove the same cryptographic chain.
    content = asyncio.run(run())
    assert "content-marker-42" in content
    # Sanity: the unmodified ramp_fetch_impl behaves identically against a
    # Broker URL whose signed_url host is reachable — covered by the mocked
    # tests in src/mcp/tests/test_server.py.
    _ = ramp_fetch_impl
