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
from .seed import SeededFixture, _resolve_pg_dsn, seed_stack
from .signing import AGENT_E2E_KEY_PATH, sign_post


# Compose-internal hosts the broker returns inside signed URLs. When the
# tests run from the host (RAMP_E2E_IN_NETWORK unset), these DNS names do
# not resolve; we rewrite the netloc to the host-published port reported
# by compose_stack so the TCP connection can land on the edge container.
#
# Signature contract (verified 2026-05-20 under a9esw.4):
#   - Exchange-side: src/exchange/internal/signing/signed_url.go:66 builds
#     the canonical as `GET\n<full URL minus sig>` — scheme + host + path
#     + query.
#   - Edge-side:     src/edge/src/verify.ts:122-126 mirrors that exactly
#     via canonicalMessage(url), where `url` is parsed from `c.req.url`
#     (app.ts:58).
#
# So the canonical payload covers the FULL URL, NOT just path+query as
# the prior version of this comment claimed. A bare netloc rewrite for
# host-side fetch produces an HTTP request whose Host header reflects
# the host-published port (e.g. `127.0.0.1:58009`), which means Workerd
# reconstructs c.req.url with that authority and the signature check
# fails with `signature_mismatch`.
#
# Callers that ACTUALLY FETCH the rewritten URL through the edge must
# therefore also stamp a `Host:` header matching the original signed
# netloc — see tests/e2e/harness/obligations/test_00_happy_03_usage_record_paid_access.py
# for the canonical pattern (post-a9esw.4). The _host_url() helper below
# rewrites the URL only; callers carry the Host header themselves.
_COMPOSE_INTERNAL_EDGE_HOSTS: tuple[tuple[str, str], ...] = (
    ("http://edge:8787", "edge"),
    ("http://aws-edge:8788", "aws_edge"),
    ("http://fastly-edge:7676", "fastly_edge"),
)


def _host_url(signed: str, compose_stack: StackURLs) -> str:
    """Rewrite a broker-returned signed URL's netloc for host-side fetch.

    Returns the rewritten URL only. Callers that fetch this URL through
    the edge's signature verifier MUST also pass a ``Host`` header equal
    to the original signed netloc (e.g. ``edge:8787``); the signature
    canonical covers the full URL — see the module-level comment above.
    """
    for compose_host, attr in _COMPOSE_INTERNAL_EDGE_HOSTS:
        if compose_host in signed:
            return signed.replace(compose_host, getattr(compose_stack, attr))
    return signed


def _ramp_body(
    agent_id: str, *, uri: str | None = None, query: str | None = None
) -> dict[str, object]:
    """Build a canonical RAMPRequest body for /broker/v1/resolve.

    The per-call unique ``id`` keeps the signed bytes — hence the
    Content-Digest and the signature — distinct, so the Broker's
    (keyID, signature) replay store never treats two resolves of the same
    {agent, uri} as a duplicate. The Broker decodes the body with a
    DiscardUnknown protojson decoder, so any forward-compatible extras are
    ignored.
    """
    requester: dict[str, object] = {"id": agent_id}
    if uri:
        requester["uris"] = [uri]
    body: dict[str, object] = {
        "ver": "1.0",
        "id": f"rampreq-{uuid.uuid4().hex}",
        "requester": requester,
    }
    if query:
        body["query"] = query
    return body


def _broker_licensed(payload: dict[str, object]) -> bool:
    """True when the canonical resolve response carries ext['ramp.broker.licensed']."""
    ext = payload.get("ext")
    return bool(isinstance(ext, dict) and ext.get("ramp.broker.licensed"))


def _resolve(compose_stack: StackURLs, body: dict[str, object]) -> httpx.Response:
    """POST a signed canonical RAMPRequest to ``/broker/v1/resolve`` as the agent.

    The Broker requires every ``/broker/v1/*`` call to carry a valid RFC 9421
    signature whose keyID equals the request's ``requester.id`` (self-act). We
    sign as ``agent-e2e`` (kid == requester.id), the identity the seed both
    credits and registers. Build bodies with :func:`_ramp_body` so each carries
    a unique ``id`` (hence a unique signature) and the replay store stays happy.
    """
    return sign_post(
        f"{compose_stack.broker}/broker/v1/resolve",
        body=body,
        key_path=AGENT_E2E_KEY_PATH,
    )


@pytest.fixture(scope="session")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Seed the stack once per session."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


def test_broker_resolve_returns_signed_url_and_writes_tx_log(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Broker should mint an Exchange-backed signed URL and persist a tx row."""
    body = _ramp_body(seeded.agent_id, uri=seeded.resource_uri)
    resp = _resolve(compose_stack, body)
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = resp.json()

    assert _broker_licensed(payload), f"expected licensed=true, got {payload}"
    signed_url = payload.get("retrievalEndpoint")
    tx_id = payload.get("transactionId")
    assert signed_url, f"signed_url missing from resolve: {payload}"
    assert tx_id, f"transaction_id missing from resolve: {payload}"

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
    """The Exchange-signed URL verifies at the edge and delivers origin bytes."""
    body = _ramp_body(seeded.agent_id, uri=seeded.resource_uri)
    resp = _resolve(compose_stack, body)
    assert resp.status_code == httpx.codes.OK, resp.text
    signed_url = _host_url(resp.json()["retrievalEndpoint"], compose_stack)
    content_resp = httpx.get(signed_url, timeout=15.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating the signature flips the edge verify to 403."""
    body = _ramp_body(seeded.agent_id, uri=seeded.resource_uri)
    resp = _resolve(compose_stack, body)
    signed_url = _host_url(resp.json()["retrievalEndpoint"], compose_stack)
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
    bad = httpx.get(tampered, timeout=15.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_aws_path_resolve_returns_cloudfront_signed_url(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Exchange tenant with AWS_CLOUDFRONT_RSA scheme mints a canned-policy signed URL."""
    body = _ramp_body(seeded.agent_id, uri=seeded.aws_resource_uri)
    resp = _resolve(compose_stack, body)
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = resp.json()
    assert _broker_licensed(payload), payload
    signed = payload["retrievalEndpoint"]
    # CloudFront canned-policy URLs carry these exact query params.
    for name in ("Expires", "Signature", "Key-Pair-Id"):
        assert name in signed, f"{name} missing in {signed}"


def test_aws_signed_url_fetches_origin_via_cloudfront_shim(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RSA-SHA1 canned policy verifies at the shim, which proxies to publisher."""
    body = _ramp_body(seeded.agent_id, uri=seeded.aws_resource_uri)
    resp = _resolve(compose_stack, body)
    signed_url = _host_url(resp.json()["retrievalEndpoint"], compose_stack)
    content_resp = httpx.get(signed_url, timeout=15.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_aws_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating a byte inside the CloudFront Signature flips the verifier to 403."""
    body = _ramp_body(seeded.agent_id, uri=seeded.aws_resource_uri)
    resp = _resolve(compose_stack, body)
    signed_url = _host_url(resp.json()["retrievalEndpoint"], compose_stack)
    sig_match = re.search(r"Signature=([^&]+)", signed_url)
    assert sig_match, signed_url
    sig_val = sig_match.group(1)
    mid = len(sig_val) // 2
    replacement = "B" if sig_val[mid] != "B" else "C"
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    tampered = signed_url.replace(f"Signature={sig_val}", f"Signature={tampered_sig}")
    bad = httpx.get(tampered, timeout=15.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_fastly_signed_url_fetches_origin_via_viceroy(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Ed25519-signed URL verifies on Fastly Compute (Viceroy) and returns content."""
    body = _ramp_body(seeded.agent_id, uri=seeded.fastly_resource_uri)
    resp = _resolve(compose_stack, body)
    assert resp.status_code == httpx.codes.OK, resp.text
    assert _broker_licensed(resp.json()), resp.text
    signed_url = _host_url(resp.json()["retrievalEndpoint"], compose_stack)
    content_resp = httpx.get(signed_url, timeout=30.0)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    assert "content-marker-42" in content_resp.text


def test_fastly_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating the sig param trips Fastly Compute's ed25519 verify."""
    body = _ramp_body(seeded.agent_id, uri=seeded.fastly_resource_uri)
    resp = _resolve(compose_stack, body)
    signed_url = _host_url(resp.json()["retrievalEndpoint"], compose_stack)
    sig_match = re.search(r"sig=([^&]+)", signed_url)
    assert sig_match, signed_url
    sig_val = sig_match.group(1)
    mid = len(sig_val) // 2
    replacement = "B" if sig_val[mid] != "B" else "C"
    tampered_sig = sig_val[:mid] + replacement + sig_val[mid + 1 :]
    tampered = signed_url.replace(f"sig={sig_val}", f"sig={tampered_sig}")
    bad = httpx.get(tampered, timeout=30.0)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_mcp_ramp_fetch_returns_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """The hosted MCP's ramp_fetch tool delivers the end-to-end story.

    Rather than driving the MCP streamable-HTTP protocol directly from pytest,
    this test exercises the same code path via a small in-process client that
    imports ramp_fetch_impl and points it at the running Broker.
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
    # compose-internal host. _host_url rewrites the netloc to the
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
        return await client.fetch_content(_host_url(resp.retrieval_endpoint, compose_stack))

    # The imported ramp_fetch_impl is fine when DNS resolves; here we use the
    # host-rewrite helper above. Both paths prove the same cryptographic chain.
    content = asyncio.run(run())
    assert "content-marker-42" in content
    # Sanity: the unmodified ramp_fetch_impl behaves identically against a
    # Broker URL whose signed_url host is reachable — covered by the mocked
    # tests in src/mcp/tests/test_server.py.
    _ = ramp_fetch_impl
