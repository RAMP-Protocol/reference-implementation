"""Full-stack E2E: MCP → Broker → Exchange → Edge → Publisher (demo catalog).

Proves the 3-way cryptographic chain works end-to-end against a real
dockerised stack, driven entirely against the demo-catalog resources the real
``ramp-ingest`` binary ingested (one signed PushResources RPC per feed) —
there is no ``push_catalog`` of demo content anywhere in this suite.

Each demo publisher domain resolves in-network to its edge runtime via a
docker-compose network alias on port 80:

* ``demo.ramp-protocol.org``        → Cloudflare (Miniflare) ed25519 edge
* ``music.demo.ramp-protocol.org``  → Fastly Compute (Viceroy) ed25519 edge
* ``sfx.demo.ramp-protocol.org``    → AWS CloudFront RSA edge shim

So the Exchange mints a signed URL on the demo domain and the agent fetches it
DIRECTLY — no Host override, no netloc rewrite. A real row in
ramp.transaction_log backs every successful resolve.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx

from .broker_client import execute_first_offer
from .conftest import StackURLs
from .edge_fetch import fetch_signed
from .resolve_carriers import first_item_of, licensed_of, retrieval_endpoint_of
from .seed import DemoResource, SeededFixture
from .signing import build_pop_headers


def _fetch(
    signed_url: str, *, timeout: float = 30.0, key_path: Path | None = None
) -> httpx.Response:
    """Fetch a broker-returned signed URL directly (demo domain resolves to its edge).

    When ``key_path`` is set AND the agent-bound URL carries ``agent_id=``, merge
    proof-of-possession headers (X-RAMP-Agent-Key + RFC 9421 GET signature over
    the agent's bound key). Those headers are load-bearing: the ed25519 edges
    enforce binding, so a bound URL fetched without them is refused 403
    ``missing_agent_key`` — which is what the two "refused without the key" tests
    below assert. RSA (aws) URLs carry no ``agent_id=`` and need no key; the
    tamper-negative fetches stay plain deliberately.
    """
    headers: dict[str, str] = {}
    if key_path is not None and "agent_id=" in signed_url:
        headers = build_pop_headers(url=signed_url, key_path=key_path)
    return httpx.get(signed_url, headers=headers, follow_redirects=True, timeout=timeout)


def _tamper_sig(signed_url: str, param: str = "sig") -> str:
    """Flip a base64url byte in the middle of the ``param`` query value."""
    m = re.search(rf"{param}=([^&]+)", signed_url)
    assert m, f"no {param}= in {signed_url}"
    val = m.group(1)
    mid = len(val) // 2
    replacement = "B" if val[mid] != "B" else "C"
    tampered = val[:mid] + replacement + val[mid + 1 :]
    return signed_url.replace(f"{param}={val}", f"{param}={tampered}")


def _delivered_url(resp: httpx.Response) -> str:
    """Return items[0].retrievalEndpoint of an EXECUTE TransactionResponse.

    The EXECUTE response is an items[] envelope, so the signed
    URL (and every per-result field) lives on items[0], never the top level.
    Fails closed if the envelope carries no items[0] or no retrievalEndpoint.
    """
    item = first_item_of(resp.json())
    assert item is not None, f"execute response carried no items[0]: {resp.text}"
    url = retrieval_endpoint_of(item)
    assert url, f"items[0] carried no retrievalEndpoint: {resp.text}"
    return url


def _deliver_demo(compose_stack: StackURLs, res: DemoResource) -> httpx.Response:
    """Two-phase deliver a DemoResource: Broker discover → relay-execute the winner.

    Two-phase relay: Broker Resolve is discovery-only, so the signed URL is
    minted on the relay EXECUTE (TransactionResponse), not on Resolve. The agent
    relay-executes the winning Offer (agent sig1 + Broker sig2 + offer-acceptance)
    through the Broker to the Exchange. intended_use ``ai-input`` is a real
    function every demo term permits (Exchange term-eligibility filter admits it);
    the per-call nonce inside resolve keeps the signature unique for the replay
    store. Buyer is the currency-matched demo buyer.
    """
    return execute_first_offer(
        compose_stack,
        {"agent_id": res.buyer_agent_id, "uri": res.uri, "intended_use": "ai-input"},
        agent_id=res.buyer_agent_id,
        domain=res.domain,
        key_path=res.buyer_key_path,
    )


def test_broker_resolve_returns_signed_url_and_writes_tx_log(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Relay-execute mints an Exchange-backed signed URL and persists a tx.

    Observed through the relay-execute (TransactionResponse) only (Testing
    Doctrine pt9): a populated transaction_id means the Exchange committed the
    transaction_log row before returning the signed URL (the write-before-sign
    invariant). R7: Resolve is discovery-only, so the URL + transaction_id are
    minted on the EXECUTE, not Resolve. Driven on the FREE demo resource
    (socrates) as the EUR buyer through the full two-phase relay chain.
    """
    res = seeded.free
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields (licensed/retrievalEndpoint/transactionId) from items[0].
    payload = resp.json()
    item = first_item_of(payload)
    assert item is not None, f"execute response carried no items[0]: {payload}"
    assert licensed_of(item) is True, f"expected licensed=true, got {payload}"
    assert item.get("retrieval_endpoint"), f"retrievalEndpoint missing from items[0]: {payload}"
    assert item.get("transaction_id"), f"transactionId missing from items[0]: {payload}"


def test_signed_url_fetches_origin_content_via_cloudflare_edge(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """The Exchange-signed URL on the demo domain verifies at the Cloudflare edge and delivers bytes."""
    res = seeded.cloudflare  # socrates, demo.ramp-protocol.org → Cloudflare
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    signed_url = _delivered_url(resp)
    content_resp = _fetch(signed_url, key_path=res.buyer_key_path)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    # socrates body is the real Stoa Press article content. Assert the ACTUAL
    # delivered article ("Socrates"), never a bare non-empty fallback — that
    # would pass on a 200 edge error-stub or a wrong-route body.
    assert "Socrates" in content_resp.text, content_resp.text


def _refusal_reason(resp: httpx.Response) -> str:
    """The edge's refusal token, or a description of why there wasn't one.

    ``resp.json()`` raises on a non-JSON body, and a 403 that arrives as HTML or
    empty is exactly the failure worth diagnosing — so the raw parse would blow up
    before the assertion could say what it saw. Returning a marker keeps the
    assertion's message the thing the reader gets.
    """
    if not resp.headers.get("content-type", "").startswith("application/json"):
        return f"<non-JSON body: {resp.text[:120]!r}>"
    try:
        payload = resp.json()
    except ValueError:
        return f"<unparseable JSON: {resp.text[:120]!r}>"
    if not isinstance(payload, dict):
        return f"<JSON is {type(payload).__name__}, not an object>"
    return str(payload.get("reason", "<no reason field>"))


def _assert_bound_url_refused_without_key(
    compose_stack: StackURLs, res: DemoResource, body_marker: str
) -> None:
    """Drive the leaked-bound-URL refusal for one edge runtime.

    Shared between the Cloudflare and Fastly cases: two runs are the point (the
    runtimes reach the check through different Ed25519 primitives), two copies of
    the assertions are not — they had already drifted in wording.
    """
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    signed_url = _delivered_url(resp)

    # The URL must be agent-bound, or there is nothing to enforce and the refusal
    # below would be proving something else.
    assert "agent_id=" in signed_url, f"delivery URL is not agent-bound: {signed_url}"

    # No proof of possession -> refused, and refused for the RIGHT reason.
    plain = _fetch(signed_url)
    assert plain.status_code == httpx.codes.FORBIDDEN, (
        f"a bound URL fetched with no proof of possession must be refused, "
        f"got {plain.status_code}: {plain.text[:256]}"
    )
    assert _refusal_reason(plain) == "missing_agent_key", _refusal_reason(plain)
    assert body_marker not in plain.text, f"the refusal leaked the body ({body_marker})"


def test_bound_url_is_refused_without_the_key_at_cloudflare_edge(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A leaked bound URL is worthless: the edge requires the key it names.

    This is the security property ADR-013 D3 buys, driven end-to-end against the
    Cloudflare (Ed25519) edge. The test above delivers the SAME resource
    successfully by presenting the buyer key, so the only variable here is the
    proof — which makes this a statement about the check rather than about the
    URL being malformed. URL integrity is a separate axis: see
    test_tampered_signature_is_rejected.
    """
    _assert_bound_url_refused_without_key(compose_stack, seeded.cloudflare, "Socrates")


def test_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating the ed25519 signature flips the Cloudflare edge verify to 403."""
    res = seeded.cloudflare
    resp = _deliver_demo(compose_stack, res)
    tampered = _tamper_sig(_delivered_url(resp))
    bad = _fetch(tampered)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_aws_path_resolve_returns_cloudfront_signed_url(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """The sfx demo tenant (AWS_CLOUDFRONT_RSA scheme) mints a canned-policy signed URL."""
    res = seeded.aws  # rain-on-tin-roof, sfx.demo.ramp-protocol.org → AWS
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    # C2: read licensed + the CloudFront signed URL from items[0].
    payload = resp.json()
    item = first_item_of(payload)
    assert item is not None, f"execute response carried no items[0]: {payload}"
    assert licensed_of(item) is True, payload
    signed = _delivered_url(resp)
    for name in ("Expires", "Signature", "Key-Pair-Id"):
        assert name in signed, f"{name} missing in {signed}"


def test_aws_signed_url_fetches_origin_via_cloudfront_shim(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """RSA canned policy verifies at the AWS shim, which proxies to the publisher origin."""
    res = seeded.aws
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    content_resp = _fetch(_delivered_url(resp))
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    # seeded.aws is rain-on-tin-roof (foleyworks sfx JSON). Assert the ACTUAL
    # delivered asset by its unique slug, not merely non-empty — a 200 edge
    # error-stub or wrong-route body must fail.
    assert "rain-on-tin-roof" in content_resp.text, content_resp.text


def test_aws_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating a byte inside the CloudFront Signature flips the AWS shim verifier to 403."""
    res = seeded.aws
    resp = _deliver_demo(compose_stack, res)
    tampered = _tamper_sig(_delivered_url(resp), param="Signature")
    bad = _fetch(tampered)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_fastly_signed_url_fetches_origin_via_viceroy(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Ed25519-signed URL on the music demo domain verifies on Fastly Compute (Viceroy)."""
    res = seeded.fastly  # paper-satellites, music.demo.ramp-protocol.org → Fastly
    resp = _deliver_demo(compose_stack, res)
    assert resp.status_code == httpx.codes.OK, resp.text
    # C2: licensed is derived from items[0].retrievalEndpoint presence.
    item = first_item_of(resp.json())
    assert item is not None, f"execute response carried no items[0]: {resp.text}"
    assert licensed_of(item) is True, resp.text
    content_resp = _fetch(_delivered_url(resp), key_path=res.buyer_key_path)
    assert content_resp.status_code == httpx.codes.OK, content_resp.text
    # seeded.fastly is paper-satellites (harmonia-records lyrics). Assert the
    # ACTUAL delivered lyric by its title, not merely non-empty.
    assert "Paper Satellites" in content_resp.text, content_resp.text


def test_bound_url_is_refused_without_the_key_at_fastly_edge(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """The Cloudflare property above, proved on the second enforcing runtime.

    Worth driving twice because the two edges reach the check by different paths:
    Cloudflare runs the SDK's WebCrypto verifier, while Fastly Compute cannot
    import Ed25519 through SubtleCrypto and substitutes its own primitive. A
    substitution that verified nothing would serve this fetch, and every positive
    Fastly test would still pass — the refusal is what tells the two apart.

    The test above delivers the SAME resource successfully by presenting the buyer
    key, so the only variable here is the proof.
    """
    _assert_bound_url_refused_without_key(compose_stack, seeded.fastly, "Paper Satellites")


def test_fastly_tampered_signature_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Mutating the sig param trips Fastly Compute's ed25519 verify."""
    res = seeded.fastly
    resp = _deliver_demo(compose_stack, res)
    tampered = _tamper_sig(_delivered_url(resp))
    bad = _fetch(tampered)
    assert bad.status_code == httpx.codes.FORBIDDEN, bad.text


def test_discover_execute_delivers_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """discover → execute → fetch delivers the real publisher payload end to end.

    The one test that walks the whole agent story on the demo catalog: resolve an
    offer, license it through the relay (x2f94 collapsed execute — a one-resource
    call is the degenerate n=1 batch), then fetch the signed URL the Exchange
    minted and confirm the bytes are the publisher's.

    It drives the Broker over HTTP as an agent does. It used to import the Python
    shim's tool functions in-process; the shim is gone, and the MCP surface itself
    is covered by its own suite (``test_mcp_endpoint.py`` (in-network runs only)) plus the Go integration
    tests. What is proven here is the RAMP path, not the MCP wrapper around it.
    """
    # paper-satellites is FLAT USD with no geo/user-type restriction, so it
    # resolves cleanly via the canonical DiscoveryRequest (which carries no facet
    # fields). It is fronted by the Fastly demo edge.
    res = seeded.fastly

    exec_resp = execute_first_offer(
        compose_stack,
        {
            "agent_id": res.buyer_agent_id,
            "uri": res.uri,
            "intended_use": "ai-input",
        },
        agent_id=res.buyer_agent_id,
        domain=res.domain,
        key_path=res.buyer_key_path,
    )
    assert exec_resp.status_code == httpx.codes.OK, exec_resp.text

    payload = exec_resp.json()
    item = first_item_of(payload)
    assert item is not None, f"relay response carried no items[0]: {payload}"
    assert licensed_of(item) is True, f"execute did not license the offer: {payload}"
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, f"execute licensed the offer but minted no URL: {payload}"

    # Assert the ACTUAL delivered lyric by its title, not merely a 200: an edge
    # error-stub or a wrong-route body would otherwise pass.
    fetch_signed(
        signed_url,
        compose_stack,
        expect_marker="Paper Satellites",
        key_path=res.buyer_key_path,
    )
