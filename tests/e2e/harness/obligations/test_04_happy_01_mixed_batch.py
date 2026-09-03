"""Obligation 04 mixed-batch: free happy-path plus unknown-URI failure.

Grounds in the obligation's batch-with-mixed-verdicts contract: an agent asks
for a batch of URIs, some known and some not; the platform returns offers only
for the known ones and explains the unknown ones.

V1 reading: the structural failure mode the catalog produces for an unknown
URI is ``OFFER_ABSENCE_REASON_NOT_IN_CATALOG``. Driven against two known demo
philosophy resources (socrates + heraclitus, both FREE EUR) and one
never-seeded demo URI, as the EUR demo buyer (academic, EU) signing with its
own well-known key (no delegation/biscuit headers).
"""

from __future__ import annotations

import json
import uuid
from typing import Any, cast

import httpx
import pytest

from ramp_sdk.core import sign_offer_acceptance_jcs
from ramp_sdk import ProtocolVersion
from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import StackURLs
from ..edge_fetch import fetch_signed
from ..httpsig_signer import load_keypair, sign_request
from ..resolve_carriers import first_item_of, retrieval_endpoint_of
from ..seed import DEMO_PHILOSOPHY_DOMAIN, EUR_AGENT_ID, SeededFixture
from ..signing import EUR_AGENT_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_NOT_IN_CATALOG = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"
_EXCHANGE_METHOD = "DISCOVERY_METHOD_EXCHANGE"

# socrates: FREE EUR academic/EU. heraclitus: FREE EUR (no user-type), EU.
_KNOWN_URI_A = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/socrates.txt"
_KNOWN_URI_B = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/heraclitus.txt"


def _post_signed_json(url: str, body: dict[str, object]) -> httpx.Response:
    payload = json.dumps(body, separators=(",", ":")).encode()
    kid, priv = load_keypair(EUR_AGENT_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=payload, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    return httpx.post(url, content=payload, headers=headers, timeout=30.0)


def _group_for(groups: list[dict[str, Any]], uri: str) -> dict[str, Any] | None:
    for g in groups:
        if g.get("uri") == uri:
            return g
    return None


def _absence_reason(group: dict[str, Any]) -> str | None:
    v = group.get("absence_reason")
    return v if isinstance(v, str) else None


def test_mixed_batch_groups_known_offers_and_not_in_catalog_reason(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Batch DiscoverResources returns per-URI offer groups for known + unseeded demo URIs."""
    unseeded_uri = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/never-seeded-{uuid.uuid4().hex}.txt"
    discover_url = f"{compose_stack.exchange}{_DISCOVER_PATH}"
    body: dict[str, object] = discover_body(
        agent_id=EUR_AGENT_ID,
        uris=[_KNOWN_URI_A, _KNOWN_URI_B, unseeded_uri],
        exchange=recipient_of(discover_url),
        domain=DEMO_PHILOSOPHY_DOMAIN,
        user_type="academic",
        geography="EU",
    )
    resp = _post_signed_json(discover_url, body)
    assert resp.status_code == httpx.codes.OK, (
        f"signed batch DiscoverResources should succeed, got {resp.status_code}: {resp.text[:256]}"
    )
    payload = cast(dict[str, Any], resp.json())
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    assert groups, f"expected offerGroups in response, got {payload}"

    # Every group says how its URI was found, the two hits and the miss alike.
    # This request goes straight to the Exchange, which answers only out of its
    # own catalog, so the answer is EXCHANGE on all three.
    for reported in groups:
        assert reported.get("discovery_method") == _EXCHANGE_METHOD, (
            f"group {reported.get('uri')!r} must report {_EXCHANGE_METHOD!r}; got {reported}"
        )

    # Both known URI groups carry offers.
    for uri in (_KNOWN_URI_A, _KNOWN_URI_B):
        group = _group_for(groups, uri)
        assert group is not None, f"no OfferGroup for known URI {uri!r} in {groups}"
        assert group.get("offers"), (
            f"known URI {uri!r} must surface at least one offer, got {group}"
        )

    # Unseeded URI group is empty and reports NOT_IN_CATALOG.
    unseeded_group = _group_for(groups, unseeded_uri)
    assert unseeded_group is not None, f"no OfferGroup for unseeded URI {unseeded_uri!r}"
    assert (unseeded_group.get("offers") or []) == [], (
        f"unseeded URI must have empty offers, got {unseeded_group}"
    )
    assert _absence_reason(unseeded_group) == _NOT_IN_CATALOG, (
        f"unseeded URI group must report {_NOT_IN_CATALOG!r}; got {unseeded_group}"
    )

    # Agent proceeds with one known URI: accept + fetch content.
    pub_group_a = cast(dict[str, Any], _group_for(groups, _KNOWN_URI_A))
    pub_offer = cast(list[dict[str, Any]], pub_group_a.get("offers") or [])[0]
    offer_id = pub_offer.get("offer_id")
    offer_signature = pub_offer.get("signature")
    assert offer_id and offer_signature, f"known offer A missing id/signature: {pub_offer}"
    accept_url = f"{compose_stack.exchange}/ramp.v1.ExchangeService/ExecuteTransaction"
    tx_request_id = f"tx-{uuid.uuid4().hex[:8]}"
    # Agent acceptance: agent_acceptance is REQUIRED at execute. Detached-sign it over
    # the chosen offer's signature + requester + idempotency_key with the agent's
    # own well-known key.
    _, acc_priv = load_keypair(EUR_AGENT_KEY_PATH)
    acceptance_sig, acceptance_alg = sign_offer_acceptance_jcs(
        seed=acc_priv.private_bytes_raw(),
        offer_sig=str(offer_signature),
        requester_id=EUR_AGENT_ID,
        requester_domain=DEMO_PHILOSOPHY_DOMAIN,
        idempotency_key=tx_request_id,
    )
    # A single offer rides the items[] envelope (NO top-level
    # offer/agentAcceptance/offerId) — the 1-element-batch wire shape. The per-item
    # acceptance signs over the chosen offer.signature + requester + idempotency_key
    # (unchanged). Each item reflects the FULL signed offer; the Exchange
    # verifies offer.signature over the presented bytes.
    tx_resp = _post_signed_json(
        accept_url,
        {
            "ver": ProtocolVersion,
            "idempotency_key": tx_request_id,
            "requester": {
                "id": EUR_AGENT_ID,
                "domain": DEMO_PHILOSOPHY_DOMAIN,
                "type": "REQUESTER_TYPE_AGENT",
            },
            "items": [
                {
                    "offer": pub_offer,
                    "agent_acceptance": {
                        "signature": acceptance_sig,
                        "signature_algorithm": acceptance_alg,
                    },
                }
            ],
        },
    )
    assert tx_resp.status_code == httpx.codes.OK, (
        f"signed ExecuteTransaction on known URI should succeed, got "
        f"{tx_resp.status_code}: {tx_resp.text[:256]}"
    )
    # C2: read the signed URL from items[0], never the top level.
    tx_payload = cast(dict[str, Any], tx_resp.json())
    item = first_item_of(tx_payload)
    assert item is not None, f"tx response carried no items[0]: {tx_payload}"
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, f"signed URL missing from tx items[0]: {tx_payload}"

    # The agent proceeded with _KNOWN_URI_A (socrates). Fetch via the shared
    # content-delivery seam: asserts 200 + the ACTUAL delivered socrates article
    # (deploy/content/demo/stoa-press/.../socrates.txt).
    # The accept-minted URL is bound to the executing agent — fetch with PoP:
    # ``key_path`` makes fetch_signed mint X-RAMP-Agent-Key + an RFC 9421 GET
    # signature when the URL carries ``agent_id=`` (ADR-013).
    fetch_signed(
        signed_url,
        compose_stack,
        expect_marker="Socrates",
        timeout=30.0,
        key_path=EUR_AGENT_KEY_PATH,
    )
