"""Obligation 04, happy-0: an agent-as-own-principal fetches a free resource.

Traces to the first happy-path bullet (verbatim):

> An agent operating as its own principal asks the platform for a public
> resource. The platform returns an offer at price zero whose access
> restrictions reflect the resource's licensing rules. The agent accepts
> the offer; the platform delivers a signed URL.

Driven against the demo ``socrates`` resource (FREE EUR, academic, EU) as the
EUR demo buyer operating as its own principal: every Exchange call is signed
with the agent's own Ed25519 key and carries NO ``Authorization`` bearer and
NO entitlement biscuit. The offer is FREE (price zero); accepting it yields a
signed URL whose fetch through the Cloudflare edge delivers content. The
``ramp.transaction_log`` row carries the agent's identity.
"""

from __future__ import annotations

import json
import uuid

import httpx
import psycopg
import pytest

from ramp_sdk.core import sign_offer_acceptance_jcs
from ramp_sdk import ProtocolVersion
from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import COMPOSE_FILE, StackURLs
from ..edge_fetch import fetch_signed
from ..httpsig_signer import load_keypair, sign_request
from ..resolve_carriers import first_item_of, retrieval_endpoint_of
from ..seed import (
    DEMO_PHILOSOPHY_DOMAIN,
    EUR_AGENT_ID,
    SeededFixture,
    _resolve_pg_dsn,
)
from ..signing import EUR_AGENT_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent operating as its own principal asks the platform for a "
    "public resource. The platform returns an offer at price zero whose "
    "access restrictions reflect the resource's licensing rules. The "
    "agent accepts the offer; the platform delivers a signed URL."
)

_LIST_OFFERS_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_ACCEPT_OFFER_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/socrates.txt"

_FORBIDDEN_DELEGATION_HEADERS = ("authorization", "x-ramp-entitlement-biscuit")


def _assert_no_delegation_credentials_on_wire(resp: httpx.Response) -> None:
    """Fail if the request that produced ``resp`` carried any populated delegation header."""
    sent = resp.request.headers
    for name in _FORBIDDEN_DELEGATION_HEADERS:
        value = sent.get(name, "")
        assert not value, (
            f"obligation 04 own-principal path expects no delegation/entitlement headers; "
            f"request to {resp.request.url} carried {name!r}={value!r}"
        )


def _post_signed_json(url: str, body: dict[str, object]) -> httpx.Response:
    """Sign a JSON POST with the agent's own well-known key and send it."""
    payload = json.dumps(body, separators=(",", ":")).encode()
    kid, priv = load_keypair(EUR_AGENT_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=payload, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    return httpx.post(url, content=payload, headers=headers, timeout=30.0)


def test_agent_as_own_principal_lists_accepts_and_fetches_free_resource(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Agent-as-own-principal lists, accepts, and fetches a zero-price demo resource."""
    list_resp = _post_signed_json(
        f"{compose_stack.exchange}{_LIST_OFFERS_PATH}",
        discover_body(
            agent_id=EUR_AGENT_ID,
            uris=[_RESOURCE_URI],
            exchange=recipient_of(compose_stack.exchange),
            domain=DEMO_PHILOSOPHY_DOMAIN,
            user_type="academic",
            geography="EU",
        ),
    )
    _assert_no_delegation_credentials_on_wire(list_resp)
    assert list_resp.status_code == httpx.codes.OK, (
        f"signed DiscoverResources should succeed, got {list_resp.status_code}: "
        f"{list_resp.text[:256]}"
    )
    offers = list_resp.json().get("offers") or []
    assert offers, f"expected at least one offer for the free URI, got {list_resp.json()}"

    per_request_offers = [o for o in offers if not (o.get("subscription_id"))]
    assert per_request_offers, f"free URI must surface a per-request offer, got {offers!r}"
    chosen = per_request_offers[0]
    # Price zero — assert on the canonical pricing.rate (the FREE term's rate is 0).
    # Money-as-string: pricing.rate rides as a decimal STRING on the wire
    # (discover.go FormatMoney: 0 → "0"); parse before comparing to zero.
    rate = (chosen.get("pricing") or {}).get("rate")
    assert rate is not None, f"free resource offer carries no pricing.rate: {chosen}"
    assert float(rate) == 0, f"free resource offer must carry price zero, got pricing.rate={rate!r}"
    offer_id = chosen.get("offer_id")
    offer_signature = chosen.get("signature")
    assert offer_id and offer_signature, f"offer missing id/signature: {chosen}"

    tx_request_id = f"tx-{uuid.uuid4().hex}"
    # Agent acceptance: agent_acceptance is REQUIRED at execute even on this agent-direct
    # path. Detached-sign it over the chosen offer's signature + requester +
    # idempotency_key with the agent's own well-known key.
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
    accept_resp = _post_signed_json(
        f"{compose_stack.exchange}{_ACCEPT_OFFER_PATH}",
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
                    "offer": chosen,
                    "agent_acceptance": {
                        "signature": acceptance_sig,
                        "signature_algorithm": acceptance_alg,
                    },
                }
            ],
        },
    )
    _assert_no_delegation_credentials_on_wire(accept_resp)
    assert accept_resp.status_code == httpx.codes.OK, (
        f"signed ExecuteTransaction should succeed for zero-price offer, got "
        f"{accept_resp.status_code}: {accept_resp.text[:256]}"
    )
    # C2: the EXECUTE response is an items[] envelope — read the per-result fields
    # from items[0], never the top level.
    accept_payload = accept_resp.json()
    item = first_item_of(accept_payload)
    assert item is not None, f"accept response carried no items[0]: {accept_payload}"
    transaction_id = item.get("transaction_id")
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, f"retrievalEndpoint missing from accept items[0]: {accept_payload}"
    assert transaction_id, f"transactionId missing from accept items[0]: {accept_payload}"

    # The demo domain resolves to its edge in-network; fetch the signed URL
    # directly (no Host override). The fetch carries no delegation header.
    # Fetch via the shared content-delivery seam: asserts 200 + the ACTUAL
    # delivered socrates article (deploy/content/demo/stoa-press/.../socrates.txt).
    # The fetch carries no delegation header — assert that on the response.
    content_resp = fetch_signed(
        signed_url,
        compose_stack,
        expect_marker="Socrates",
        timeout=30.0,
        key_path=EUR_AGENT_KEY_PATH,
    )
    _assert_no_delegation_credentials_on_wire(content_resp)

    # The usage record carries the agent's identity. BLACK-BOX e2e exception:
    # the transaction ledger has NO protocol read surface BY
    # DESIGN — record-read/reporting is downstream observability over the
    # operator's datastore, out of RAMP's protocol scope (no read RPC will be
    # added). A full-stack e2e observing the deployment's datastore directly is
    # NOT the pt9 layer-bypass that rule forbids (an in-process test reaching
    # past a production layer); it is the only way to assert this ledger side
    # effect (agent_id) end-to-end.
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT agent_id FROM ramp.transaction_log WHERE transaction_id = %s",
            (transaction_id,),
        )
        row = cur.fetchone()
    assert row is not None, f"no transaction_log row for {transaction_id}"
    assert row[0] == EUR_AGENT_ID, (
        f"transaction_log.agent_id must record the agent identity {EUR_AGENT_ID!r}; got {row[0]!r}"
    )
