"""Obligation 00 — failure 05: buyer has no billing arrangement.

Verbatim scenario (second failure-mode bullet):

> The buyer has no billing arrangement. The agent cannot accept any
> offer; the platform says so plainly.

Driven against the demo ``epicurus`` resource (PER_UNIT USD) under the
credit-less ``agent-nobilling-e2e`` identity (registered + keyed but absent
from ``EXCHANGE_BILLING_SEED``).

Semantic relocation, NOT a weakening: on the items[] batch
path the Exchange classifies a no-billing buyer as a PER-ITEM denial rather
than aborting the envelope (``KindBillingDenied`` → ``denialReasonByKind``,
denial.go), so the refusal now surfaces in-body at HTTP 200 with
``items[0].denialReason == DENIAL_REASON_INSUFFICIENT_BALANCE`` and no
``items[0].retrievalEndpoint`` — instead of a non-200 Connect error. The
platform still "says so plainly"; the rejection moved from the transport layer
to the per-item layer. The four observables (relocated, still rejecting):

1. response is HTTP 200 — the items[] batch path classifies the refusal in-body
   (no envelope abort, since the request is well-formed).
2. ``items[0].denialReason`` is the billing-family reason
   ``DENIAL_REASON_INSUFFICIENT_BALANCE`` (SCREAMING_SNAKE wire enum value) —
   "says so plainly".
3. no ``items[0].retrievalEndpoint`` is issued.
4. no ``ramp.transaction_log`` row is written under the credit-less agent.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import httpx
import psycopg
import pytest

from ramp_sdk.core import sign_offer_acceptance_jcs
from ramp_sdk import ProtocolVersion
from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import COMPOSE_FILE, StackURLs
from ..httpsig_signer import load_keypair
from ..resolve_carriers import first_item_of, retrieval_endpoint_of
from ..seed import (
    DEMO_PHILOSOPHY_DOMAIN,
    NOBILLING_AGENT_ID,
    SeededFixture,
    _resolve_pg_dsn,
)
from ..signing import AGENT_NOBILLING_KEY_PATH, sign_post

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The buyer has no billing arrangement. The agent cannot accept any "
    "offer; the platform says so plainly."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_ACCEPT_OFFER_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"

# The billing-family per-item denial reason the items[] batch path emits for a
# credit-less buyer. SCREAMING_SNAKE: the handler codec
# (protojson MarshalOptions{EmitUnpopulated:true}, no UseEnumNumbers/UseProtoNames)
# serializes enum VALUES as their full proto names (field NAMES stay camelCase).
_INSUFFICIENT_BALANCE = "DENIAL_REASON_INSUFFICIENT_BALANCE"


def _transaction_log_row_count_for_agent(dsn: str, agent_id: str) -> int:
    """Count ramp.transaction_log rows for the credit-less agent.

    The credit-less agent never transacts, so its count MUST stay 0.

    BLACK-BOX e2e exception: the transaction ledger has NO
    protocol read surface BY DESIGN — record-read/reporting is downstream
    observability over the operator's datastore, out of RAMP's protocol scope,
    so no public read RPC will be added. A full-stack e2e observing the
    deployment's datastore directly is NOT the pt9 layer-bypass that rule
    forbids (an in-process test reaching past a production layer); it is the
    only way to assert this ledger side effect (here, its absence) end-to-end.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM ramp.transaction_log WHERE agent_id = %s", (agent_id,))
        row = cur.fetchone()
    return int(row[0]) if row else 0


def _discover_first_offer(exchange_url: str) -> dict[str, Any]:
    resp = sign_post(
        f"{exchange_url}{_DISCOVER_PATH}",
        body=discover_body(
            agent_id=NOBILLING_AGENT_ID,
            uris=[_RESOURCE_URI],
            exchange=recipient_of(exchange_url),
            domain=DEMO_PHILOSOPHY_DOMAIN,
            user_type="individual",
            geography="US",
        ),
        key_path=AGENT_NOBILLING_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"DiscoverResources must precede ExecuteTransaction; got {resp.status_code}: {resp.text[:512]}"
    )
    offers = resp.json().get("offers") or []
    assert offers, f"DiscoverResources returned no offers for {_RESOURCE_URI!r}"
    offer = cast(dict[str, Any], offers[0])
    assert offer.get("signature"), f"discovered offer carries no signature: {offer!r}"
    return offer


def test_credit_less_agent_is_refused_with_billing_signal_and_no_url(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers the credit-less agent
) -> None:
    """No billing arrangement → refusal, billing-family reason, no URL, no row."""
    offer = _discover_first_offer(compose_stack.exchange)

    tx_request_id = f"tx-{uuid.uuid4().hex}"
    # Agent acceptance: agent_acceptance is REQUIRED at execute. Sign it with the
    # credit-less agent's own key so the request PASSES the acceptance gate and
    # REACHES the billing gate — which is the refusal this scenario asserts. (Were
    # acceptance absent, the Exchange would refuse earlier with an acceptance error,
    # not the billing-family refusal the obligation requires.)
    _, acc_priv = load_keypair(AGENT_NOBILLING_KEY_PATH)
    acceptance_sig, acceptance_alg = sign_offer_acceptance_jcs(
        seed=acc_priv.private_bytes_raw(),
        offer_sig=str(offer.get("signature")),
        requester_id=NOBILLING_AGENT_ID,
        requester_domain=DEMO_PHILOSOPHY_DOMAIN,
        idempotency_key=tx_request_id,
    )
    # A single offer rides the items[] envelope (NO top-level
    # offer/agentAcceptance/offerId) — the 1-element-batch wire shape. The tightened proto:
    # each item reflects the FULL signed offer; the Exchange verifies
    # offer.signature over the presented bytes. The billing refusal fires AFTER
    # the offer verifies, so this still reaches the billing gate — but on the
    # batch path it classifies as an in-body PER-ITEM denial, not an envelope abort.
    resp = sign_post(
        f"{compose_stack.exchange}{_ACCEPT_OFFER_PATH}",
        body={
            "ver": ProtocolVersion,
            "idempotency_key": tx_request_id,
            "requester": {
                "id": NOBILLING_AGENT_ID,
                "domain": DEMO_PHILOSOPHY_DOMAIN,
                "type": "REQUESTER_TYPE_AGENT",
            },
            "items": [
                {
                    "offer": offer,
                    "agent_acceptance": {
                        "signature": acceptance_sig,
                        "signature_algorithm": acceptance_alg,
                    },
                }
            ],
        },
        extra_headers={"X-RAMP-Agent-Id": NOBILLING_AGENT_ID},
        key_path=AGENT_NOBILLING_KEY_PATH,
    )

    # (1) HTTP 200 — the items[] batch path classifies the no-billing refusal as
    # an in-body per-item denial (the request is well-formed, so no envelope abort).
    assert resp.status_code == httpx.codes.OK, (
        f"items[] batch path must classify the no-billing refusal in-body at 200; "
        f"got status={resp.status_code}, body={resp.text[:512]!r}"
    )
    payload = cast(dict[str, Any], resp.json())
    item = first_item_of(payload)
    assert item is not None, f"refusal response carried no items[0]: {payload}"
    # (2) Billing-family per-item denial reason — "says so plainly".
    assert item.get("denial_reason") == _INSUFFICIENT_BALANCE, (
        f"credit-less buyer must surface items[0].denialReason == {_INSUFFICIENT_BALANCE!r}; "
        f"got {item.get('denial_reason')!r} (item={item})"
    )
    # (3) No signed URL on the denied item.
    issued_url = retrieval_endpoint_of(item)
    assert issued_url is None, (
        f"denial must NOT issue items[0].retrievalEndpoint; got {issued_url!r}"
    )

    # (4) No transaction_log row for the credit-less agent.
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    row_count = _transaction_log_row_count_for_agent(dsn, NOBILLING_AGENT_ID)
    assert row_count == 0, (
        f"refusal must not persist a ramp.transaction_log row; found {row_count} for "
        f"agent_id={NOBILLING_AGENT_ID!r}"
    )
