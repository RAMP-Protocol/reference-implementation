"""E2E: stateless offer redemption — reflect the signed Offer through the public RPC.

Mirrors, over the wire and cross-process, the Go integration negatives in
``src/exchange/internal/transport/execute_offer_redemption_integration_test.go``
(``PresentedOfferAccepted`` / ``TamperedOfferPriceRejected`` plus the tampered-
expiry leg).

Core invariant
-------------------------------------------------------
An agent redeems an offer end-to-end by RE-PRESENTING the exact Exchange-signed
Offer it received at discovery on ``TransactionRequest.offer``. The tightened
proto removed ``offer_signature``; the request now carries the FULL signed
``offer`` (XOR ``items``) and the Exchange honours it ONLY while the signature
still covers the presented bytes. Any post-discovery mutation — price, expiry —
is observable through the public ``ExchangeService/ExecuteTransaction`` RPC as a
rejection with NO delivery URL.

Why this surface (decisive)
---------------------------
Tampering is only expressible where the TEST holds the offer object. The agent
gets it from ``DiscoverResources`` and reflects it on ``TransactionRequest.offer``;
the Broker ``Resolve`` path reflects the winning offer INTERNALLY
(``resolve.go`` ``tx.Offer = winner.Offer``) and the agent never touches it on
the wire, so a tampered/expired offer CANNOT be expressed through Resolve.
Therefore every leg drives ``ExchangeService/ExecuteTransaction`` agent-direct,
signed with the agent key whose kid == ``requester.id`` (``USD_AGENT_KEY_PATH``
== ``agent-e2e``).

Round-trip honesty
------------------
Each leg is a full discover→reflect→execute PROTOCOL round-trip on the Exchange
RPC. Positives additionally fetch the signed URL through the edge (delivery
round-trip). Negatives assert through the RESPONSE ONLY — the per-item
``denialReason`` and the absence of ``retrievalEndpoint`` — because there is NO
public transaction-read RPC by design
and the e2e runner cannot reach the Exchange's repo in a separate process
(Testing Doctrine §9): the strongest side-effect-absence observable through the
public surface is the absent signed URL on the denied item.

Negative-path relocation (verified against exchange_batch.go /
denial.go, NOT a weakening): on the items[] batch path the Exchange CLASSIFIES a
tampered offer as a PER-ITEM denial (``verifyPresentedOffer`` →
``ErrOfferSignatureInvalid`` → ``KindSignatureInvalid`` → ``denialReasonByKind``)
rather than aborting the envelope with a Connect error. So a 1-item tampered
request now surfaces HTTP 200 with ``items[0].denialReason ==
DENIAL_REASON_SIGNATURE_INVALID`` and no ``items[0].retrievalEndpoint`` — the
rejection moved from the transport layer to the per-item layer (doctrine pt10
honoured: it still rejects). The wire enum VALUE is full SCREAMING_SNAKE (the
handler codec emits ``EmitUnpopulated`` protojson with no ``UseEnumNumbers`` /
``UseProtoNames``; field NAMES stay camelCase). Unlike the pre-C2 single-offer
path the denial reason is now directly wire-observable, so the assertion pins
the typed ``denialReason`` rather than the coarse Connect ``code``.

Expiry scope (SCOPING DECISION)
-------------------------------------------
A genuinely-signed-but-stale offer (→ ``DENIAL_REASON_OFFER_EXPIRED``) is NOT
e2e-producible: the harness holds no Exchange offer-signing key and the
production Exchange clock has no override (hard-coded 5m OfferTTL). That case is
covered by the Go integration ``TestExecuteTransaction_ExpiredOfferRejected``.
Here, expiry is exercised via a TAMPERED ``expiresAt`` (set to a past instant),
which the discovered offer's signature does NOT cover → rejected. The denial
reason for a tampered field is ``SIGNATURE_INVALID`` (the signature check fires
independently of the freshness check), surfacing as Connect ``unauthenticated``.

Denial-reason note
------------------
On the items[] batch path the canonical ``DenialReason`` rides
as a typed field on the per-item ``TransactionResultItem`` (``buildBatchResultItem``),
emitted directly on the wire as ``items[0].denialReason`` (full SCREAMING_SNAKE
enum value). So the wire-observable assertion is the typed ``denialReason ==
DENIAL_REASON_SIGNATURE_INVALID`` plus the absent ``items[0].retrievalEndpoint``
— a stronger, fine-grained contract than the pre-C2 single-offer path, where the
reason rode as an undecodable base64 ``ErrorDetail`` on a Connect error and only
the coarse ``code`` was wire-observable.
"""

from __future__ import annotations

from typing import Any, cast

import httpx
import pytest

from .conftest import StackURLs
from .edge_fetch import fetch_signed
from .obligations.flow import discover_first_offer, execute_offer
from .resolve_carriers import cost_of, first_item_of, retrieval_endpoint_of
from .seed import DEMO_SFX_DOMAIN, USD_AGENT_ID, SeededFixture
from .signing import USD_AGENT_KEY_PATH

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

# The per-item denial reason a tampered offer produces on the items[] batch
# path (KindSignatureInvalid → denialReasonByKind). SCREAMING_SNAKE: the handler
# codec serializes enum VALUES as their full proto names (field NAMES stay
# camelCase).
_SIGNATURE_INVALID = "DENIAL_REASON_SIGNATURE_INVALID"

# The priced PER_UNIT demo resource (wooden-door-creak, 0.25 USD) — the only
# PRICED demo resource, so a price tamper is meaningful AND the happy path
# delivers a real fetch + an observable cost. Bought with the USD buyer
# (== agent-e2e, whose key signs ExecuteTransaction).
_RESOURCE_URI = f"http://{DEMO_SFX_DOMAIN}/sfx/wooden-door-creak.json"


def _assert_tamper_denied(resp: httpx.Response, *, what: str) -> None:
    """Assert a tampered-offer EXECUTE is a per-item SIGNATURE_INVALID denial.

    On the items[] batch path a tampered offer classifies as an
    in-body per-item denial (KindSignatureInvalid), not a Connect envelope error.
    So the public-surface rejection is HTTP 200 + ``items[0].denialReason ==
    DENIAL_REASON_SIGNATURE_INVALID`` + no ``items[0].retrievalEndpoint`` (no
    delivery side effect). ``what`` names the tampered field for the message.
    """
    assert resp.status_code == httpx.codes.OK, (
        f"a tampered {what} now classifies as an in-body per-item denial at 200; "
        f"got status={resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    item = first_item_of(payload)
    assert item is not None, f"tamper response carried no items[0]: {payload!r}"
    assert item.get("denial_reason") == _SIGNATURE_INVALID, (
        f"a tampered {what} must reject with items[0].denialReason == "
        f"{_SIGNATURE_INVALID!r} (signature does not cover the presented bytes); "
        f"got {item.get('denial_reason')!r}, body={resp.text[:512]}"
    )
    assert retrieval_endpoint_of(item) is None, (
        f"a rejected tamper must NOT issue items[0].retrievalEndpoint; body={resp.text[:512]}"
    )


def test_reflected_offer_redeems_and_delivers_content(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """HAPPY: discover → reflect the signed offer unchanged → execute → fetch bytes.

    Full discover→reflect→execute protocol round-trip on the Exchange RPC, then a
    delivery round-trip fetching the signed URL through the edge. Asserts a
    non-empty transactionId, a non-empty retrievalEndpoint, the signed unit cost,
    and that the edge delivers real bytes.
    """
    offer = discover_first_offer(
        compose_stack.exchange_c,
        uri=_RESOURCE_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    resp, _tx = execute_offer(
        compose_stack.exchange_c,
        offer,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"reflecting the genuine signed offer must succeed; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    payload: dict[str, Any] = resp.json()

    # The EXECUTE response is an items[] envelope — read the
    # per-result fields (transactionId, retrievalEndpoint, cost) from items[0].
    item = first_item_of(payload)
    assert item is not None, f"accepted transaction carried no items[0]: {payload!r}"
    transaction_id = item.get("transaction_id")
    assert isinstance(transaction_id, str) and transaction_id, (
        f"accepted transaction must carry a non-empty items[0].transactionId; got {payload!r}"
    )
    signed_url = retrieval_endpoint_of(item)
    assert signed_url, f"accepted transaction returned no items[0].retrievalEndpoint: {payload!r}"

    # The charged unit cost equals the SIGNED rate (the agent pays what it signed).
    # Money-as-string: Money.amount/unit_cost serialize as decimal
    # STRINGS on the wire, so compare numeric value, not the raw type.
    cost = cost_of(item)
    assert cost is not None, payload
    assert float(cost["unit_cost"]) == seeded.priced_per_unit_rate, cost
    assert cost.get("currency") == "USD", cost

    # Delivery round-trip: the signed URL fetches real bytes through the edge.
    content = fetch_signed(signed_url, compose_stack, timeout=30.0, key_path=USD_AGENT_KEY_PATH)
    assert content.text.strip(), content.text


def test_tampered_price_on_reflected_offer_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """TAMPERED PRICE: mutate offer.pricing.rate after discovery → rejected, no URL.

    Full discover→reflect→execute protocol round-trip. The reflected offer's
    signed ``pricing.rate`` is mutated BEFORE signing+sending, so the genuine
    Exchange signature (over the original bytes) no longer covers the presented
    bytes. C2: on the items[] path this is an in-body per-item denial — asserts
    HTTP 200 + ``items[0].denialReason == DENIAL_REASON_SIGNATURE_INVALID`` AND
    that NO ``items[0].retrievalEndpoint`` is returned (no delivery side effect).
    """
    offer = discover_first_offer(
        compose_stack.exchange_c,
        uri=_RESOURCE_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )

    def _halve_rate(presented: dict[str, Any]) -> None:
        pricing = presented.get("pricing")
        assert isinstance(pricing, dict) and "rate" in pricing, (
            f"discovered offer must carry pricing.rate to tamper; got {presented!r}"
        )
        # A value the Exchange never signed — strictly different from the signed rate.
        pricing["rate"] = "0.01"

    resp, _tx = execute_offer(
        compose_stack.exchange_c,
        offer,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
        mutate=_halve_rate,
    )

    _assert_tamper_denied(resp, what="offer.pricing.rate")


def test_tampered_expires_at_on_reflected_offer_is_rejected(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """TAMPERED EXPIRY: mutate offer.expiresAt after discovery → rejected, no URL.

    Full discover→reflect→execute protocol round-trip. The reflected offer's
    signed ``expiresAt`` is set to a PAST instant the Exchange never signed; the
    signature does not cover the mutated expiry, so the offer is rejected on
    signature grounds — independent of the freshness check. C2: on the items[]
    path this is an in-body per-item denial — asserts HTTP 200 +
    ``items[0].denialReason == DENIAL_REASON_SIGNATURE_INVALID`` AND the absent
    ``items[0].retrievalEndpoint``.

    A genuinely-signed-but-stale offer (→ OFFER_EXPIRED) is NOT e2e-producible
    (no exchange offer key in the harness, no clock override); that case is
    covered by the Go integration ExpiredOfferRejected test. See module docstring.
    """
    offer = discover_first_offer(
        compose_stack.exchange_c,
        uri=_RESOURCE_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )

    def _expire_in_the_past(presented: dict[str, Any]) -> None:
        assert presented.get("expires_at"), (
            f"discovered offer must carry expiresAt to tamper; got {presented!r}"
        )
        # An instant the Exchange never signed (and which is also strictly past).
        presented["expires_at"] = "2000-01-01T00:00:00Z"

    resp, _tx = execute_offer(
        compose_stack.exchange_c,
        offer,
        agent_id=USD_AGENT_ID,
        domain=DEMO_SFX_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
        mutate=_expire_in_the_past,
    )

    _assert_tamper_denied(resp, what="offer.expiresAt")
