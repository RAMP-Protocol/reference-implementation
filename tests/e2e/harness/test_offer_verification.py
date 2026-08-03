"""E2E: the Broker admits a REAL-Exchange-signed offer through its fail-closed Verifier.

Core invariant
-------------------------------------------------------
Every offer that reaches the Broker's typed ``DiscoveryResponse.offer_groups``
MUST have passed the broker's fail-closed offer Verifier
(``core.NewVerifier(Strict, …)`` wired in ``src/broker/cmd/server/wiring.go``):
the Verifier resolves the exchange's offer-signing key from that exchange's
published WBA directory and rejects any offer whose signature does not verify.
The default is fail-CLOSED — an unwired Verifier rejects EVERYTHING
(``unwiredVerifier`` in ``resolve.go``).

This suite proves the POSITIVE half end-to-end against a REAL Exchange container:
a licensed resolve of a real catalog URI returns a genuinely Exchange-signed offer
in ``offer_groups``. Because the production Verifier is fail-closed, an offer can
ONLY appear if verification SUCCEEDED — its presence is the observable proof that
the broker resolved the exchange's real WBA key and the signature checked out. No
mock stands anywhere in this path: the Exchange signs with its own key, publishes
that key in its own directory, and the Broker verifies against the fetched key.

Negative half — SCOPING DECISION (mirrors test_offer_redemption.py:54-63)
-------------------------------------------------------------------------
The complementary broker-discover NEGATIVE — the Broker DROPS an offer the
Verifier rejects, keeping only the verified ones — is NOT e2e-producible against a
real Exchange. A real Exchange publishes the SAME key it signs with
(``main.go``: ``OfferKey: signer.PublicKey()``) and its key window is hard-coded,
so it can NEVER emit an offer that fails the broker's discover-path Verifier;
there is no harness seam to make a real Exchange produce a rejectable offer.
Additionally the broker Resolve path reflects the winning offer INTERNALLY
(``resolve.go`` folds the offer into the group; the agent never re-presents it on
the wire), so — unlike the Exchange ExecuteTransaction tamper path in
``test_offer_redemption.py`` — a tampered/unverifiable offer cannot even be
expressed through Resolve from the agent side.

The drop-wiring negative is therefore pinned one level down, at the broker
integration layer, by
``src/broker/internal/transport/offer_drop_wiring_integration_test.go``
(``TestResolve_RejectingVerifierDropsOfferFromOfferGroups``): it injects a
broker-side ``Deps.OfferVerifier`` that rejects one of two REAL-Exchange-signed
offers and asserts the discover path drops exactly that offer from
``offer_groups`` — mocking the broker's verify/reject DECISION (a legitimate
broker seam), NOT the Exchange (Testing Doctrine pt 6). Together the two tests
cover both halves without any test mocking the Exchange.

Round-trip honesty
------------------
The single leg here is a full protocol round-trip: signed
``BrokerService/Resolve`` (RFC 9421, keyID == requester.id) → Broker → real
Exchange ``DiscoverResources`` → the Broker's fail-closed Verifier (real WBA key
fetch) → the typed ``DiscoveryResponse`` the agent decodes. Presence of a signed
offer is asserted through that same public surface — no DB or internal-state read.
"""

from __future__ import annotations

from typing import Any, cast

import httpx
import pytest

from . import broker_client
from .conftest import StackURLs
from .seed import SeededFixture

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")


def _offers_in_groups(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten every offer across all ``offer_groups`` of a DiscoveryResponse.

    Reads the canonical proto-JSON (emit-unpopulated, camelCase-with-snake
    fallback) the Broker emits on ``BrokerService/Resolve`` — the same shape
    ``broker_client._first_offer`` / ``resolve_carriers`` read.
    """
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    return [o for g in groups for o in cast(list[dict[str, Any]], g.get("offers") or [])]


def test_broker_admits_real_exchange_signed_offer_into_offer_groups(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A licensed resolve returns a genuinely Exchange-signed offer in offer_groups.

    The Broker's Verifier is fail-CLOSED, so the offer surfaces ONLY if its
    signature verified against the exchange's real WBA-published key — presence is
    the observable proof that verification passed. Driven on the FREE demo resource
    (socrates) so no billing gate can pre-empt discovery; the currency-matched demo
    buyer signs the Resolve (keyID == requester.id).
    """
    res = seeded.free
    resp = broker_client.resolve(
        compose_stack,
        {"agent_id": res.buyer_agent_id, "uri": res.uri, "intended_use": "ai-input"},
        key_path=res.buyer_key_path,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = cast(dict[str, Any], resp.json())

    offers = _offers_in_groups(payload)
    assert offers, (
        "licensed resolve returned no offers in offer_groups — the fail-closed "
        f"Verifier admitted nothing (verification failed or offer absent): {payload!r}"
    )

    # The admitted offer carries the Exchange's genuine signature. Its PRESENCE
    # past the fail-closed Verifier is the proof that verification succeeded; the
    # non-empty signature is the artifact that was verified.
    winner = offers[0]
    signature = winner.get("signature")
    assert isinstance(signature, str) and signature, (
        f"admitted offer carries no signature — cannot have passed the Verifier: {winner!r}"
    )
