"""Obligation 00, happy-1: agent accepts a per-request offer.

Scenario (verbatim — the second happy-path bullet):

> The agent selects a per-request offer. The platform confirms acceptance
> and hands the agent a URL it can fetch.

Driven against the demo ``epicurus`` resource (PER_UNIT USD, individual,
US/GB) as the USD demo buyer through the FULL two-phase Broker-relay chain
: the agent discovers via the Broker ``Resolve``
(discovery-only ranked Offers), then relay-executes the winning Offer — agent
sig1 + Broker sig2 multisig + agent offer-acceptance — through
``POST /broker/v1/exchange/execute`` to the Exchange.

(a) "selects a per-request offer" — Broker Resolve then relay the first Offer.
(b) "platform confirms acceptance" — 200 with a non-empty, Exchange-assigned
    transactionId. (The response no longer echoes the request's
    idempotency_key: ADR-019 dropped the response id; the durable identity of
    what the call created is the Exchange-assigned transactionId.)
(c) "hands the agent a URL it can fetch" — the canonical top-level
    ``retrievalEndpoint`` is non-empty.
"""

from __future__ import annotations

from typing import Any, cast

import httpx
import pytest

from ..broker_client import execute_first_offer
from ..conftest import StackURLs
from ..resolve_carriers import first_item_of, retrieval_endpoint_of
from ..seed import DEMO_PHILOSOPHY_DOMAIN, USD_AGENT_ID, SeededFixture
from ..signing import USD_AGENT_KEY_PATH

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent selects a per-request offer. The platform confirms "
    "acceptance and hands the agent a URL it can fetch."
)

_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"


def test_agent_accepts_per_request_offer_and_receives_signed_url(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Two-phase relay accept of a per-request offer → 200 + transactionId + URL."""
    # (a) Broker Resolve (discovery) → relay-execute the winning Offer (sig1+sig2).
    resp = execute_first_offer(
        compose_stack,
        {"agent_id": USD_AGENT_ID, "uri": _RESOURCE_URI, "domain": DEMO_PHILOSOPHY_DOMAIN},
        agent_id=USD_AGENT_ID,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"two-phase relay execute should succeed; got {resp.status_code}: {resp.text[:512]}"
    )
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields (transactionId, retrievalEndpoint) from items[0].
    payload = cast(dict[str, Any], resp.json())
    item = first_item_of(payload)
    assert item is not None, f"relay response carried no items[0]: {payload!r}"
    # (b)
    transaction_id = item.get("transaction_id")
    assert isinstance(transaction_id, str) and transaction_id, (
        f"items[0] must carry a non-empty transactionId; got {transaction_id!r}"
    )
    # (c)
    signed_url = retrieval_endpoint_of(item)
    assert isinstance(signed_url, str) and signed_url, (
        f"items[0].retrievalEndpoint must be a non-empty string; "
        f"got payload={payload!r}, body={resp.text[:512]}"
    )
