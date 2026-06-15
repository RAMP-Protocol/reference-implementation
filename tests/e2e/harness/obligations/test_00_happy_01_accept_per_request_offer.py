"""Obligation 00, happy-1: agent accepts a per-request offer.

Obligation file: ``docs/obligations/00-access-a-paid-resource.md``.

Scenario (verbatim — the second happy-path bullet):

> The agent selects a per-request offer. The platform confirms acceptance
> and hands the agent a URL it can fetch.

This is the commit point of the paid-resource flow: after the buyer
has browsed offers (happy-0) the agent picks one and asks the platform
to commit to it. The platform's contract is two-fold:

* "confirms acceptance" — ExecuteTransaction returns 200 with a
  transaction_id echoing the caller's tx_request_id. Persistence is
  observable later via the usage record (happy-3).
* "hands the agent a URL it can fetch" — the response carries a
  delivery URL on the canonical RAMP-native field
  ``TransactionResponse.retrieval_endpoint`` (field 18; protojson
  camelCase ``retrievalEndpoint``), set by ``buildTxResponse`` in
  ``src/exchange/internal/service/exchange_helpers.go``.
  This test asserts the URL is present and non-empty on that field
  (and that the legacy ``ext['signed_url']`` carrier is gone); the
  *content fetch* against that URL is obligation 00 happy-2's job.

Assertions trace to the scenario:

(a) "selects a per-request offer" — the agent has previously browsed
    the catalog (DiscoverResources) and picked one offer by its
    ``offer_id`` and ``signature``. The test seeds a catalog row at a
    paid URI, calls DiscoverResources to obtain a canonical Offer with
    its Exchange-minted signature, and then submits that offer_id +
    signature on ExecuteTransaction.
(b) "platform confirms acceptance" — the response is HTTP 200 with a
    non-empty ``transactionId`` echoing the ``id`` field the caller
    submitted (the tx_request_id idempotency key).
(c) "hands the agent a URL it can fetch" — top-level
    ``retrievalEndpoint`` is a non-empty string.

No biscuit, no subscription, no Authorization header — obligation 00
is the SPOT (per-request) baseline. The agent signs each outbound
request with its own RFC 9421 key material per obligation 04
(agent-as-own-principal); this test stays on the unsigned anonymous
path so the assertion focuses on the platform's confirm + URL contract,
not on the signature wiring.

Production status: the unsigned anonymous accept path requires the
canonical request body (``id``, ``offerId``, ``offerSignature``,
``requester``). Production validates these in
``exchange_helpers.go::validateTxRequest`` and rejects on any
missing field with ``KindInvalidRequest``. The test sends all four.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any, cast

import httpx
import pytest

from ..catalog_push import CatalogEntry, push_catalog
from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    EDGE_PUBLIC_HOST,
    EDGE_PUBLIC_URL,
    SeededFixture,
    _resolve_pg_dsn,
    _upsert_agent,
    _upsert_tenant_ed25519,
    seed_stack,
)
from ..signing import AGENT_E2E_KEY_PATH, sign_post
from .carriers import assert_signed_url


pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent selects a per-request offer. The platform confirms "
    "acceptance and hands the agent a URL it can fetch."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_EXECUTE_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"

# The Exchange's inmemory billing adapter is seeded at container start
# via ``EXCHANGE_BILLING_SEED`` (docker-compose.e2e.yml:201) with one
# agent: ``agent-e2e`` with a USD 100.00 balance. ExecuteTransaction's
# billing gate refuses any other agent id with "billing_denied: unknown
# agent" (KindPermissionDenied → HTTP 403), so the accept step must run
# under the seeded agent. The per-test tenant keeps the catalog row
# isolated; the agent identifier is the stack-wide seeded one.
_TENANT_ID = "tenant-e2e-ob00-accept"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Run the stack-wide seed (catalog contributor, default tenant, broker)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def paid_catalog(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> Iterator[tuple[str, str]]:
    """Seed a per-test tenant and a single paid catalog row.

    Yields ``(resource_uri, offer_id)``. The offer_id IS the catalog
    row's resource_id (post-t3vk); DiscoverResources will surface a
    single per-request Offer at the default pricing stamped by
    ``defaultPricing`` (rate=0.05, currency=USD).
    """
    del seeded  # ordering only — stack-wide seed primes the contributor row
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)

    suffix = uuid.uuid4().hex[:8]
    path = f"/premium/accept-{suffix}.html"
    resource_uri = f"{EDGE_PUBLIC_URL}{path}"
    content_id = f"res-accept-{suffix}"

    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=EDGE_PUBLIC_HOST, path=path, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )

    yield resource_uri, content_id


def _discover_offer(exchange_url: str, resource_uri: str) -> dict[str, Any]:
    """Call DiscoverResources and return the single per-request Offer payload.

    Post-1rnxh: signing is mandatory on every /ramp.v1.ExchangeService/*
    call. The agent signs as its own principal (kid == requester.id ==
    agent-e2e), pre-registered in deploy/broker/keys.json + ramp.agents.
    """
    resp = sign_post(
        f"{exchange_url}{_DISCOVER_PATH}",
        body={
            "requester": {
                "id": _AGENT_ID,
                "domain": _TENANT_DOMAIN,
                "uris": [resource_uri],
            },
        },
        key_path=AGENT_E2E_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, (
        f"DiscoverResources must precede ExecuteTransaction; got "
        f"{resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])
    assert offers, f"DiscoverResources returned no offers for {resource_uri!r}"
    return offers[0]


def _post_execute_transaction(
    exchange_url: str,
    *,
    tx_request_id: str,
    offer_id: str,
    offer_signature: str,
) -> httpx.Response:
    """POST a signed ExecuteTransaction with the canonical TransactionRequest body."""
    body = {
        "ver": "1.0",
        "id": tx_request_id,
        "offerId": offer_id,
        "offerSignature": offer_signature,
        "requester": {
            "id": _AGENT_ID,
            "domain": _TENANT_DOMAIN,
            "type": "REQUESTER_TYPE_AGENT",
        },
    }
    return sign_post(f"{exchange_url}{_EXECUTE_PATH}", body=body, key_path=AGENT_E2E_KEY_PATH)


def test_agent_accepts_per_request_offer_and_receives_signed_url(
    compose_stack: StackURLs,
    paid_catalog: tuple[str, str],
) -> None:
    """Accepting a per-request offer returns 200 + transactionId + signed URL."""
    resource_uri, expected_offer_id = paid_catalog
    offer = _discover_offer(compose_stack.exchange, resource_uri)

    offer_id = cast(str, offer.get("offerId"))
    offer_signature = cast(str, offer.get("signature"))
    assert offer_id == expected_offer_id, (
        f"DiscoverResources surfaced {offer_id!r}, expected {expected_offer_id!r}"
    )
    assert offer_signature, "offer must carry a non-empty signature from the Exchange"

    tx_request_id = f"tx-{uuid.uuid4().hex}"
    resp = _post_execute_transaction(
        compose_stack.exchange,
        tx_request_id=tx_request_id,
        offer_id=offer_id,
        offer_signature=offer_signature,
    )

    # (b) "platform confirms acceptance"
    assert resp.status_code == httpx.codes.OK, (
        f"ExecuteTransaction must succeed on a canonical request; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    assert payload.get("id") == tx_request_id, (
        f"response must echo tx_request_id {tx_request_id!r}; got id={payload.get('id')!r}"
    )
    transaction_id = payload.get("transactionId")
    assert isinstance(transaction_id, str) and transaction_id, (
        f"response must carry a non-empty transactionId; got {transaction_id!r}"
    )

    # (c) "hands the agent a URL it can fetch" — assert a non-empty canonical
    # top-level retrieval_endpoint (TransactionResponse field 18) and that the
    # legacy ext['signed_url'] carrier is gone. (This test asserts receipt; the
    # fetch itself is exercised by happy_02.)
    assert_signed_url(payload)
