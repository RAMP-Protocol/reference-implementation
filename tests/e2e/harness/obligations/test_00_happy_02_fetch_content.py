"""Obligation 00 happy-path #2: the agent fetches the URL; content is delivered.

Obligation file: ``docs/obligations/00-access-a-paid-resource.md``

Scenario (verbatim, third happy-path bullet):

> The agent fetches the URL. The resource owner's content is delivered
> as the response body.

Preceding scenarios in the same file set up the state this one consumes:

- happy-0 asks the platform for offers on a URI and sees the list,
  including the SPOT per-request option.
- happy-1 selects that SPOT per-request offer; the Exchange confirms
  acceptance and returns a signed URL.

This scenario picks up from there: the agent issues a plain HTTP GET
against the Exchange-minted signed URL — carrying no identity, no
Authorization, no entitlement biscuit, no RFC 9421 signature — and the
edge worker verifies the signature, proxies to the publisher
container, and relays back the publisher's HTML. The observable is
the publisher's ``content-marker-ob00-fetch`` string in the response
body, served from this test's dedicated ``/premium/fetch-content.html``
path (analogous to ``tests/e2e/harness/test_full_stack.py::
test_signed_url_fetches_origin_content_via_edge``, which uses the shared
seed_stack article-42 row).

The tenant/agent upsert, catalog push, DiscoverResources, and
ExecuteTransaction call are reproduced in-module rather than imported from
sibling happy files, keeping parallel executors decoupled. The catalog row
is pushed at this test's dedicated served path ``/premium/fetch-content.html``
so the test owns it outright: DiscoverResources resolves that URI to this
row, and the test submits the discovered ``offer_id`` + ``signature`` from
the SAME Offer (ExecuteTransaction re-verifies the signature against the
submitted ``offer_id``, so a hardcoded/mismatched offer_id is rejected with
``offer signature invalid``). The dedicated path also means the signed-URL
fetch lands on a file the mock-publisher actually serves — avoiding both the
URI-keyed catalog trie's last-write-wins collision with the shared seed_stack
article-42 row and a 404 on an unseeded path.

This test now PASSES (no longer xfail): the wire-format gap it once
documented is closed. The Exchange surfaces the signed delivery URL on
the canonical RAMP-native field ``TransactionResponse.retrieval_endpoint``
(field 18, proto-JSON ``retrievalEndpoint``); ``buildTxResponse`` in
``src/exchange/internal/service/exchange_helpers.go`` no longer writes
the legacy ``ext["signed_url"]`` struct slot. The assertion reads the
top-level ``retrievalEndpoint`` directly off the Exchange's
``ExecuteTransaction`` response.

P2.00 audit note (pizh, against canonical proto at ramp.proto):

* RPC path: ``/ramp.v1.ExchangeService/ExecuteTransaction`` matches
  canonical ``ExchangeService.ExecuteTransaction`` (ramp.proto:119).
* Request payload ``{"offerId": <id>}`` uses only canonical
  ``TransactionRequest.offer_id`` (camelCase). No non-canonical fields. ✓
* Response assertion reads the canonical
  ``TransactionResponse.retrieval_endpoint`` (proto-JSON
  ``retrievalEndpoint``); the legacy ``ext["signed_url"]`` carrier is gone.
* ``_OBLIGATION_TEXT`` quotes the obligation 00 third happy-path
  bullet verbatim (``docs/obligations/00-access-a-paid-resource.md``).
* No ``_PRODUCTION_GAP`` — the production path is reachable end-to-end.
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


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent fetches the URL. The resource owner's content is delivered as the response body."
)

_ACCEPT_OFFER_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"

# Per-test tenant keeps this module decoupled from any other module's
# seed state when executors run in parallel against the shared compose
# stack.
_TENANT_ID = "tenant-e2e-ob00-fetch"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
# ExecuteTransaction runs caller authz (resolveCaller + authorizeForAgent):
# the signing kid must be a registered agent in ramp.agents AND equal
# requester.id, and the billing gate credits only the stack-wide seeded
# agent-e2e ($100). A per-test agent id is neither in the static httpsig
# resolver (deploy/broker/keys.json) nor billing-credited, so this test acts
# AS agent-e2e — the per-test _TENANT_ID still isolates the catalog row. This
# mirrors test_00_happy_01.
_AGENT_ID = "agent-e2e"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Reuse the session-wide stack seed (contributor key, default tenant)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


# Dedicated served path for this obligation. The mock-publisher nginx serves
# tests/e2e/mock-publisher/content/ as its webroot, so this file is fetchable
# at the edge once the signed URL verifies. It is owned outright by THIS test
# (no other module seeds it), which sidesteps the global URI-keyed catalog
# trie's last-write-wins collision the shared seed_stack article-42 row would
# otherwise cause — snap.Lookup(uri) (exchange.go) resolves a URI to exactly
# one catalog entry regardless of the caller's tenant.
_PUBLISHER_PATH = "/premium/fetch-content.html"
_CONTENT_MARKER = "content-marker-ob00-fetch"


@pytest.fixture(scope="module")
def spot_offer(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: contributor + health gate
) -> Iterator[tuple[str, str]]:
    """Seed a per-request offer over this test's dedicated served path.

    Yields ``(resource_uri, content_id)``. The seeded catalog row's
    ``content_id`` IS the ``offer_id`` DiscoverResources surfaces and
    ExecuteTransaction consumes; the test discovers the offer and submits the
    discovered ``offer_id`` + ``signature`` so the pair stays consistent (the
    Exchange re-verifies the signature against the submitted ``offer_id``).

    The per-test tenant plus a dedicated served path keep this module
    decoupled from sibling fixtures and from the shared seed_stack row.
    Default pricing (stamped by ``push_catalog``) applies — no bare-SQL
    pricing update, so no catalog-snapshot rebuild is needed (``push_catalog``
    is a real PushResources RPC and reloads the snapshot itself). This mirrors
    ``test_00_happy_01``.
    """
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)

    resource_uri = f"{EDGE_PUBLIC_URL}{_PUBLISHER_PATH}"
    content_id = "res-ob00-fetch"
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=EDGE_PUBLIC_HOST, path=_PUBLISHER_PATH, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )

    yield resource_uri, content_id


_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"


def _discover_offer(exchange_url: str, resource_uri: str) -> dict[str, Any]:
    """Call DiscoverResources and return the single per-request Offer.

    Signs AS ``agent-e2e`` (kid == requester.id) so the same identity carries
    into ExecuteTransaction's caller authz. ``validateTxRequest`` requires
    BOTH ``offer_id`` and ``offer_signature``; the caller takes both off the
    SAME discovered Offer so the Exchange's offer-signature re-verification
    (which binds the signature to the submitted ``offer_id``) succeeds.
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
    exchange_url: str, offer_id: str, offer_signature: str
) -> httpx.Response:
    """Call ExecuteTransaction with an RFC 9421 signature on the request.

    Post-1rnxh: signing is universally mandatory on /ramp.v1.* paths.
    ExecuteTransaction additionally runs caller authz (resolveCaller +
    authorizeForAgent): the signing kid must be a registered agent in
    ramp.agents AND equal requester.id. So this signs AS ``agent-e2e``
    (``key_path=AGENT_E2E_KEY_PATH``; kid == requester.id == agent-e2e),
    the stack-wide seeded identity EXCHANGE_BILLING_SEED credits. The
    transport-only test signer (test-signer-e2e.v1) is NOT in ramp.agents
    and would be refused at resolveCaller. No ``Authorization`` bearer and
    no ``X-RAMP-Entitlement-Biscuit`` — SPOT offers do not exercise
    ``verifySubscriptionCoverage``, so no entitlement biscuit is required.

    The transaction surfaces the signed URL on the canonical
    ``TransactionResponse.retrieval_endpoint`` field (proto-JSON
    ``retrievalEndpoint``), which the caller asserts on.
    """
    url = f"{exchange_url}{_ACCEPT_OFFER_PATH}"
    return sign_post(
        url,
        body={
            "ver": "1.0",
            "id": f"tx-{uuid.uuid4().hex}",
            "offerId": offer_id,
            "offerSignature": offer_signature,
            "requester": {
                "id": _AGENT_ID,
                "domain": _TENANT_DOMAIN,
                "type": "REQUESTER_TYPE_AGENT",
            },
        },
        key_path=AGENT_E2E_KEY_PATH,
    )


def test_agent_fetches_signed_url_and_receives_publisher_content(
    compose_stack: StackURLs,
    spot_offer: tuple[str, str],
) -> None:
    """Fetching the Exchange-minted signed URL returns publisher bytes.

    Scenario bullet (verbatim):
        The agent fetches the URL. The resource owner's content is
        delivered as the response body.

    Assertion trace:

    1. Preceding scenario (happy-1) prerequisite — the agent accepts a
       SPOT per-request offer, so the Exchange returns a signed URL.
       Reproduced inline here (ExecuteTransaction call).
    2. "The agent fetches the URL" — ``httpx.get(signed_url,
       follow_redirects=True)`` with no identity, no Authorization,
       no entitlement biscuit, no RFC 9421 signature. The signed URL
       carries all authorization the edge worker needs.
    3. "The resource owner's content is delivered as the response body"
       — HTTP 200 AND the publisher's canary ``content-marker-ob00-fetch``
       substring is present in the response body. This test owns the
       dedicated ``/premium/fetch-content.html`` served path; the marker is
       seeded by the mock-publisher compose service.
    """
    assert _OBLIGATION_TEXT  # traceability anchor for the obligation matrix
    resource_uri, expected_offer_id = spot_offer

    offer = _discover_offer(compose_stack.exchange, resource_uri)
    offer_id = cast(str, offer.get("offerId"))
    offer_signature = cast(str, offer.get("signature"))
    assert offer_id == expected_offer_id, (
        f"DiscoverResources surfaced {offer_id!r}, expected {expected_offer_id!r}"
    )
    assert offer_signature, "offer must carry a non-empty signature from the Exchange"

    accept_resp = _post_execute_transaction(compose_stack.exchange, offer_id, offer_signature)
    assert accept_resp.status_code == httpx.codes.OK, (
        f"SPOT ExecuteTransaction should succeed for per-request offer, "
        f"got {accept_resp.status_code}: {accept_resp.text[:256]}"
    )
    accept_payload = accept_resp.json()
    # Canonical signed-URL carrier: top-level retrieval_endpoint (field 18);
    # legacy ext['signed_url'] carrier gone.
    signed_url = assert_signed_url(accept_payload)

    # Rewrite the internal edge host when the runner lives outside the
    # compose network; inside the network `edge:8787` resolves natively.
    host_signed_url = signed_url
    if compose_stack.edge != EDGE_PUBLIC_URL:
        host_signed_url = signed_url.replace(EDGE_PUBLIC_URL, compose_stack.edge)

    content_resp = httpx.get(host_signed_url, follow_redirects=True, timeout=15.0)
    # Obligation requires "the resource owner's content is delivered as
    # the response body" — exact 200 status (not a 404 substitute) and
    # the publisher's canary marker present in the body. This test owns the
    # dedicated served path ``/premium/fetch-content.html``; the
    # mock-publisher webroot file carries ``content-marker-ob00-fetch``.
    assert content_resp.status_code == httpx.codes.OK, (
        f"signed URL fetch must return 200 (obligation: content delivered as "
        f"response body), got {content_resp.status_code}: "
        f"{content_resp.text[:256]}"
    )
    assert _CONTENT_MARKER in content_resp.text, (
        f"response body missing publisher canary {_CONTENT_MARKER!r} "
        f"(obligation: resource owner's content is delivered as the response "
        f"body): {content_resp.text[:256]}"
    )
