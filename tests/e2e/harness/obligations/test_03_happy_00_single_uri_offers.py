"""Obligation 03, happy-0: browse offers on a single URI.

Obligation file: ``docs/obligations/03-browse-offers-without-committing.md``.

Scenario (verbatim — the first happy-path bullet):

> An agent asks the platform for offers on a single resource URI. The
> platform returns all applicable offers — per-request, subscription,
> any bundled options — with their prices and terms.

R1 scope clarification: subscription offers and bundles are deferred
past R1 (the deferred-obligations 01/02/06 carry that surface). For
v1, "all applicable offers" means the canonical per-request Offer
``buildOffer`` (catalog.go) materializes for an unrestricted catalog
row. The test asserts the per-request offer surfaces with non-empty
pricing and a non-empty Exchange-minted signature — the bare-minimum
data agents need to evaluate cost ("prices and terms") and to commit
later via ExecuteTransaction ("any bundled options" once those land).

Assertions trace to the scenario text:

(a) "asks the platform for offers on a single resource URI" — a single
    DiscoverResources POST for one seeded URI returns 200.
(b) "returns all applicable offers" — at least one offer surfaces.
    Under v1 that is exactly one per-request Offer; the proto carries
    a list so the agent can iterate without special-casing arity.
(c) "with their prices and terms" — each surfaced Offer carries a
    ``pricing.rate`` (number) AND a ``pricing.currency`` (3-letter
    ISO 4217 uppercase) AND a non-empty Exchange-minted ``signature``
    (the "terms" the agent commits to later by re-presenting it on
    ExecuteTransaction).

Obligation 03's "Implementation hints" guarantee — "browse is a
read-only operation. No ledger row is written." — is the *sibling*
invariant under test_03_happy_01_browse_leaves_no_record. This test
focuses on the response shape only.
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
from ..signing import sign_post


pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent asks the platform for offers on a single resource URI. "
    "The platform returns all applicable offers — per-request, "
    "subscription, any bundled options — with their prices and terms."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_TENANT_ID = "tenant-e2e-ob03-single"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-ob03-single"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Run the stack-wide seed (contributor key + default tenant)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def single_uri_catalog(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> Iterator[tuple[str, str]]:
    """Seed a per-test tenant + a single catalog row at one resource URI."""
    del seeded
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)

    suffix = uuid.uuid4().hex[:8]
    path = f"/premium/ob03-single-{suffix}.html"
    resource_uri = f"{EDGE_PUBLIC_URL}{path}"
    content_id = f"res-ob03-single-{suffix}"

    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=EDGE_PUBLIC_HOST, path=path, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )

    yield resource_uri, content_id


def test_single_uri_browse_returns_offers_with_prices_and_terms(
    compose_stack: StackURLs,
    single_uri_catalog: tuple[str, str],
) -> None:
    """DiscoverResources on a single seeded URI returns one Offer with full terms."""
    resource_uri, expected_offer_id = single_uri_catalog

    # Post-1rnxh: every /ramp.v1.ExchangeService/* request is verified
    # by the Exchange's global httpsig middleware. sign_post stamps an
    # RFC 9421 signature with the test signer kid; requester.id carries
    # the agent identity the service layer attaches to the trace.
    resp = sign_post(
        f"{compose_stack.exchange}{_DISCOVER_PATH}",
        body={
            "requester": {
                "id": _AGENT_ID,
                "domain": _TENANT_DOMAIN,
                "uris": [resource_uri],
            },
        },
    )

    # (a) "asks the platform for offers on a single resource URI"
    assert resp.status_code == httpx.codes.OK, (
        f"DiscoverResources on a seeded URI must return 200; "
        f"got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())

    # (b) "returns all applicable offers" — at least one offer for this URI
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])
    assert offers, (
        f"DiscoverResources on a seeded URI must return at least one offer; "
        f"got offers={offers!r}; body={resp.text[:512]}"
    )
    returned_ids = {o.get("offerId") for o in offers}
    assert expected_offer_id in returned_ids, (
        f"expected offerId={expected_offer_id!r} in {returned_ids!r}"
    )

    # (c) "with their prices and terms" — each surfaced Offer carries
    # pricing.rate (number), pricing.currency (ISO 4217), and a non-empty
    # Exchange-minted signature (the term the agent re-presents on accept).
    for offer in offers:
        offer_id = offer.get("offerId")
        pricing = cast(dict[str, Any], offer.get("pricing") or {})
        rate = pricing.get("rate")
        currency = pricing.get("currency")
        signature = offer.get("signature")
        assert isinstance(rate, (int, float)), (
            f"offer {offer_id!r} must carry a numeric pricing.rate; got {rate!r}"
        )
        assert (
            isinstance(currency, str)
            and len(currency) == 3
            and currency.isalpha()
            and currency.isupper()
        ), f"offer {offer_id!r} pricing.currency must be a 3-letter ISO 4217 code; got {currency!r}"
        assert isinstance(signature, str) and signature, (
            f"offer {offer_id!r} must carry a non-empty Exchange-minted signature; "
            f"got {signature!r}"
        )
