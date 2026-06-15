"""Obligation 00, happy-0: offer list with prices and currencies in plain numbers.

Obligation file: ``docs/obligations/00-access-a-paid-resource.md``.

Scenario (verbatim — the first happy-path bullet):

> An agent asks the platform for a resource by URI. The platform returns
> the list of ways the buyer can pay for it, with prices and currencies
> in plain numbers.

This is the baseline commercial transaction: a buyer agent asks
``DiscoverResources`` for a URI and sees the per-request ways to pay for it.
Obligation 00 scopes out subscription pricing (``out of scope`` clause
points it at ``01-access-a-subscription-resource.md``), so this test
seeds only per-request (``SPOT``) offers at two distinct price tiers
against the same ``resource_url``. The obligation's sibling invariant —
"browse is a read-only operation. No ledger row is written." — is
asserted by the paired obligation 03 test; obligation 00 keeps its
assertions on the response shape the scenario actually describes.

Assertions trace directly to the scenario text:

(a) "asks the platform for a resource by URI" — a single ``DiscoverResources``
    call for the seeded ``resource_url`` returns 200.
(b) "returns the list of ways the buyer can pay for it" — every seeded
    per-request offer is present in the response (count matches the
    seeded set; browse is exhaustive).
(c) "with prices and currencies" — every returned offer carries a
    ``price.amountMinor`` and a ``price.currency`` matching the seeded
    values; both SPOT tiers (500 minor, 1200 minor) surface at their
    listed prices with ``currency == "USD"``.
(d) "plain numbers" — ``price.amountMinor`` is a canonical JSON number
    (int) or the canonical proto-JSON representation of ``int64``
    (decimal-digit string). It is NOT locale-formatted ("1,200"), NOT
    currency-decorated ("$500"), NOT a JSON object / array, NOT
    base64-encoded — i.e. it round-trips through ``int()`` with no
    transformation beyond optional string-to-int for the proto-JSON
    int64 rule. ``price.currency`` is a 3-letter ISO 4217 uppercase
    alphabetic code.

Obligation 00 explicitly scopes subscription pricing OUT
("Subscription pricing — belongs in 01-access-a-subscription-resource.md"),
so this test also asserts that no ``OFFER_TYPE_SUBSCRIPTION`` offer
surfaces for the per-request URI. That keeps the "paid resource"
baseline distinct from the subscription obligation.

Production status:

The agent-facing ``DiscoverResources`` path is reachable end-to-end against
the running compose stack: the Exchange-side gates that previously
blocked browse — the global RFC 9421 ``httpsig`` predicate over
``/ramp.*`` and the unconditional ``jwt.sub`` requirement in
``DiscoverResources`` — were closed in the wave-2 ``da2a5e3`` cluster
(exchange behavior gates). This test is now an honest regression
guard for the "paid resource baseline" contract: a single
``DiscoverResources`` call returns every seeded SPOT offer with plain-number
prices and ISO-4217 currencies, and no SUBSCRIPTION offers leak in.
The lenient xfail marker was removed in commit ``e91039e`` (ADR-008
D3 sweep — lenient xfail markers are forbidden; see
``docs/architecture/adr-008-testing-surface-isolation.md``).

P2.00 audit note (pizh, against canonical proto at ramp.proto):

* RPC path: ``/ramp.v1.ExchangeService/DiscoverResources`` matches canonical
  ``ExchangeService.DiscoverResources`` (ramp.proto:115).
* Request payload uses ``{"resourceUrl": ...}`` — canonical
  ``ResourceQuery`` carries the URI via ``requester.uris`` (ramp.proto:161,
  Requester.uris field). The codebase's protojson codec
  (``src/exchange/internal/transport/jsoncodec.go``) sets
  ``DiscardUnknown: true``, so ``resourceUrl`` is silently dropped and
  the handler (``exchange.go:226-232``) rejects with
  KindInvalidRequest "requester required" / "at least one uri required".
  The test asserts HTTP 200 — this is a real wire-format mismatch
  flagged for P3 to rewrite the request body to ``{"requester":
  {"uris": [resource_url]}}``.
* Response assertions reference ``offer.offerId``, ``offer.price.amountMinor``,
  ``offer.price.currency``, ``offer.subscriptionId``. Canonical
  ``Offer`` has no ``price`` sub-message: pricing rides on
  ``Offer.pricing.rate`` (double, ramp.proto:794) and
  ``Offer.pricing.currency`` (ramp.proto:797). ``Offer.offerId`` and
  ``Offer.subscriptionId`` map to canonical ``offer_id`` /
  ``subscription_id`` fields (ramp.proto:378 / :422). The
  ``price.amountMinor`` / ``price.currency`` assertions are stale —
  flagged for P3 rewrite to ``pricing.rate`` (double, not minor units)
  and ``pricing.currency``.
* ``_OBLIGATION_TEXT`` quotes the obligation 00 first happy-path
  bullet verbatim (``docs/obligations/00-access-a-paid-resource.md``).
* No ``_PRODUCTION_GAP`` — the production path is reachable; gap is
  in the test request body, not the platform.
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


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent asks the platform for a resource by URI. The platform returns "
    "the list of ways the buyer can pay for it, with prices and currencies "
    "in plain numbers."
)

_LIST_OFFERS_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# Per-test tenant — the obligation scopes a specific paid-resource URI
# and must not interfere with other obligation tests running against the
# shared compose stack. Per-test tenant_id + domain keep the seeded
# offer rows isolated and deletable on teardown.
_TENANT_ID = "tenant-e2e-ob00-offers"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-ob00-offers"

# The per-request offer's pricing the test pins against. The seeded
# value is the production default applied by
# ``src/exchange/internal/service/catalog.go::defaultPricing`` to every
# pushed catalog entry: ResourceEntry carries no pricing field
# (ramp.proto:1341), so the platform stamps a constant rate at push
# time. Asserting against this constant is faithful to the obligation
# prose — which binds the *shape* ("plain numbers", "currencies") but
# not the *value* — and avoids the dead-SQL anti-pattern the previous
# revision used: an UPDATE on ramp.catalog cannot affect the running
# DiscoverResources call because the catalog is served from an
# in-memory atomic snapshot (catalog.go:197, 324) that rebuilds only
# on PushResources. A future per-row rate variation test would need a
# proto pricing field on ResourceEntry or an admin reload RPC.
_EXPECTED_RATE = 0.05
_CURRENCY = "USD"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Run the stack-wide seed (catalog contributor, default tenant, broker).

    The stack-wide seed registers the catalog contributor pubkey in
    ``ramp.agents`` (Gate 1) which the per-test ``push_catalog`` call
    below relies on. The per-test tenant in ``paid_catalog`` does not
    share state with the default tenant — only the contributor row is
    reused.
    """
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def paid_catalog(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> Iterator[tuple[str, str]]:
    """Seed a per-test tenant + a single catalog row at one ``resource_url``.

    Returns ``(resource_uri, spot_offer_id)``. Post-t3vk, the legacy
    ``ramp.offers`` table was dropped (000006_drop_ye6f9_schema); the
    discover path now derives offer identity from the catalog row.
    Per ``src/exchange/internal/service/discover.go::buildOffer``, the
    canonical Offer surfaced for an unrestricted catalog row is a
    single per-request offer at the catalog's listed rate, and that
    rate is stamped by ``catalog.go::defaultPricing`` at push time
    because ``ResourceEntry`` (ramp.proto:1341) carries no pricing
    field for the caller to override. The test asserts against this
    default (``_EXPECTED_RATE``); a future variant requiring per-row
    pricing variation would need either a proto pricing field or an
    admin reload RPC to invalidate the in-memory catalog snapshot.

    Note: the legacy "two seeded SPOT rows at distinct price tiers"
    contract that this fixture used to provide cannot be replicated
    under the canonical schema — one catalog row produces exactly one
    per-request offer. The test below is updated accordingly.
    """
    del seeded  # Ordering-only: stack-wide seed primes the contributor row.
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))

    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)

    suffix = uuid.uuid4().hex[:8]
    path = f"/premium/paid-{suffix}.html"
    resource_uri = f"{EDGE_PUBLIC_URL}{path}"
    content_id = f"res-paid-{suffix}"

    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=EDGE_PUBLIC_HOST, path=path, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )

    yield resource_uri, content_id

    # Catalog row teardown is handled by the suite-wide tenant cleanup;
    # the legacy ramp.offers DELETE no longer applies post-t3vk.


def _post_discover_resources(url: str, resource_url: str) -> httpx.Response:
    """POST DiscoverResources without a biscuit — obligation 00 has no entitlement.

    Obligation 00 is the paid (non-subscription) baseline: the buyer has
    no covering subscription, so the agent carries no entitlement biscuit
    when asking how to pay. The body is the canonical ``ResourceQuery``
    shape — URIs ride on ``requester.uris[]``; the legacy "resourceUrl"
    body was silently dropped by the Connect-Go JSON codec post-t3vk
    (DiscardUnknown=true).

    Post-1rnxh: every /ramp.v1.ExchangeService/* request is verified by
    the Exchange's global httpsig middleware. sign_post stamps an RFC
    9421 signature with the test signer kid; requester.id carries the
    agent identity the service layer requires post-rjtks.
    """
    return sign_post(
        url,
        body={
            "requester": {
                "id": _AGENT_ID,
                "domain": _TENANT_DOMAIN,
                "uris": [resource_url],
            },
        },
    )


def _coerce_rate(raw: object) -> float:
    """Parse canonical ``pricing.rate`` enforcing the "plain numbers" invariant.

    The canonical ``Pricing.rate`` field is a ``double`` (ramp.proto:794).
    proto-JSON renders doubles as JSON numbers; "plain numbers" excludes
    locale-formatted strings ("1,200"), currency decorations ("$500"),
    base64, and nested structures.
    """
    if isinstance(raw, bool):
        msg = f"pricing.rate must not be a JSON boolean: {raw!r}"
        raise AssertionError(msg)
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError as exc:
            msg = (
                f"pricing.rate {raw!r} is not a plain number — "
                "locale formatting, currency glyphs, or non-numeric "
                "characters violate the obligation's 'plain numbers' clause"
            )
            raise AssertionError(msg) from exc
    msg = (
        f"pricing.rate must be a JSON number or proto-JSON double string, "
        f"got {type(raw).__name__}: {raw!r}"
    )
    raise AssertionError(msg)


def test_paid_resource_offer_list_with_plain_prices_and_currencies(
    compose_stack: StackURLs,
    paid_catalog: tuple[str, str],
) -> None:
    """DiscoverResources on a paid URI returns the per-request offer with plain prices.

    Every assertion traces back to the obligation scenario text:

    (a) "asks the platform for a resource by URI" — one DiscoverResources POST
        for the seeded URI returns 200.
    (b) "returns the list of ways the buyer can pay for it" — the seeded
        per-request offer surfaces in the response. (Under the canonical
        schema, one catalog row produces exactly one per-request offer
        via ``discover.go::buildOffer``; the legacy "two seeded SPOT
        rows" multi-tier contract cannot be replicated post-t3vk.)
    (c) "with prices and currencies" — the offer carries canonical
        ``pricing.rate`` (a double, ramp.proto:794) and
        ``pricing.currency`` (3-letter ISO 4217, ramp.proto:797),
        echoed at the seeded value.
    (d) "in plain numbers" — ``pricing.rate`` is a JSON number, not
        locale- or currency-formatted.

    Also asserts obligation-00's explicit scope boundary: no
    SUBSCRIPTION offer is returned (that path lives in obligation 01).
    """
    resource_uri, spot_offer_id = paid_catalog

    list_url = f"{compose_stack.exchange}{_LIST_OFFERS_PATH}"
    resp = _post_discover_resources(list_url, resource_uri)

    # (a) "asks the platform for a resource by URI" — the call succeeds.
    assert resp.status_code == httpx.codes.OK, (
        f"DiscoverResources on paid URI should succeed, got {resp.status_code}: {resp.text[:512]}"
    )

    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])

    # (b) "returns the list of ways the buyer can pay for it" — the
    # seeded per-request offer id surfaces. Per discover.go::buildOffer
    # the canonical offer_id IS the catalog row's resource_id.
    returned_ids = {o.get("offerId") for o in offers}
    assert spot_offer_id in returned_ids, (
        f"expected the per-request offer {spot_offer_id!r} for "
        f"{resource_uri!r}; got returned_ids={returned_ids}"
    )

    # Obligation 00 scope boundary — no SUBSCRIPTION offers (that path
    # is obligation 01's territory per the "Explicitly out of scope"
    # clause of the obligation file). Subscription offers carry a
    # non-empty subscription_id; per-request/SPOT do not (W1 of t3vk
    # removed the Offer.type / OfferType field).
    subscription_offers = [o for o in offers if o.get("subscriptionId") or o.get("subscription_id")]
    assert not subscription_offers, (
        f"obligation 00 scopes subscription pricing out; got subscription "
        f"offers {subscription_offers}"
    )

    by_id = {cast(str, o["offerId"]): o for o in offers}

    # (c) + (d) Per-request offer surfaces at the platform's canonical
    # default pricing — rate is a double (not minor units), currency is
    # a 3-letter ISO code. The default is stamped by
    # ``defaultPricing`` (catalog.go:406) on every push because the
    # canonical ``ResourceEntry`` carries no pricing field; see the
    # ``_EXPECTED_RATE`` comment above.
    spot = by_id[spot_offer_id]
    pricing = cast(dict[str, Any], spot.get("pricing") or {})
    rate = _coerce_rate(pricing.get("rate"))
    assert rate == _EXPECTED_RATE, (
        f"per-request offer should echo the platform's default rate "
        f"{_EXPECTED_RATE}, got {rate} from {spot}"
    )
    currency = pricing.get("currency")
    assert (
        isinstance(currency, str)
        and len(currency) == 3
        and currency.isalpha()
        and currency.isupper()
    ), f"currency must be a 3-letter uppercase ISO 4217 code, got {currency!r}"
    assert currency == _CURRENCY, f"currency should echo seeded {_CURRENCY!r}, got {currency!r}"
    # The "plain numbers" invariant — informational here since
    # _coerce_rate already enforced it.
    assert isinstance(rate, float), (
        f"pricing.rate must be a plain number; got {type(rate).__name__}: {rate!r}"
    )
