"""Obligation 00, happy-0: offer list with prices and currencies in plain numbers.

Scenario (verbatim — the first happy-path bullet):

> An agent asks the platform for a resource by URI. The platform returns
> the list of ways the buyer can pay for it, with prices and currencies
> in plain numbers.

Driven against the demo ``epicurus`` resource — a single PER_UNIT USD term
(0.0001/characters, individual, US/GB) the real ingester produced. A single
DiscoverResources call surfaces the per-request offer with its term-derived
price and ISO-4217 currency as plain numbers.

Assertions trace to the scenario text:
(a) "asks the platform for a resource by URI" — one DiscoverResources POST
    returns 200.
(b) "returns the list of ways the buyer can pay for it" — the per-request
    offer for the URI surfaces.
(c) "with prices and currencies" — the offer carries ``pricing.rate`` (double)
    and ``pricing.currency`` (3-letter ISO 4217).
(d) "plain numbers" — ``pricing.rate`` is a JSON number, not locale- or
    currency-formatted.
Scope boundary: no SUBSCRIPTION offer surfaces (that path is obligation 01).
"""

from __future__ import annotations


from typing import Any, cast

import httpx
import pytest

from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import StackURLs
from ..seed import DEMO_PHILOSOPHY_DOMAIN, USD_AGENT_ID, SeededFixture
from ..signing import sign_post

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent asks the platform for a resource by URI. The platform returns "
    "the list of ways the buyer can pay for it, with prices and currencies "
    "in plain numbers."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

# epicurus: PER_UNIT 0.0001/characters USD; individual; geo[US,GB].
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"
_EXPECTED_RATE = 0.0001
_CURRENCY = "USD"


def _coerce_rate(raw: object) -> float:
    """Parse canonical ``pricing.rate`` enforcing the 'plain numbers' invariant."""
    if isinstance(raw, bool):
        msg = f"pricing.rate must not be a JSON boolean: {raw!r}"
        raise AssertionError(msg)
    if isinstance(raw, (int, float)):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError as exc:
            msg = f"pricing.rate {raw!r} is not a plain number"
            raise AssertionError(msg) from exc
    msg = f"pricing.rate must be a JSON number or proto-JSON double string, got {raw!r}"
    raise AssertionError(msg)


def test_paid_resource_offer_list_with_plain_prices_and_currencies(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """DiscoverResources on a paid demo URI returns the per-request offer with plain prices."""
    resp = sign_post(
        f"{compose_stack.exchange}{_DISCOVER_PATH}",
        body=discover_body(
            agent_id=USD_AGENT_ID,
            uris=[_RESOURCE_URI],
            exchange=recipient_of(compose_stack.exchange),
            domain=DEMO_PHILOSOPHY_DOMAIN,
            user_type="individual",
            geography="US",
        ),
    )
    # (a)
    assert resp.status_code == httpx.codes.OK, (
        f"DiscoverResources on paid URI should succeed, got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])

    # (b)
    assert offers, f"expected a per-request offer for {_RESOURCE_URI!r}; got {payload}"

    # scope boundary — no SUBSCRIPTION offers
    subscription_offers = [o for o in offers if o.get("subscription_id")]
    assert not subscription_offers, (
        f"obligation 00 scopes subscription out; got {subscription_offers}"
    )

    spot = offers[0]
    pricing = cast(dict[str, Any], spot.get("pricing") or {})
    # (c) + (d)
    rate = _coerce_rate(pricing.get("rate"))
    assert rate == pytest.approx(_EXPECTED_RATE), (
        f"per-request offer should echo the term rate {_EXPECTED_RATE}, got {rate} from {spot}"
    )
    currency = pricing.get("currency")
    assert (
        isinstance(currency, str)
        and len(currency) == 3
        and currency.isalpha()
        and currency.isupper()
    ), f"currency must be a 3-letter uppercase ISO 4217 code, got {currency!r}"
    assert currency == _CURRENCY, f"currency should echo {_CURRENCY!r}, got {currency!r}"
    assert isinstance(rate, float)
