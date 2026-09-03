"""Obligation 03, happy-0: browse offers on a single URI.

Scenario (verbatim — the first happy-path bullet):

> An agent asks the platform for offers on a single resource URI. The
> platform returns all applicable offers — per-request, subscription,
> any bundled options — with their prices and terms.

R1 scope: subscription offers and bundles are deferred; "all applicable
offers" means the per-request Offer the Exchange materialises for the
matching term. Driven against the demo ``epicurus`` resource (single PER_UNIT
USD term). The test asserts the offer surfaces with non-empty pricing and a
non-empty Exchange-minted signature — the data agents need to evaluate cost
and commit later via ExecuteTransaction.
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

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent asks the platform for offers on a single resource URI. "
    "The platform returns all applicable offers — per-request, "
    "subscription, any bundled options — with their prices and terms."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"


def test_single_uri_browse_returns_offers_with_prices_and_terms(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """DiscoverResources on a single demo URI returns one Offer with full terms."""
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
        f"DiscoverResources on a demo URI must return 200; got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    # (b)
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])
    assert offers, f"DiscoverResources must return at least one offer; body={resp.text[:512]}"

    # (c) each surfaced Offer carries pricing.rate (number), pricing.currency
    # (ISO 4217), and a non-empty Exchange-minted signature.
    for offer in offers:
        offer_id = offer.get("offer_id")
        pricing = cast(dict[str, Any], offer.get("pricing") or {})
        rate = pricing.get("rate")
        currency = pricing.get("currency")
        signature = offer.get("signature")
        # Money-as-string: pricing.rate rides as a decimal STRING on the
        # wire (discover.go FormatMoney). Assert it is present and parses to a
        # number (the "plain number" invariant), not that it is a JSON number.
        assert isinstance(rate, (int, float, str)) and not isinstance(rate, bool), (
            f"offer {offer_id!r} must carry a numeric pricing.rate; got {rate!r}"
        )
        try:
            float(rate)
        except (TypeError, ValueError) as exc:
            msg = f"offer {offer_id!r} pricing.rate {rate!r} is not a plain number"
            raise AssertionError(msg) from exc
        assert (
            isinstance(currency, str)
            and len(currency) == 3
            and currency.isalpha()
            and currency.isupper()
        ), f"offer {offer_id!r} pricing.currency must be 3-letter ISO 4217; got {currency!r}"
        assert isinstance(signature, str) and signature, (
            f"offer {offer_id!r} must carry a non-empty Exchange-minted signature; got {signature!r}"
        )
