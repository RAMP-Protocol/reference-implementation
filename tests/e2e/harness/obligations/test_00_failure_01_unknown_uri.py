"""Obligation 00, failure-1: the URI is unknown to the platform.

Scenario (verbatim — the first failure-mode bullet):

> The resource URI is unknown to the platform. The agent receives a
> response saying no offer is available for that URI.

Driven against a never-seeded URI on the demo philosophy domain (the demo
catalog the real ingester produced has no entry for it): a DiscoverResources
call returns HTTP 200 with an empty offers list AND a structured
``OFFER_ABSENCE_REASON_NOT_IN_CATALOG`` explanation (ADR-008 D2).
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import httpx
import pytest

from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import StackURLs
from ..seed import DEMO_PHILOSOPHY_DOMAIN, EUR_AGENT_ID, SeededFixture
from ..signing import sign_post

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The resource URI is unknown to the platform. The agent receives a "
    "response saying no offer is available for that URI."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_NOT_IN_CATALOG = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"


def test_unknown_uri_browse_returns_no_offer_with_explanation(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers the demo buyer
) -> None:
    """DiscoverResources on a never-seeded demo URI returns 200 + empty offers + reason."""
    unknown_uri = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/never-seeded-{uuid.uuid4().hex}.txt"
    resp = sign_post(
        f"{compose_stack.exchange}{_DISCOVER_PATH}",
        body=discover_body(
            agent_id=EUR_AGENT_ID,
            uris=[unknown_uri],
            exchange=recipient_of(compose_stack.exchange),
            domain=DEMO_PHILOSOPHY_DOMAIN,
        ),
    )
    assert resp.status_code == httpx.codes.OK, (
        f"unknown-URI DiscoverResources must answer 200; got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[Any], payload.get("offers") or [])
    assert not offers, f"unknown-URI DiscoverResources must return offers=[]; got {offers!r}"
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    assert groups, f"response must carry an OfferGroup; got offerGroups={groups!r}"
    absence_reason = groups[0].get("absence_reason")
    assert absence_reason == _NOT_IN_CATALOG, (
        f"absenceReason for an unknown URI must be {_NOT_IN_CATALOG!r}; got {absence_reason!r}"
    )
