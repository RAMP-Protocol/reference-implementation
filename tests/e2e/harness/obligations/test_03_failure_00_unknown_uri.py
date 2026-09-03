"""Obligation 03, failure-0: query for an unknown URI (browse framing).

Scenario (verbatim — the first failure-mode bullet):

> The agent queries a URI the platform does not recognize. The offer
> list is empty; the response explains that no offer is available for
> that URI.

The obligation 00 failure-1 sibling covers the same observable from the
paid-access perspective; this grounds it in obligation 03's browse framing.
Driven against a never-seeded URI on the demo music domain.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import httpx
import pytest

from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import StackURLs
from ..seed import DEMO_MUSIC_DOMAIN, USD_AGENT_ID, SeededFixture
from ..signing import sign_post

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent queries a URI the platform does not recognize. The offer "
    "list is empty; the response explains that no offer is available for "
    "that URI."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_NOT_IN_CATALOG = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"


def test_unknown_uri_browse_empty_with_explanation(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed registers the demo buyer
) -> None:
    """DiscoverResources for an unknown demo URI returns 200 + empty offers + reason."""
    unknown_uri = f"http://{DEMO_MUSIC_DOMAIN}/lyrics/never-seeded-{uuid.uuid4().hex}.txt"
    resp = sign_post(
        f"{compose_stack.exchange}{_DISCOVER_PATH}",
        body=discover_body(
            agent_id=USD_AGENT_ID,
            uris=[unknown_uri],
            exchange=recipient_of(compose_stack.exchange),
            domain=DEMO_MUSIC_DOMAIN,
        ),
    )
    assert resp.status_code == httpx.codes.OK, (
        f"browse must answer 200 even on an unknown URI; got {resp.status_code}: {resp.text[:512]}"
    )
    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[Any], payload.get("offers") or [])
    assert not offers, f"browse on an unknown URI must return offers=[]; got {offers!r}"
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    assert groups, f"response must carry an OfferGroup; got offerGroups={groups!r}"
    absence_reason = groups[0].get("absence_reason")
    assert absence_reason == _NOT_IN_CATALOG, (
        f"absenceReason for an unknown URI must be {_NOT_IN_CATALOG!r}; got {absence_reason!r}"
    )
