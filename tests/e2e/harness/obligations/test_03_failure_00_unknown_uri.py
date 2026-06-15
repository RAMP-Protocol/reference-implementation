"""Obligation 03, failure-0: query for an unknown URI.

Obligation file: ``docs/obligations/03-browse-offers-without-committing.md``.

Scenario (verbatim — the first failure-mode bullet):

> The agent queries a URI the platform does not recognize. The offer
> list is empty; the response explains that no offer is available for
> that URI.

The obligation 00 failure-1 sibling
(``test_00_failure_01_unknown_uri.py``) covers the *same observable
behavior* from the paid-access perspective; this test grounds the
assertion in obligation 03's *browse* framing. Both must stay green
because both obligations name the property independently — drift in
either direction is a regression.

Assertions:

(a) "queries a URI the platform does not recognize" — DiscoverResources
    on a never-seeded URI returns HTTP 200. (Transport-level failures
    are the *other* obligation 03 failure bullet — see
    ``test_03_failure_04_transient_retry.py``.)
(b) "the offer list is empty" — ``offers[]`` is empty.
(c) "the response explains that no offer is available for that URI" —
    the response carries a structured absence reason per ADR-008 D2:
    ``offerGroups[].absenceReason == OFFER_ABSENCE_REASON_NOT_IN_CATALOG``.
"""

from __future__ import annotations

import uuid
from typing import Any, cast

import httpx
import pytest

from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    _resolve_pg_dsn,
    _upsert_agent,
    _upsert_tenant_ed25519,
)
from ..signing import sign_post


pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The agent queries a URI the platform does not recognize. The offer "
    "list is empty; the response explains that no offer is available for "
    "that URI."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_TENANT_ID = "tenant-e2e-ob03-unknown"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-ob03-unknown"

_NOT_IN_CATALOG = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"


@pytest.fixture(scope="module")
def unknown_uri_seed() -> str:
    """Register the per-test tenant + agent; return a URI no catalog row covers."""
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)
    return f"http://edge:8787/ob03-unknown-{uuid.uuid4().hex}.html"


def test_unknown_uri_browse_empty_with_explanation(
    compose_stack: StackURLs,
    unknown_uri_seed: str,
) -> None:
    """DiscoverResources for an unknown URI returns 200 + empty offers + reason."""
    # Post-1rnxh: sign every /ramp.* call. The test signer's kid is
    # pre-registered in deploy/broker/keys.json so the global httpsig
    # middleware resolves it.
    resp = sign_post(
        f"{compose_stack.exchange}{_DISCOVER_PATH}",
        body={
            "requester": {
                "id": _AGENT_ID,
                "domain": _TENANT_DOMAIN,
                "uris": [unknown_uri_seed],
            },
        },
    )

    # (a) the platform responds — 200, not a 4xx/5xx
    assert resp.status_code == httpx.codes.OK, (
        f"browse must answer 200 even on an unknown URI; got {resp.status_code}: {resp.text[:512]}"
    )

    payload = cast(dict[str, Any], resp.json())

    # (b) "the offer list is empty"
    offers = cast(list[Any], payload.get("offers") or [])
    assert not offers, (
        f"browse on an unknown URI must return offers=[]; got {offers!r}; body={resp.text[:512]}"
    )

    # (c) "the response explains that no offer is available for that URI"
    groups = cast(list[dict[str, Any]], payload.get("offerGroups") or [])
    assert groups, (
        f"response must carry exactly one OfferGroup for the queried URI; "
        f"got offerGroups={groups!r}; body={resp.text[:512]}"
    )
    group = groups[0]
    absence_reason = group.get("absenceReason") or group.get("absence_reason")
    assert absence_reason == _NOT_IN_CATALOG, (
        f"absenceReason for an unknown URI must be {_NOT_IN_CATALOG!r}; "
        f"got {absence_reason!r}; body={resp.text[:512]}"
    )
