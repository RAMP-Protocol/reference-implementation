"""Obligation 00, failure-1: the URI is unknown to the platform.

Obligation file: ``docs/obligations/00-access-a-paid-resource.md``.

Scenario (verbatim — the first failure-mode bullet):

> The resource URI is unknown to the platform. The agent receives a
> response saying no offer is available for that URI.

The contract this test guards is observable on the wire: a
DiscoverResources call for a URI the platform has never seen returns
HTTP 200 with an empty offers list, AND a structured explanation that
no offer is available for that URI. The "structured explanation" piece
is the ADR-008 D2 contract — every empty offers response carries an
``OfferAbsenceReason`` enum, never a bare empty list with no reason —
and ADR-008 D2 names the canonical value for the never-seeded-URI case
``OFFER_ABSENCE_REASON_NOT_IN_CATALOG`` (post-t3vk W1 renamed
``UNKNOWN_RESOURCE`` to this).

The structural absence-reason invariant is exhaustively asserted by
``test_99_adr008_d2_absence_reason.py``. THIS test asserts the
*obligation 00* framing: the agent sees a response that says no offer
is available, full stop. The two assertions overlap at the wire level
but ground in different documents.

Assertions:

(a) HTTP 200 — the platform answers, it does not error out. This is
    distinct from obligation 03 failure-2 ("the platform is
    unreachable") which is a transport failure.
(b) Empty ``offers[]`` — no per-request offer is surfaced for the
    unknown URI.
(c) ``offerGroups[0].absenceReason`` is a string the agent can parse
    as the structured "no offer available" explanation. The specific
    enum value is the ADR-008 D2 vocabulary's ``NOT_IN_CATALOG``.

Out of scope for this test:

* Subscription-shaped refusals (``SCOPE_INSUFFICIENT``) — those belong
  to obligations 01/05.
* Restricted catalog rows with non-empty ``required_scopes`` — also
  obligation 05.
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
    "The resource URI is unknown to the platform. The agent receives a "
    "response saying no offer is available for that URI."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_TENANT_ID = "tenant-e2e-ob00-unknown"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-ob00-unknown"

_NOT_IN_CATALOG = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"


@pytest.fixture(scope="module")
def unknown_uri_seed() -> str:
    """Register the per-test tenant + agent; return a URI no catalog row covers."""
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)
    return f"http://edge:8787/ob00-unknown-{uuid.uuid4().hex}.html"


def test_unknown_uri_browse_returns_no_offer_with_explanation(
    compose_stack: StackURLs,
    unknown_uri_seed: str,
) -> None:
    """DiscoverResources on a never-seeded URI returns 200 + empty offers + reason."""
    # Post-1rnxh: every /ramp.v1.ExchangeService/* request is verified
    # by the Exchange's global httpsig middleware. sign_post stamps an
    # RFC 9421 signature with the test signer kid (pre-registered in
    # deploy/broker/keys.json).
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

    # (a) the platform answers — 200, not 4xx/5xx
    assert resp.status_code == httpx.codes.OK, (
        f"unknown-URI DiscoverResources must answer 200; got {resp.status_code}: {resp.text[:512]}"
    )

    payload = cast(dict[str, Any], resp.json())

    # (b) no offers surfaced
    offers = cast(list[Any], payload.get("offers") or [])
    assert not offers, f"unknown-URI DiscoverResources must return offers=[]; got {offers!r}"

    # (c) the response carries a structured explanation under the
    # canonical OfferGroup absence-reason vocabulary
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
