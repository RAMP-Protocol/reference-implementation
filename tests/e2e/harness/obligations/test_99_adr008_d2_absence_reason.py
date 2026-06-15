"""ADR-008 D2 — every empty-offers DiscoverResources/Discover response carries
a structured ``OfferAbsenceReason`` enum at the request level.

Anchor docs:
* ``docs/architecture/adr-008-testing-surface-isolation.md`` D2 —
  "every empty result carries a structured reason; tests assert on the
  enum, not on length-zero or truthiness."
* ``docs/architecture/adr-004-protocol-layers.md`` — refusal is the
  product; a refusal without a reason is a half-implementation.
* ``github.com/RAMP-Protocol/protocol/ramp/v1/ramp.proto`` — ``OfferAbsenceReason`` (request-level
  vocabulary) and ``ResourceResponse.absence_reason_oneof``.

This module exercises the wire surface for the request-level vocabulary
the boio task added (UNKNOWN_RESOURCE, NO_AGENT_ENTITLEMENT,
GRANTS_DO_NOT_COVER, etc.). It deliberately sticks to the easiest
asserted-on-enum case — UNKNOWN_RESOURCE for a never-seeded URI —
because the harder causes (BILLING_BLOCK, OUTSTANDING_OBLIGATIONS,
SUBSCRIPTION_EXPIRED, INTERNAL_ERROR) are exhaustively unit-tested at
the helper boundary in
``src/exchange/internal/service/absence_reason_test.go`` and
``src/broker/internal/transport/resolve_gate_test.go``.

The unit tests at the helper boundary are what guard the per-cause
mapping; this E2E test guards that the wired call site stamps the
enum on the wire response when the path is exercised end-to-end.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import pytest

from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    _resolve_pg_dsn,
    _upsert_agent,
    _upsert_tenant_ed25519,
)
from ..signing import sign_post


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_LIST_OFFERS_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_TENANT_ID = "tenant-e2e-adr008-d2"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-adr008-d2"


@pytest.fixture(scope="module")
def absence_reason_seed() -> Iterator[str]:
    """Seed a per-test tenant with no catalog rows; return an unknown URI."""
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)
    unknown_uri = f"http://edge:8787/adr008-d2-never-seeded-{uuid.uuid4().hex}.html"
    yield unknown_uri


def _flatten_for_key(obj: object, key: str, out: list[object]) -> None:
    """Walk a JSON-ish structure collecting every value at ``key``.

    The proto-JSON-camelCase carrier name for the new oneof field is
    ``absenceReason``; some Connect-RPC frameworks emit ``absence_reason``
    directly. The walk picks up either form regardless of nesting depth.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                out.append(v)
            _flatten_for_key(v, key, out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_for_key(item, key, out)


def _extract_absence_reasons(payload: object) -> list[str]:
    """Return every absence_reason value found in ``payload``.

    Looks for both the camelCase wire name (``absenceReason``, the
    proto-JSON default) and the snake_case alias some clients normalise
    to. Returns the matched values verbatim so the assertion below
    asserts on the exact enum string.
    """
    out: list[object] = []
    _flatten_for_key(payload, "absenceReason", out)
    _flatten_for_key(payload, "absence_reason", out)
    return [str(v) for v in out if isinstance(v, str)]


def test_unknown_uri_discover_resources_sets_not_in_catalog_enum(
    compose_stack: StackURLs,
    absence_reason_seed: str,
) -> None:
    """DiscoverResources on a never-seeded URI MUST stamp NOT_IN_CATALOG.

    Asserts on the SPECIFIC enum value (NOT len(offers)==0 / truthiness),
    per ADR-008 D2: "tests assert on the enum, not on length-zero or
    truthiness." A regression that drops the absence_reason field, or
    emits OFFER_ABSENCE_REASON_UNSPECIFIED, or collapses every cause to
    one value, fails this test at the wire boundary.

    (W1 of t3vk renamed the never-seeded-URI cause from the
    project-specific ``OFFER_ABSENCE_REASON_UNKNOWN_RESOURCE`` to the
    canonical RAMP-protocol ``OFFER_ABSENCE_REASON_NOT_IN_CATALOG``.)
    """
    # Canonical ramp.proto ResourceQuery body: URIs ride on requester.uris.
    # The legacy {"resourceUrl": ...} shape is silently dropped by the
    # Connect-Go JSON codec (DiscardUnknown=true,
    # src/exchange/internal/transport/jsoncodec.go) and the handler then
    # rejects with KindInvalidRequest "requester required"
    # (exchange.go:229-235), short-circuiting the absence-reason path.
    #
    # Post-1rnxh: the Exchange's global httpsig middleware verifies every
    # /ramp.v1.ExchangeService/* request unconditionally. The signed-post
    # helper stamps an RFC 9421 signature with the test signer kid
    # (test-signer-e2e.v1) which is pre-registered in the static resolver
    # via deploy/broker/keys.json.
    body = {
        "requester": {
            "id": _AGENT_ID,
            "domain": _TENANT_DOMAIN,
            "uris": [absence_reason_seed],
        },
    }
    url = f"{compose_stack.exchange}{_LIST_OFFERS_PATH}"
    resp = sign_post(url, body=body)

    assert resp.status_code == 200, (
        f"DiscoverResources on unknown URI must answer 200 — got {resp.status_code}: "
        f"{resp.text[:512]!r}"
    )

    try:
        payload = resp.json()
    except json.JSONDecodeError as exc:
        pytest.fail(f"response not JSON: {exc}; body={resp.text[:512]!r}")

    reasons = _extract_absence_reasons(payload)

    # ADR-008 D2 contract: every empty-offers response sets a structured
    # cause; UNSPECIFIED is the bug-value (proto3 default).
    forbidden = "OFFER_ABSENCE_REASON_UNSPECIFIED"
    assert forbidden not in reasons, (
        f"absence_reason emitted as {forbidden!r} — ADR-008 D2 names "
        f"this value the producer-bug case; full body={resp.text[:512]!r}"
    )

    want = "OFFER_ABSENCE_REASON_NOT_IN_CATALOG"
    assert want in reasons, (
        f"DiscoverResources on never-seeded URI did not carry absence_reason="
        f"{want!r}; observed={reasons!r}; body={resp.text[:512]!r} — "
        f"obligation: 'every empty result carries a structured reason'"
    )
