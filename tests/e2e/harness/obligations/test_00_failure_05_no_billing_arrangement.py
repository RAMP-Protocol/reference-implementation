"""Obligation 00 — failure 05: buyer has no billing arrangement.

Verbatim scenario (``docs/obligations/00-access-a-paid-resource.md``,
second failure-mode bullet):

> The buyer has no billing arrangement. The agent cannot accept any
> offer; the platform says so plainly.

This test seeds a SPOT (per-request) offer against a fresh tenant, then
calls ``ExecuteTransaction`` under an agent identity that has NO billing seed
anywhere in the stack. The compose ``EXCHANGE_BILLING_SEED`` credits
``agent-e2e`` with $100 (see ``docker-compose.e2e.yml:187``); this test
deliberately picks ``agent-nobilling-<suffix>`` so the seeded credit
cannot satisfy the acceptance.

Per the obligation text, the four observables the platform MUST honor
are:

1. response is NOT 200 — the platform refuses the acceptance, it does
   not hand a URL.
2. refusal carries a billing-family signal (``billing`` / ``no credit``
   / ``no arrangement`` / ``insufficient funds``) distinct from the
   other failure families (``expired`` / ``not granted`` / ``bad
   proof`` / ``unknown URI``) — "the platform says so plainly" demands
   the buyer can tell WHY. A generic 401/403 does not.
3. no signed URL is issued in the response body.
4. no ``ramp.transaction_log`` row is written under this attempt.

Production status:

The four observables now pass under the running compose stack and
this test is an honest regression guard for the "no billing
arrangement" refusal contract: the ``ExecuteTransaction`` path now refuses
credit-less callers with a billing-family reason, issues no signed
URL, and writes no ``ramp.transaction_log`` row. The lenient xfail
marker was removed in commit ``e91039e`` (ADR-008 D3 sweep — lenient
xfail markers are forbidden; see
``docs/architecture/adr-008-testing-surface-isolation.md``).

P2.00 audit note (pizh, against canonical proto at ramp.proto):

* RPC path: ``/ramp.v1.ExchangeService/ExecuteTransaction`` matches
  canonical ``ExchangeService.ExecuteTransaction`` (ramp.proto:119). ✓
* Request payload ``{"offerId": ...}`` is canonical
  (``TransactionRequest.offer_id``, ramp.proto:1137). ✓ The
  ``X-RAMP-Agent-Id`` header is an out-of-band observability stub —
  canonical identity rides on ``TransactionRequest.requester`` or
  the Authorization Bearer JWT (per existing AgentJWTMiddleware).
* Response refusal explanation walked via flattened JSON haystack —
  tolerant of any canonical carrier. The signed-URL-absence check
  inspects the canonical ``retrieval_endpoint`` (TransactionResponse
  field 18; protojson ``retrievalEndpoint``) on the top level and on
  each ``items[i]`` (TxItem field 12). On a refusal no URL appears on
  either, so the assertion holds — and a future leak on the canonical
  field is now caught (the old ``ext['signed_url']`` check became a
  dead slot after the carrier move).
* In-body comment cites
  ``src/exchange/internal/service/execute_transaction.go:54-58``
  for ``verifySubscriptionCoverage`` — that file was deleted in W3
  of t3vk (``66b8312``). Equivalent SUBSCRIPTION-coverage refusal
  now happens inside ``authorizeAnonymousAccess``
  (``src/exchange/internal/service/anonymous_execute.go:74-78``).
* ``_OBLIGATION_TEXT`` quotes the obligation 00 second failure-mode
  bullet verbatim (``docs/obligations/00-access-a-paid-resource.md``).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from typing import Any, cast

import httpx
import psycopg
import pytest

from ..catalog_push import CatalogEntry, load_public_key_bytes, push_catalog
from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    EDGE_PUBLIC_HOST,
    EDGE_PUBLIC_URL,
    _resolve_pg_dsn,
    _upsert_agent,
    _upsert_catalog_contributor,
    _upsert_exchange,
    _upsert_tenant_ed25519,
)
from ..signing import AGENT_NOBILLING_KEY_PATH, sign_post
from .carriers import retrieval_endpoint_of


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "The buyer has no billing arrangement. The agent cannot accept any "
    "offer; the platform says so plainly."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_ACCEPT_OFFER_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"

_TENANT_ID = "tenant-e2e-ob00-nobilling"
_EXCHANGE_ID = "mp-e2e-ob00-nobilling"
_EXCHANGE_DOMAIN = "exchange.e2e.local"

# Lowercase substrings that satisfy "the platform says so plainly" for the
# billing failure family. Matched against the whole response body plus every
# flattened string carrier. These are the exact family demanded by the
# team-lead prompt — distinct from the other failure families
# (expired / not granted / bad proof / unknown URI).
_BILLING_REASON_TOKENS: tuple[str, ...] = (
    "billing",
    "no credit",
    "no arrangement",
    "insufficient funds",
)


# The Exchange's EXCHANGE_BILLING_SEED credits only 'agent-e2e' with $100.
# 'agent-nobilling-e2e' is registered + keyed by seed.py but deliberately
# uncredited, so the billing gate refuses it — the observable that makes this
# obligation testable. The caller signs as its OWN principal (signing kid ==
# requester.id == this id), which the Exchange caller authz requires before
# the billing gate is even reached.
_NOBILLING_AGENT_ID = "agent-nobilling-e2e"


@pytest.fixture(scope="module")
def spot_offer_without_billing(
    compose_stack: StackURLs,
) -> Iterator[tuple[str, str, str]]:
    """Seed a per-request catalog row under a fresh tenant + credit-less agent.

    Returns ``(offer_id, resource_uri, agent_id)``. Post-t3vk, the
    legacy ``ramp.offers`` table was dropped (000006_drop_ye6f9_schema);
    the per-request offer surfaced by ``DiscoverResources`` is built
    from the catalog row via ``discover.go::buildOffer``. The catalog
    row's ``resource_id`` IS the canonical ``offer_id``. Default pricing
    is bumped to 500 minor (=5.00) USD so the billing gate has a
    non-trivial amount to refuse.

    SPOT (not SUBSCRIPTION) is deliberate: a SUBSCRIPTION offer would
    be gated upstream by ``authorizeAnonymousAccess`` with
    ``KindUnauthenticated`` on a missing biscuit — that refusal is
    the wrong failure family. The obligation here is specifically
    about a BUYER with no BILLING; the per-request path is the one
    where the billing gate would live.
    """
    suffix = uuid.uuid4().hex[:8]
    path = f"/premium/nobilling-{suffix}.html"
    content_id = f"res-nobilling-{suffix}"
    resource_uri = f"{EDGE_PUBLIC_URL}{path}"
    agent_id = _NOBILLING_AGENT_ID

    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=f"{_TENANT_ID}.local")
    _upsert_agent(dsn, agent_id=agent_id)
    _upsert_catalog_contributor(dsn, pubkey_bytes=load_public_key_bytes(CONTRIBUTOR_KEY_PATH))
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=EDGE_PUBLIC_HOST, path=path, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    _upsert_exchange(dsn, exchange_id=_EXCHANGE_ID, domain=_EXCHANGE_DOMAIN)
    _upsert_spot_offer(dsn, offer_id=content_id, resource_uri=resource_uri)
    try:
        yield content_id, resource_uri, agent_id
    finally:
        _delete_offer(dsn, content_id)


def _upsert_spot_offer(dsn: str, *, offer_id: str, resource_uri: str) -> None:
    """Stamp the catalog row at a non-trivial per-request rate.

    Post-t3vk, ``ramp.offers`` was dropped. The catalog row's
    pricing JSONB is updated to rate=5.00 USD (the seeded
    ``price_minor=500`` projected through the discover path's
    minor-units-to-rate convention). That's well above any seed
    credit the credit-less agent could hold, so a billing check
    that looked at reserved balance would refuse.
    """
    del resource_uri  # row is keyed by resource_id post-t3vk
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ramp.catalog
               SET pricing = jsonb_set(
                       jsonb_set(pricing, '{rate}', to_jsonb(%s::float)),
                       '{currency}', to_jsonb(%s::text)
                   ),
                   updated_at = NOW()
             WHERE resource_id = %s
            """,
            (5.0, "USD", offer_id),
        )
        conn.commit()


def _delete_offer(dsn: str, offer_id: str) -> None:  # noqa: ARG001 — kept for signature symmetry
    # ramp.offers no longer exists; tenant teardown removes catalog rows.
    return None


def _discover_offer_signature(exchange_url: str, *, resource_uri: str, agent_id: str) -> str:
    """Call DiscoverResources to obtain the Exchange-minted offer signature.

    validateTxRequest requires both ``offer_id`` AND ``offer_signature``
    before the billing gate is reached. We must discover first so the
    refusal at the billing layer (not the validator layer) is what
    the obligation observable measures.
    """
    discover_url = f"{exchange_url}{_DISCOVER_PATH}"
    resp = sign_post(
        discover_url,
        body={
            "requester": {
                "id": agent_id,
                "domain": f"{_TENANT_ID}.local",
                "uris": [resource_uri],
            },
        },
        key_path=AGENT_NOBILLING_KEY_PATH,
    )
    if resp.status_code != httpx.codes.OK:
        msg = (
            f"DiscoverResources must precede ExecuteTransaction; got "
            f"{resp.status_code}: {resp.text[:512]}"
        )
        raise AssertionError(msg)
    payload = resp.json()
    offers = payload.get("offers") or []
    if not offers:
        msg = f"DiscoverResources returned no offers for {resource_uri!r}"
        raise AssertionError(msg)
    signature = offers[0].get("signature") or ""
    if not signature:
        msg = f"discovered offer carries no signature: {offers[0]!r}"
        raise AssertionError(msg)
    return cast(str, signature)


def _post_execute_transaction_as_credit_less_agent(
    exchange_url: str,
    offer_id: str,
    agent_id: str,
    *,
    offer_signature: str,
) -> httpx.Response:
    """POST a signed ExecuteTransaction as the credit-less agent identity.

    The Exchange's resolveCaller reads the SIGNING kid and
    authorizeForAgent requires kid == requester.id, so the credit-less
    caller signs with its OWN key (kid == requester.id ==
    ``agent-nobilling-e2e``). That clears the caller-authz layer and lets
    the refusal land at the BILLING gate — the obligation observable. The
    ``X-RAMP-Agent-Id`` header is kept as an observability stub. The
    offer_signature is required by validateTxRequest before billing runs.
    """
    url = f"{exchange_url}{_ACCEPT_OFFER_PATH}"
    body: dict[str, object] = {
        "ver": "1.0",
        "id": f"tx-{uuid.uuid4().hex}",
        "offerId": offer_id,
        "offerSignature": offer_signature,
        "requester": {
            "id": agent_id,
            "domain": f"{_TENANT_ID}.local",
            "type": "REQUESTER_TYPE_AGENT",
        },
    }
    return sign_post(
        url,
        body=body,
        extra_headers={"X-RAMP-Agent-Id": agent_id},
        key_path=AGENT_NOBILLING_KEY_PATH,
    )


def _flatten_strings(obj: object, out: list[str]) -> None:
    """Walk a JSON-ish structure, collecting every string value found."""
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_strings(item, out)


def _explanation_haystack(resp: httpx.Response) -> str:
    """Lower-cased concat of every plausible refusal-reason carrier."""
    candidates: list[str] = [resp.text]
    try:
        payload = resp.json()
    except ValueError:
        return " ".join(candidates).lower()
    _flatten_strings(payload, candidates)
    return " ".join(candidates).lower()


def _leaked_signed_url(resp: httpx.Response) -> str | None:
    """Return the first canonical signed URL the response leaks, else None.

    A refusal MUST carry no signed URL. The canonical carrier is the top-level
    ``retrieval_endpoint`` (TransactionResponse field 18) and, for batch
    deliveries, each ``items[i].retrieval_endpoint`` (TxItem field 12). Both are
    checked so a leak on either surface fails the guard. This is the post-
    carrier-move replacement for the old ``ext['signed_url']`` check, which is
    now a dead slot the URL never lands in.
    """
    try:
        payload = resp.json()
    except ValueError:
        return None
    top = retrieval_endpoint_of(payload)
    if top:
        return top
    items = payload.get("items") if isinstance(payload, dict) else None
    if isinstance(items, list):
        for item in items:
            url = retrieval_endpoint_of(item)
            if url:
                return url
    return None


def _transaction_log_row_count_for_offer(dsn: str, offer_id: str) -> int:
    """Count ``ramp.transaction_log`` rows whose ``offer_id`` matches.

    The obligation demands no transaction row be persisted when the
    acceptance is refused. Scoping by ``offer_id`` is enough because
    each test run mints a fresh ``offer-nobilling-<suffix>`` — there
    is zero overlap with seeded happy-path rows.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM ramp.transaction_log WHERE offer_id = %s",
            (offer_id,),
        )
        row = cur.fetchone()
    if row is None:
        return 0
    return int(row[0])


def test_credit_less_agent_is_refused_with_billing_signal_and_no_url(
    compose_stack: StackURLs,
    spot_offer_without_billing: tuple[str, str, str],
) -> None:
    """No billing arrangement → refusal, billing-family reason, no URL, no row.

    Every assertion below traces directly to the scenario text and the
    team-lead-provided observables:

    1. ``response is NOT 200`` — "The agent cannot accept any offer"
       means ExecuteTransaction must not hand back a success.
    2. ``refusal reason contains a billing-family token`` — "the
       platform says so plainly." The refusal must carry one of
       ``billing`` / ``no credit`` / ``no arrangement`` / ``insufficient
       funds``, distinguishing this mode from the other failure
       families (expired / not granted / bad proof / unknown URI). A
       generic 401 ``CodeUnauthenticated`` with no billing signal does
       NOT satisfy the obligation.
    3. ``no signed URL issued`` — corollary of (1): even if the status
       leaked through as 2xx for some reason, no ``signedUrl`` must
       appear in the body.
    4. ``no transaction_log row persisted`` — the Exchange's ledger
       must not grow under a refused attempt; an orphan ACCEPTED /
       PENDING row for a buyer with no billing would contaminate
       downstream billing reconciliation.
    """
    offer_id, resource_uri, agent_id = spot_offer_without_billing

    # The validator requires offer_signature alongside offer_id; we
    # discover first so the refusal under test reaches the billing
    # gate (not the validator) — the obligation observable is the
    # billing-family refusal, not a missing-field error.
    offer_signature = _discover_offer_signature(
        compose_stack.exchange, resource_uri=resource_uri, agent_id=agent_id
    )

    resp = _post_execute_transaction_as_credit_less_agent(
        compose_stack.exchange,
        offer_id,
        agent_id,
        offer_signature=offer_signature,
    )

    # (1) Refusal — not HTTP 200.
    assert resp.status_code != httpx.codes.OK, (
        f"platform must refuse ExecuteTransaction for a buyer with no billing "
        f"arrangement (agent_id={agent_id!r}); got 200 with body "
        f"{resp.text[:512]!r}"
    )

    # (2) Refusal carries a billing-family explanation — "says so plainly".
    haystack = _explanation_haystack(resp)
    matched = next((token for token in _BILLING_REASON_TOKENS if token in haystack), None)
    assert matched is not None, (
        f"refusal must surface a billing-family reason (one of "
        f"{list(_BILLING_REASON_TOKENS)}) distinct from other failure "
        f"families; got status={resp.status_code}, body={resp.text[:512]!r}"
    )

    # (3) No signed URL in the payload regardless of status.
    issued_url = _leaked_signed_url(resp)
    assert issued_url is None, (
        f"refusal must NOT issue a signed URL on canonical retrieval_endpoint; "
        f"got {issued_url!r} in body={resp.text[:512]!r}"
    )

    # The body, if JSON, must parse — shape-check so a future change that
    # starts returning an unparseable body is caught by the inspection
    # path, not hidden behind an exception.
    try:
        payload: Any = resp.json()
    except json.JSONDecodeError:
        payload = None
    assert payload is None or isinstance(payload, dict), (
        f"ExecuteTransaction refusal body, if JSON, must be an object — got "
        f"{type(payload).__name__}: {payload!r}"
    )

    # (4) No transaction_log row persisted under the refused attempt.
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    row_count = _transaction_log_row_count_for_offer(dsn, offer_id)
    assert row_count == 0, (
        f"refusal must not persist a ramp.transaction_log row; found "
        f"{row_count} row(s) for offer_id={offer_id!r}"
    )
