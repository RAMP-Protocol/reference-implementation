"""Obligation 00 happy-path #3: the paid usage record shows one access with price, currency, and timestamp.

Obligation file: ``docs/obligations/00-access-a-paid-resource.md``.
Scenario (verbatim — the fourth happy-path bullet):

    After delivery, the agent reports the usage back to the platform. The
    buyer's usage record now shows one paid access with the resource URI,
    price, currency, and timestamp.

The "buyer's usage record" maps to Exchange's ``ramp.transaction_log``.
The ofxz ExecuteTransaction path (current location:
``src/exchange/internal/service/exchange.go::ExecuteTransaction``; the
historical ``execute_transaction.go`` file was deleted in W3 of t3vk, ``66b8312``)
writes the row with four columns that together satisfy the obligation:

* ``unit_cost`` — NUMERIC(20, 8) charge the Exchange billed per unit.
  ``offerUnitCost`` (post-t3vk W3 deletion 66b8312; equivalent unit-cost formatter under exchange_helpers.go::buildTxResponse) sets this from the SPOT
  offer's ``price_minor`` (``price_minor / 100``), so the stored value
  **MUST** be strictly greater than zero — this is the "price" the
  obligation demands.
* ``currency`` — NOT NULL column echoed verbatim from the catalog row's
  ``pricing.currency`` (post-t3vk; legacy ``ramp.offers.currency``).
  The obligation names "currency" as a first-class observable; a missing
  or blank currency would mean the buyer's ledger cannot be reconciled
  against an invoice.
* ``created_at`` — TIMESTAMPTZ with a ``DEFAULT NOW()`` clause
  (``src/exchange/internal/db/migrations/000001_init.up.sql:112``).
  The obligation names "timestamp" as a distinct field — without it
  the buyer cannot anchor the charge on a calendar.

The transaction_log.subscription_id column was dropped by migration
000007 (commit d9d774a, slice #1 e2k7h.8). The v1 spec has no
subscription path, so the "distinct from subscription sibling"
assertion this test used to carry is no longer meaningful and was
removed per diagnostic agentic-content-access-a9esw.1.

Post-a9esw.3 follow-up fixes carried in this same module
(``agentic-content-access-a9esw.4``):

  * Signed-URL host rewrite preserves the canonical signature payload.
    The Exchange signs ``GET\\n<URL>`` over the FULL URL (scheme + host
    + path + query — see ``src/exchange/internal/signing/signed_url.go``
    ``SignURL``); the edge mirrors that canonicalization
    (``src/edge/src/verify.ts::canonicalMessage``). When the test runs
    OUTSIDE the compose network it must point httpx at the host-published
    port AND stamp a ``Host: edge:8787`` header so Workerd reconstructs
    ``c.req.url = http://edge:8787/...`` — keeping the canonical payload
    byte-identical to what the Exchange signed. Without the Host header
    the verifier sees ``http://127.0.0.1:NNNN/...`` and returns
    ``403 signature_mismatch``.
  * The fixture pins ``/paid/usage.html`` (a real file under
    ``tests/e2e/mock-publisher/content/paid/``) as the publisher path
    instead of inventing a per-run path the publisher's nginx cannot
    serve. The pin keeps the URI distinct from the session-wide
    ``seed_stack`` row's ``/premium/article-42.html`` so the
    ``CatalogSnapshot`` trie's longest-prefix Lookup returns this
    test's catalog row (not the seed_stack default).
  * ``_trigger_snapshot_rebuild`` follows ``_upsert_spot_offer`` to
    force the in-memory catalog snapshot to reload from Postgres. The
    snapshot only rebuilds on a successful ``PushResources`` RPC
    (``CatalogService.rebuild`` is private); a bare SQL UPDATE to
    ``ramp.catalog.pricing`` therefore stays invisible to discover /
    execute until a separate push triggers the reload.
  * The fixture purges this test's tenant scope (catalog +
    transaction_log) before seeding so reruns are idempotent: the
    URI-keyed trie keeps last-inserter-wins semantics, so accumulated
    rows at the same URI would let the offer ExecuteTransaction loads
    by PK diverge from the row discover signed against, surfacing as
    ``401 offer signature invalid``.

The obligation names "resource URI" as a first-class field. Post-t3vk
(``ramp.offers`` dropped in migration 000006_drop_ye6f9_schema) the
persistTransaction logic (``exchange.go::persistTransaction``, line
410) writes ``transaction_log.resource_id`` referencing
``ramp.catalog.resource_id``; the canonical URI for the transaction
therefore lives on ``ramp.catalog.uri``, joined via ``resource_id``.
The assertion reads the URI through that join so the ledger's URI
field is grounded in the post-t3vk catalog row, not the legacy offers
table.

Flow exercised end-to-end against the compose stack:

  1. Seed a SPOT offer over a fresh catalog entry at a non-zero price.
  2. Accept the SPOT offer (ExecuteTransaction) → Exchange returns a signed URL
     AND writes the transaction_log row.
  3. Fetch the signed URL through the edge — closes the delivery half of
     the scenario ("After delivery...").
  4. Report the usage (ReportUsage) for the returned transaction_id.
     The scenario text says "the agent reports the usage back"; the
     report call MUST be accepted (HTTP 200) or the obligation is not
     met.
  5. Read ``ramp.transaction_log`` joined with ``ramp.catalog`` and
     assert on the four obligation-mandated observables: URI, non-zero
     price, currency, non-null timestamp — plus ``COUNT = 1`` (one paid
     access, not two).

Post-t3vk wire-format sweep (slh5):

The originally cited xfail gates were closed post-t3vk
(``exchangeGlobalSigPathPredicate`` renamed and relaxed,
``execute_transaction.go`` deleted in W3 ``66b8312``). The remaining
gaps closed by THIS sweep:

  * Signed-URL extraction reads the canonical top-level
    ``retrievalEndpoint`` (``TransactionResponse.retrieval_endpoint``,
    field 18) and asserts the legacy ``ext['signed_url']`` carrier is
    gone. ``buildTxResponse`` (``exchange_helpers.go``) sets the field
    directly; the prior ``ext['signed_url']`` Struct slot was removed.
  * Fixture migrated from ``INSERT INTO ramp.offers`` (dropped in
    migration 000006_drop_ye6f9_schema) to ``UPDATE ramp.catalog ...
    jsonb_set(pricing, '{rate}', ...)``; the catalog row's
    ``resource_id`` IS the canonical offer_id surfaced by
    DiscoverResources / consumed by ExecuteTransaction.
  * Ledger join now reads the URI from ``ramp.catalog.uri`` joined on
    ``transaction_log.resource_id`` (legacy ``ramp.offers`` is gone).

P2.00 audit note (pizh, against canonical proto at ramp.proto):

* RPC paths: ExecuteTransaction (ramp.proto:119) and ReportUsage
  (ramp.proto:123) — both canonical.
* ExecuteTransaction request payload ``{"offerId": ...}`` is
  canonical (``TransactionRequest.offer_id``).
* ReportUsage request payload uses ``ver``, ``id``, ``transactionId``,
  ``billingId``, ``usage.consumedQuantity``, ``usage.function`` —
  all canonical (``UsageReport.ver`` ramp.proto:1433,
  ``UsageReport.id`` ramp.proto:1436,
  ``UsageReport.transaction_id`` ramp.proto:1439,
  ``UsageReport.billing_id`` ramp.proto:1442,
  ``Usage.consumed_quantity`` ramp.proto:1501,
  ``Usage.function`` ramp.proto:1492).
* Response ``transactionId`` is canonical ``transaction_id``
  (ramp.proto:1189).
* Response ``report_payload.get('accepted')`` matches canonical
  ``UsageReportResponse.accepted`` (ramp.proto:1527).
* ``_OBLIGATION_TEXT`` quotes the obligation 00 fourth happy-path
  bullet verbatim (``docs/obligations/00-access-a-paid-resource.md``).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
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
    SeededFixture,
    _resolve_pg_dsn,
    _set_allow_broker_relay,
    _upsert_agent,
    _upsert_catalog_contributor,
    _upsert_exchange,
    _upsert_tenant_ed25519,
    seed_stack,
)
from ..relay import relay_execute
from ..signing import (
    AGENT_E2E_KEY_PATH,
    build_pop_headers,
    sign_post,
)
from .carriers import assert_signed_url

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "After delivery, the agent reports the usage back to the platform. "
    "The buyer's usage record now shows one paid access with the resource "
    "URI, price, currency, and timestamp."
)

_REPORT_USAGE_PATH = "/ramp.v1.ExchangeService/ReportUsage"

# Per-test tenant — the COUNT=1 assertion wants the ledger scoped so
# parallel test modules sharing the compose stack cannot add spurious
# rows. A dedicated tenant_id keyed by the obligation id keeps this
# module hermetic.
_TENANT_ID = "tenant-e2e-ob00-usage"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
# The compose stack's EXCHANGE_BILLING_SEED (docker-compose.e2e.yml) credits
# agent-e2e with $100; any other agent_id hits the billing gate's "unknown
# agent" refusal. The per-test tenant keeps catalog isolation; the agent
# identifier is the stack-wide seeded one so the accept step reaches the
# transaction log (the obligation observable).
_AGENT_ID = "agent-e2e"
_EXCHANGE_ID = "mp-e2e-ob00-usage"
_EXCHANGE_DOMAIN = "exchange.ob00-usage.local"

# SPOT price in minor units — must be non-zero to satisfy the
# obligation's "price" observable. 50 minor = $0.50, which surfaces as
# 0.50000000 in the NUMERIC(20, 8) column. The value is kept small so
# the per-test charge does not deplete the demo-stack's
# EXCHANGE_BILLING_SEED budget for agent-e2e ($100) across repeated
# test runs within one compose-up window (200 runs at $0.50/run).
_SPOT_PRICE_MINOR = 50
_SPOT_CURRENCY = "USD"
# Reporting obligation estimate. ReportUsage's protocol validator strict-rejects
# a positive consumed quantity against a zero-estimate obligation
# (report_validator.go: "consumed quantity N reported against zero-estimate
# obligation"). The catalog pricing's estimated_quantity flows offer →
# obligation (discover.go::buildOffer → exchange.go), so seed it equal to the
# consumed quantity this test reports (1) — diff 0 is within the ±20% tolerance.
_SPOT_ESTIMATED_QUANTITY = 1


def _upsert_spot_offer(
    dsn: str,
    *,
    offer_id: str,
    resource_url: str,
    publisher_slug: str,
) -> None:
    """Stamp the catalog row at the seeded non-zero per-request rate.

    Post-t3vk, ``ramp.offers`` was dropped (migration
    000006_drop_ye6f9_schema). The per-request offer surfaced by
    DiscoverResources is built from the catalog row via
    ``discover.go::buildOffer``; we override the default rate so
    ``_SPOT_PRICE_MINOR / 100`` is what the billing path charges. The
    catalog row's ``resource_id`` IS the canonical offer_id surfaced
    by DiscoverResources, so the test passes ``resource_id`` as
    ``offer_id`` here.

    The catalog's in-memory snapshot is only rebuilt on a successful
    ``PushResources`` call (``CatalogService.rebuild`` is private), so
    a bare SQL UPDATE to ``ramp.catalog.pricing`` is invisible to
    ``DiscoverResources`` / ``ExecuteTransaction`` — they keep serving
    the pre-update pricing from the cached snapshot. To make the
    update visible the caller must invoke ``_trigger_snapshot_rebuild``
    after this call.

    SPOT offers are not gated by biscuit coverage, so no
    ``required_scope`` shape needs to be carried — that field is part
    of the legacy offer model and no longer relevant to the catalog
    row.
    """
    del resource_url, publisher_slug  # row is keyed by resource_id post-t3vk
    rate = float(_SPOT_PRICE_MINOR) / 100.0
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        # Stamp rate + unit_cost + currency in lockstep. ``buildTxResponse``
        # (src/exchange/internal/service/exchange_helpers.go:163) reads
        # ``pricing.unit_cost`` (NOT ``pricing.rate``) to compute the
        # transaction_log.unit_cost the obligation asserts on, so an
        # update that touches only ``rate`` leaves the unit_cost at the
        # ``defaultPricing`` value (0.05) and silently misses the seeded
        # SPOT price.
        cur.execute(
            """
            UPDATE ramp.catalog
               SET pricing = jsonb_set(
                       jsonb_set(
                           jsonb_set(
                               jsonb_set(pricing, '{rate}', to_jsonb(%s::float)),
                               '{unit_cost}', to_jsonb(%s::float)
                           ),
                           '{currency}', to_jsonb(%s::text)
                       ),
                       '{estimated_quantity}', to_jsonb(%s::int)
                   ),
                   updated_at = NOW()
             WHERE resource_id = %s
            """,
            (rate, rate, _SPOT_CURRENCY, _SPOT_ESTIMATED_QUANTITY, offer_id),
        )
        conn.commit()


def _trigger_snapshot_rebuild(
    exchange_url: str,
    tenant_id: str,
) -> None:
    """Force the Exchange to reload its catalog snapshot from Postgres.

    The catalog snapshot is an in-memory radix trie rebuilt only on a
    successful ``PushResources`` RPC (``CatalogService.PushResources``
    -> ``CatalogService.rebuild``). A bare SQL UPDATE to
    ``ramp.catalog.pricing`` therefore stays invisible to subsequent
    discover/execute calls until something triggers a rebuild.

    To get the SQL-side pricing edits into the snapshot WITHOUT
    overwriting the row we just edited (``PushResources`` re-stamps
    the default pricing from ``defaultPricing`` for any entry it
    accepts — see ``catalog.go::entryFromProto``), we push a SEPARATE
    throwaway entry under a non-colliding ``content_id``. The
    rebuild reads ALL rows from ``ramp.catalog`` and re-inserts them
    into the trie, so the edited row's new pricing surfaces in the
    snapshot.
    """
    push_catalog(
        exchange_url=exchange_url,
        tenant_id=tenant_id,
        entries=[
            CatalogEntry(
                domain=EDGE_PUBLIC_HOST,
                path=f"/sentinel/{uuid.uuid4().hex[:8]}.html",
                content_id=f"res-rebuild-sentinel-{uuid.uuid4().hex[:8]}",
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )


def _delete_spot_offer(dsn: str, offer_id: str) -> None:  # noqa: ARG001 — kept for signature symmetry
    # ramp.offers no longer exists; tenant teardown removes catalog rows.
    return None


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Reuse the session-wide stack seed (catalog contributor)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def spot_offer(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> Iterator[tuple[str, str]]:
    """Seed a SPOT offer at a non-zero price over a fresh catalog entry.

    Returns ``(offer_id, resource_uri)``. Teardown removes the offer row
    so repeated test sessions stay hermetic.
    """
    del seeded  # Fixture order only — stack-wide seed registers contributor.
    suffix = uuid.uuid4().hex[:8]
    # Pin a publisher path that the mock publisher actually serves with
    # the ``content-marker-42`` body and that is DISTINCT from the
    # session-wide seed_stack URI (``/premium/article-42.html``). Two
    # catalog rows sharing the same URI collide at the
    # ``CatalogSnapshot.Lookup`` trie (longest-prefix returns ONE entry),
    # and the discover would surface seed_stack's ``res-e2e-1`` (default
    # 0.05 USD pricing) instead of this test's seeded SPOT row — silently
    # asserting against the wrong unit_cost. ``/paid/usage.html`` is
    # static content under ``tests/e2e/mock-publisher/content/paid/`` so
    # the edge's pass-to-origin step returns the marker body cleanly.
    path = "/paid/usage.html"
    # Post-t3vk: catalog row's resource_id IS the offer_id surfaced by
    # DiscoverResources (legacy ramp.offers dropped in 000006).
    resource_id = f"res-paid-usage-{suffix}"
    resource_uri = f"{EDGE_PUBLIC_URL}{path}"

    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    # Purge prior runs' catalog + transaction_log rows for our tenant.
    # Each rerun pushes a NEW catalog row (suffix-keyed resource_id) at
    # the same URI; without this purge the catalog accumulates competing
    # rows sharing the URI, the ``CatalogSnapshot`` trie keeps whichever
    # row was last inserted at rebuild time, and the offer_id discover
    # returns no longer matches the row ExecuteTransaction loads by PK —
    # surfacing as a 401 ``offer signature invalid``. The COUNT=1
    # invariant the test asserts on also requires the ledger to start
    # empty for this tenant. Module-scoped — runs once per pytest
    # invocation, not per assertion.
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM ramp.transaction_log WHERE tenant_id = %s", (_TENANT_ID,))
        cur.execute("DELETE FROM ramp.catalog WHERE tenant_id = %s", (_TENANT_ID,))
        conn.commit()
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _set_allow_broker_relay(dsn, tenant_id=_TENANT_ID)
    _upsert_agent(dsn, agent_id=_AGENT_ID)
    _upsert_catalog_contributor(dsn, pubkey_bytes=load_public_key_bytes(CONTRIBUTOR_KEY_PATH))
    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(
                domain=EDGE_PUBLIC_HOST,
                path=path,
                content_id=resource_id,
            ),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    _upsert_exchange(dsn, exchange_id=_EXCHANGE_ID, domain=_EXCHANGE_DOMAIN)
    _upsert_spot_offer(
        dsn,
        offer_id=resource_id,
        resource_url=resource_uri,
        publisher_slug=EDGE_PUBLIC_HOST,
    )
    # Force the catalog snapshot to reload from Postgres so the SQL
    # UPDATE above (``_upsert_spot_offer``) actually surfaces through
    # DiscoverResources / ExecuteTransaction. Without this, discover
    # returns the pre-update pricing the snapshot was built with.
    _trigger_snapshot_rebuild(compose_stack.exchange, _TENANT_ID)
    try:
        yield resource_id, resource_uri
    finally:
        _delete_spot_offer(dsn, resource_id)


def _post_report_usage(exchange_url: str, transaction_id: str, billing_id: str) -> httpx.Response:
    """POST a signed ReportUsage to the Exchange for ``transaction_id``.

    ``billing_id`` MUST echo the value carried on the ExecuteTransaction
    response: ReportUsage's validator rejects a report whose billing_id does
    not match the transaction's assigned billing_id
    (report_validator.go::validateBillingID). ``consumedQuantity`` equals the
    offer's seeded estimated_quantity so the ±20% tolerance check passes.
    """
    body: dict[str, Any] = {
        "ver": "1.0",
        "id": f"report-{uuid.uuid4().hex}",
        "transactionId": transaction_id,
        "billingId": billing_id,
        "usage": {"consumedQuantity": 1, "function": ["ai_input"]},
        "requester": {
            "id": _AGENT_ID,
            "domain": _TENANT_DOMAIN,
            "type": "REQUESTER_TYPE_AGENT",
        },
    }
    return sign_post(f"{exchange_url}{_REPORT_USAGE_PATH}", body=body, key_path=AGENT_E2E_KEY_PATH)


def test_paid_usage_record_shows_uri_price_currency_and_timestamp(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — fixture order (stack seed)
    spot_offer: tuple[str, str],
) -> None:
    """Usage record for a paid access carries URI, non-zero price, currency, timestamp.

    Every assertion traces to the scenario text:

      - "After delivery" — the agent fetches the signed URL through the
        edge and the content is delivered (HTTP 200 with the publisher's
        ``content-marker-42``). Without delivery the scenario is not
        reached; the obligation says "after delivery".
      - "the agent reports the usage back" — a ReportUsage call is
        POSTed to ``/ramp.v1.ExchangeService/ReportUsage`` for the
        transaction_id returned by ExecuteTransaction. The call MUST be
        accepted (HTTP 200 and ``accepted: true``); a refused report
        leaves the obligation unsatisfied.
      - "one paid access" — exactly one ``transaction_log`` row exists
        for this test's tenant (COUNT = 1 scoped by ``tenant_id``).
      - "with the resource URI" — the joined ``ramp.catalog.uri``
        (via ``transaction_log.resource_id`` = ``catalog.resource_id``)
        matches the URI the agent accepted.
      - "price" — ``unit_cost`` exactly equals the seeded SPOT
        price (``_SPOT_PRICE_MINOR / 100`` = ``12.99``). The
        obligation names "price" as a first-class observable; a
        ``> 0`` check would silently pass under any non-zero value
        — including a wrong charge — so the assertion uses exact
        decimal equality against the seed. ``offerUnitCost``
        (post-t3vk W3 deletion 66b8312; equivalent under exchange_helpers.go::buildTxResponse) renders ``price_minor / 100`` as
        ``"12.99000000"``, which psycopg surfaces as
        ``Decimal("12.99000000")``; comparing as ``Decimal`` is
        exact and ignores trailing-zero noise.
      - "currency" — the currency column carries the non-empty code
        seeded on the offer (``USD``). A NULL/blank currency would
        mean the ledger cannot be reconciled against any invoice.
      - "timestamp" — ``created_at`` is non-NULL (the column is
        NOT NULL with ``DEFAULT NOW()``) and recent (within the last
        five minutes — wall-clock of the test run). The obligation
        file's "Why it matters" stresses buyers anchoring charges on
        a calendar; a missing or absurdly old timestamp breaks that.
    """
    assert _OBLIGATION_TEXT  # traceability anchor for the obligation matrix
    offer_id, resource_uri = spot_offer

    # Phase 1: Discovery via Broker.resolve — get offer with exchange_endpoint
    # ExecuteTransaction validateTxRequest requires both offer_id AND
    # offer_signature. Broker.resolve returns offers in ext.ramp.broker.offers
    # with exchange_endpoint for relay routing.
    discover_resp = sign_post(
        f"{compose_stack.broker}/broker/v1/resolve",
        body={
            "ver": "1.0",
            "id": f"rampreq-{uuid.uuid4().hex}",
            "requester": {
                "id": _AGENT_ID,
                "uris": [resource_uri],
            },
        },
        key_path=AGENT_E2E_KEY_PATH,
    )
    assert discover_resp.status_code == httpx.codes.OK, (
        f"Broker.Resolve must precede ExecuteTransaction; got "
        f"{discover_resp.status_code}: {discover_resp.text[:512]}"
    )
    discover_payload = cast(dict[str, Any], discover_resp.json())
    ext = discover_payload.get("ext", {})
    offers = ext.get("ramp.broker.offers", [])
    assert offers, f"Broker.Resolve returned no offers for {resource_uri!r}"
    offer = offers[0]
    offer_signature = cast(str, offer.get("signature") or "")
    exchange_endpoint = cast(str, offer.get("exchange_endpoint") or "")
    assert offer_signature, f"discovered offer carries no signature: {offer!r}"
    assert exchange_endpoint, f"discovered offer carries no exchange_endpoint: {offer!r}"

    # Phase 2: Execute via Broker relay — agent signs with Exchange URL, POSTs to Broker
    # RAMP-56 two-phase: agent sig1 + broker sig2 (multisig). Exchange verifies both
    # and binds delivery URL to agent's proven key.
    accept_resp = relay_execute(
        broker_url=compose_stack.broker,
        exchange_endpoint=exchange_endpoint,
        agent_id=_AGENT_ID,
        offer_id=offer_id,
        offer_signature=offer_signature,
        domain=_TENANT_DOMAIN,
    )
    assert accept_resp.status_code == httpx.codes.OK, (
        f"ExecuteTransaction via broker relay should succeed for SPOT offer {offer_id!r}, got "
        f"{accept_resp.status_code}: {accept_resp.text[:512]}"
    )
    accept_payload = cast(dict[str, Any], accept_resp.json())
    # Canonical signed-URL carrier: top-level retrieval_endpoint (field 18);
    # legacy ext['signed_url'] carrier gone.
    signed_url = assert_signed_url(accept_payload)
    transaction_id = accept_payload.get("transactionId")
    # ReportUsage's validator requires the report's billing_id to match the
    # one the transaction was assigned (report_validator.go::validateBillingID);
    # a paid offer always carries a non-empty billing_id on the response.
    billing_id = accept_payload.get("billingId") or accept_payload.get("billing_id") or ""
    assert transaction_id, f"transactionId missing from accept response: {accept_payload}"
    assert billing_id, f"billingId missing from paid accept response: {accept_payload}"

    # Rewrite the internal edge host when the test runs outside the
    # compose network. The Exchange signs the canonical message
    # `GET\n<URL>` over the FULL URL — scheme + host + path + query
    # (see src/exchange/internal/signing/signed_url.go::SignURL and the
    # edge mirror src/edge/src/verify.ts::canonicalMessage). The signed
    # URL therefore carries the compose-internal host `edge:8787` in
    # the canonical payload. Host-side fetches must therefore (a)
    # target the host-published port so the TCP socket resolves, AND
    # (b) carry a `Host: edge:8787` header so Workerd reconstructs
    # `c.req.url = http://edge:8787/...` for the verifier — keeping
    # the canonical payload byte-identical to what the Exchange signed.
    # In-network mode (RAMP_E2E_IN_NETWORK=1) is the trivial case where
    # both endpoints already agree on the host; the rewrite is a no-op.
    host_signed_url = signed_url
    extra_headers: dict[str, str] = {}
    if compose_stack.edge != EDGE_PUBLIC_URL:
        host_signed_url = signed_url.replace(EDGE_PUBLIC_URL, compose_stack.edge)
        extra_headers["Host"] = EDGE_PUBLIC_HOST

    # Add proof-of-possession headers for identity binding verification (ADR-013)
    pop_headers = build_pop_headers(url=signed_url)
    extra_headers.update(pop_headers)

    content_resp = httpx.get(
        host_signed_url,
        headers=extra_headers,
        follow_redirects=True,
        timeout=15.0,
    )
    assert content_resp.status_code == httpx.codes.OK, (
        f"signed URL fetch failed: {content_resp.status_code} {content_resp.text[:256]}"
    )
    assert "content-marker-42" in content_resp.text, (
        f"publisher content missing marker: {content_resp.text[:256]}"
    )

    # "the agent reports the usage back" — and the report MUST be accepted.
    report_resp = _post_report_usage(compose_stack.exchange, transaction_id, billing_id)
    assert report_resp.status_code == httpx.codes.OK, (
        f"ReportUsage refused for transaction {transaction_id}: "
        f"{report_resp.status_code} {report_resp.text[:512]}"
    )
    report_payload = cast(dict[str, Any], report_resp.json())
    assert report_payload.get("accepted") is True, f"ReportUsage did not accept: {report_payload}"

    # Read the ledger row plus the joined catalog URI in one query so
    # there is no race between a second fetch and the platform.
    # Post-t3vk: ``transaction_log.resource_id`` references
    # ``ramp.catalog.resource_id`` (legacy ramp.offers dropped in
    # migration 000006_drop_ye6f9_schema); the canonical URI lives on
    # ``ramp.catalog.uri``.
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.transaction_id,
                   t.unit_cost,
                   t.currency,
                   t.created_at,
                   c.uri
            FROM ramp.transaction_log t
            JOIN ramp.catalog c ON c.resource_id = t.resource_id
            WHERE t.tenant_id = %s
            """,
            (_TENANT_ID,),
        )
        rows = cur.fetchall()

    # "one paid access" — exactly one ledger row scoped to this
    # test's tenant. Anything else means either the accept wrote
    # more than once or another test leaked into our tenant.
    assert len(rows) == 1, (
        f"expected exactly one transaction_log row for tenant "
        f"{_TENANT_ID!r}, got {len(rows)}: {rows!r}"
    )
    (
        db_transaction_id,
        unit_cost,
        currency,
        created_at,
        catalog_uri,
    ) = rows[0]

    assert db_transaction_id == transaction_id, (
        f"single row for tenant {_TENANT_ID!r} points at a different "
        f"transaction: {db_transaction_id!r} vs {transaction_id!r}"
    )

    # "with the resource URI" — the joined catalog.uri is the URI the
    # agent accepted.
    assert catalog_uri == resource_uri, (
        f"joined catalog.uri must match the accepted URI {resource_uri!r}; got {catalog_uri!r}"
    )

    # "price" — unit_cost MUST equal the seeded SPOT price exactly.
    # ``offerUnitCost`` (post-t3vk W3 deletion 66b8312; equivalent under exchange_helpers.go::buildTxResponse) renders
    # ``price_minor / 100`` as ``"12.99000000"`` for the seed; the
    # NUMERIC(20, 8) column surfaces to psycopg as
    # ``decimal.Decimal``. Comparing as ``Decimal`` is exact and
    # ignores trailing-zero noise (``Decimal("12.99")`` ==
    # ``Decimal("12.99000000")``). A ``> 0`` check would silently
    # pass under ANY non-zero charge — including a wrong one — so
    # the obligation's "price" observable demands exact equality.
    expected_unit_cost = Decimal(_SPOT_PRICE_MINOR) / Decimal(100)
    assert isinstance(unit_cost, Decimal), (
        f"transaction_log.unit_cost must surface as decimal.Decimal "
        f"from psycopg; got {type(unit_cost).__name__}: {unit_cost!r}"
    )
    assert unit_cost == expected_unit_cost, (
        f"transaction_log.unit_cost must equal the seeded SPOT price "
        f"{expected_unit_cost!r} (price_minor={_SPOT_PRICE_MINOR}); "
        f"got {unit_cost!r}"
    )

    # "currency" — non-empty code matching what was seeded on the offer.
    assert currency == _SPOT_CURRENCY, (
        f"transaction_log.currency must echo the offer currency "
        f"{_SPOT_CURRENCY!r}; got {currency!r}"
    )

    # "timestamp" — non-null and recent. The DEFAULT NOW() clause
    # guarantees the row is stamped at insert time; asserting a
    # five-minute window catches clock-skew bugs without being flaky
    # under slow CI.
    assert created_at is not None, (
        "transaction_log.created_at is NULL — the obligation's "
        "timestamp field has no value on this row"
    )
    now = datetime.now(tz=UTC)
    assert now - created_at < timedelta(minutes=5), (
        f"transaction_log.created_at = {created_at!r} is older than "
        f"the test run (now = {now!r}); the timestamp field does not "
        f"anchor this charge to the current buyer session"
    )
