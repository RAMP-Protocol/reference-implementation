"""Obligation 00 happy-path #3: the paid usage record shows one access with price, currency, timestamp.

Scenario (verbatim — the fourth happy-path bullet):

    After delivery, the agent reports the usage back to the platform. The
    buyer's usage record now shows one paid access with the resource URI,
    price, currency, and timestamp.

Driven against the demo ``epicurus`` resource (PER_UNIT 0.0001/characters USD)
as the USD demo buyer:

  1. Discover the offer; accept it (ExecuteTransaction → signed URL + billing_id).
  2. Fetch the signed URL through the Cloudflare edge (the "after delivery" half).
  3. Report the usage (ReportUsage) for the returned transaction_id.
  4. Read the ledger row + joined catalog URI and assert the four
     obligation-mandated observables: URI, non-zero price, currency, timestamp.

The buyer's usage record maps to ``ramp.transaction_log``. The ledger has no
protocol read surface by design (record-read/reporting is downstream
observability over the operator's datastore, out of RAMP's protocol scope —
scope), so the four-observable assertion reads the row directly via a join on
``ramp.catalog.uri``: a black-box e2e exception, observed on the deployment
datastore, not an in-process layer bypass (see the read site below).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import httpx
import psycopg
import pytest

from ..exchanges import recipient_of
from ..reporting import REPORT_USAGE_PATH, report_body
from ..conftest import COMPOSE_FILE, StackURLs
from ..edge_fetch import fetch_signed
from ..resolve_carriers import first_item_of, retrieval_endpoint_of
from ..seed import (
    DEMO_PHILOSOPHY_DOMAIN,
    USD_AGENT_ID,
    SeededFixture,
    _resolve_pg_dsn,
)
from ..signing import USD_AGENT_KEY_PATH, sign_post
from .flow import accept_offer, discover_first_offer

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "After delivery, the agent reports the usage back to the platform. "
    "The buyer's usage record now shows one paid access with the resource "
    "URI, price, currency, and timestamp."
)


# epicurus: PER_UNIT 0.0001/characters USD, individual, US/GB.
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"
_EXPECTED_UNIT_COST = Decimal("0.0001")
_CURRENCY = "USD"


def _post(url: str, body: dict[str, object]) -> httpx.Response:
    return sign_post(url, body=body, key_path=USD_AGENT_KEY_PATH)


def test_paid_usage_record_shows_uri_price_currency_and_timestamp(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Usage record for a paid demo access carries URI, non-zero price, currency, timestamp."""
    assert _OBLIGATION_TEXT  # traceability anchor

    # Discover the offer (with its Exchange-minted signature), then accept it.
    offer = discover_first_offer(
        compose_stack.exchange,
        uri=_RESOURCE_URI,
        agent_id=USD_AGENT_ID,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    # "After delivery" — accept and fetch.
    result = accept_offer(
        compose_stack.exchange,
        offer,
        agent_id=USD_AGENT_ID,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
    )
    # The EXECUTE response is an items[] envelope — read the
    # per-result fields (retrievalEndpoint, transactionId, billingId) from items[0].
    accept_payload = result.payload
    item = first_item_of(accept_payload)
    assert item is not None, f"accept response carried no items[0]: {accept_payload}"
    signed_url = retrieval_endpoint_of(item)
    transaction_id = item.get("transaction_id")
    billing_id = item.get("billing_id") or ""
    assert signed_url, f"signed URL missing from accept items[0]: {accept_payload}"
    assert transaction_id, f"transactionId missing from accept items[0]: {accept_payload}"
    assert billing_id, f"billingId missing from paid accept items[0]: {accept_payload}"

    # Fetch via the shared content-delivery seam: asserts 200 + the ACTUAL
    # delivered epicurus article (deploy/content/demo/stoa-press/.../epicurus.txt).
    # The accept-minted ed25519 URL is BOUND to the executing agent's thumbprint
    # (agent_id=); the edge enforces 3-way proof-of-possession on the GET, so we
    # present the SAME agent key the URL was bound to at execute time.
    fetch_signed(
        signed_url,
        compose_stack,
        expect_marker="Epicurus",
        timeout=15.0,
        key_path=USD_AGENT_KEY_PATH,
    )

    # "the agent reports the usage back" — and the report MUST be accepted.
    # epicurus carries no reporting obligation/estimate, so the consumed
    # quantity is reported as 0 (the validator strict-rejects a positive
    # quantity against a zero-estimate obligation).
    report_resp = _post(
        f"{compose_stack.exchange}{REPORT_USAGE_PATH}",
        report_body(
            exchange=recipient_of(compose_stack.exchange),
            transaction_id=str(transaction_id),
            agent_id=USD_AGENT_ID,
            domain=DEMO_PHILOSOPHY_DOMAIN,
            billing_id=str(billing_id or ""),
        ),
    )
    assert report_resp.status_code == httpx.codes.OK, (
        f"ReportUsage refused for transaction {transaction_id}: "
        f"{report_resp.status_code} {report_resp.text[:512]}"
    )
    # Acceptance is no longer an in-body flag (ADR-019 §2): a successful report
    # returns OK and carries the issued report_id; a rejection is a transport
    # error. The OK status above + a non-empty reportId is acceptance.
    assert report_resp.json().get("report_id"), (
        f"ReportUsage accepted but returned no reportId: {report_resp.text}"
    )

    # Read the ledger row + joined catalog URI. BLACK-BOX e2e exception:
    # the transaction ledger has NO protocol read surface BY
    # DESIGN — record-read/reporting is downstream observability over the
    # operator's datastore, out of RAMP's protocol scope (no read RPC will be
    # added). A full-stack e2e observing the deployment's datastore directly is
    # NOT the pt9 layer-bypass that rule forbids (an in-process test reaching
    # past a production layer); it is the only way to assert this ledger side
    # effect (URI / price / currency / timestamp) end-to-end.
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT t.transaction_id, t.unit_cost, t.currency, t.created_at, c.uri
            FROM ramp.transaction_log t
            JOIN ramp.catalog c ON c.resource_id = t.resource_id
            WHERE t.transaction_id = %s
            """,
            (transaction_id,),
        )
        rows = cur.fetchall()

    assert len(rows) == 1, f"expected exactly one ledger row for {transaction_id!r}, got {rows!r}"
    _db_txid, unit_cost, currency, created_at, catalog_uri = rows[0]

    # "with the resource URI"
    assert catalog_uri == _RESOURCE_URI, (
        f"joined catalog.uri must match the accepted URI {_RESOURCE_URI!r}; got {catalog_uri!r}"
    )
    # "price" — exact decimal equality against the term rate.
    assert isinstance(unit_cost, Decimal), (
        f"transaction_log.unit_cost must surface as Decimal; got {type(unit_cost).__name__}"
    )
    assert unit_cost == _EXPECTED_UNIT_COST, (
        f"unit_cost must equal the term rate {_EXPECTED_UNIT_COST!r}; got {unit_cost!r}"
    )
    # "currency"
    assert currency == _CURRENCY, f"currency must echo {_CURRENCY!r}; got {currency!r}"
    # "timestamp" — non-null and recent.
    assert created_at is not None, "transaction_log.created_at is NULL"
    now = datetime.now(tz=UTC)
    assert now - created_at < timedelta(minutes=5), (
        f"transaction_log.created_at = {created_at!r} is older than the test run (now = {now!r})"
    )
