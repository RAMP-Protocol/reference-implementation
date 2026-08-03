"""Obligation 03, failure-4: transient unreachability followed by a retry.

Scenario (verbatim — the sole failure-mode bullet):

> The platform is unreachable. The agent's browse call returns a
> transient failure. Retrying later succeeds.

Driven against the demo ``epicurus`` resource as the USD demo buyer:

1. A POST to an unused loopback port raises ``httpx.ConnectError`` (the
   transport-level "platform unreachable").
2. The same DiscoverResources retried against the healthy Exchange returns 200
   with the seeded epicurus offer.
3. Read-only guarantee: neither attempt writes a ``ramp.transaction_log`` row
   (asserted as a zero DELTA observed directly on the deployment datastore — a
   black-box e2e exception; the ledger has no protocol read surface by design,
   see ``_count_transaction_rows``).
"""

from __future__ import annotations

import uuid

import httpx
import psycopg
import pytest

from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    DEMO_PHILOSOPHY_DOMAIN,
    USD_AGENT_ID,
    SeededFixture,
    _resolve_pg_dsn,
)
from ..signing import USD_AGENT_KEY_PATH, sign_post

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_LIST_OFFERS_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"
_EXPECTED_OFFER_ID = f"tenant-demo-philosophy:{_RESOURCE_URI}"

# A deliberately unused loopback port → ECONNREFUSED.
_UNREACHABLE_URL = "http://127.0.0.1:19999"


def _count_transaction_rows(dsn: str) -> int:
    """Count transaction_log rows for the USD demo buyer.

    BLACK-BOX e2e exception: the transaction ledger has NO
    protocol read surface BY DESIGN — record-read/reporting is downstream
    observability over the operator's datastore, out of RAMP's protocol scope,
    so no public read RPC will be added. A full-stack e2e observing the
    deployment's datastore directly is NOT the pt9 layer-bypass that rule
    forbids (an in-process test reaching past a production layer); it is the
    only way to assert this ledger side effect (here, its absence) end-to-end.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM ramp.transaction_log WHERE agent_id = %s", (USD_AGENT_ID,)
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0


def test_unreachable_browse_raises_transient_then_retry_succeeds(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """Unreachable first attempt raises a transient error; retry succeeds; browse is read-only."""
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    rows_before = _count_transaction_rows(dsn)

    body = {
        "id": f"q-{uuid.uuid4().hex}",
        "requester": {
            "id": USD_AGENT_ID,
            "domain": DEMO_PHILOSOPHY_DOMAIN,
            "type": "REQUESTER_TYPE_AGENT",
            "user_type": "individual",
            "geography": "US",
        },
        "uris": [_RESOURCE_URI],
    }

    # (1)+(2) Unreachable attempt → transport-level ConnectError.
    with pytest.raises(httpx.ConnectError) as excinfo:
        httpx.post(f"{_UNREACHABLE_URL}{_LIST_OFFERS_PATH}", json=body, timeout=5.0)
    assert excinfo.value is not None, "expected httpx.ConnectError"

    rows_after_unreachable = _count_transaction_rows(dsn)
    assert rows_after_unreachable == rows_before, (
        "browse is read-only and the unreachable attempt never landed on the platform"
    )

    # (3) Retry against the healthy Exchange surfaces the seeded offer.
    retry_resp = sign_post(
        f"{compose_stack.exchange}{_LIST_OFFERS_PATH}", body=body, key_path=USD_AGENT_KEY_PATH
    )
    assert retry_resp.status_code == httpx.codes.OK, (
        f"retry against the healthy Exchange must succeed, got "
        f"{retry_resp.status_code}: {retry_resp.text[:512]}"
    )
    retry_payload = retry_resp.json()
    assert isinstance(retry_payload, dict), (
        f"retry body must be JSON object: {retry_resp.text[:256]}"
    )
    offers = retry_payload.get("offers") or []
    offer_ids = {o.get("offer_id") for o in offers if isinstance(o, dict)}
    assert _EXPECTED_OFFER_ID in offer_ids, (
        f"retry must surface the seeded offer {_EXPECTED_OFFER_ID!r}; got {sorted(o for o in offer_ids if o)}"
    )

    # (4) Still read-only after a successful browse retry.
    rows_after_retry = _count_transaction_rows(dsn)
    assert rows_after_retry == rows_before, (
        "browse is read-only and must not write a transaction_log row even on success"
    )
