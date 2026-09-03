"""Obligation 03, happy-1: browse leaves no record on the buyer.

Scenario (verbatim — the second happy-path bullet):

> An agent receives the offer list, decides nothing, and walks away.
> The buyer's usage record is unchanged. Resource-owner billing systems
> see no activity.

This asserts the read-only guarantee: a DiscoverResources call writes no
``ramp.transaction_log`` row. Driven against the demo ``epicurus`` resource as
the USD demo buyer. The transaction_log has no protocol read surface by design
(record-read/reporting is downstream observability over the operator's
datastore, out of RAMP's protocol scope), so this DELTA check reads
the ledger directly: a black-box e2e exception, observed on the deployment
datastore, not an in-process layer bypass (see ``_count_transaction_log_rows``).
It asserts a ZERO DELTA around the browse (other suites share the demo buyer, so
an absolute count is not meaningful).
"""

from __future__ import annotations


from typing import Any, cast

import httpx
import psycopg
import pytest

from ..exchanges import recipient_of
from ..discovery import discover_body
from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    DEMO_PHILOSOPHY_DOMAIN,
    USD_AGENT_ID,
    SeededFixture,
    _resolve_pg_dsn,
)
from ..signing import sign_post

pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent receives the offer list, decides nothing, and walks away. "
    "The buyer's usage record is unchanged. Resource-owner billing systems "
    "see no activity."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"


def _count_transaction_log_rows(dsn: str, *, agent_id: str) -> int:
    """Count ramp.transaction_log rows for the agent.

    BLACK-BOX e2e exception: the transaction ledger has NO
    protocol read surface BY DESIGN — record-read/reporting is downstream
    observability over the operator's datastore, out of RAMP's protocol scope,
    so no public read RPC will be added. A full-stack e2e observing the
    deployment's datastore directly is NOT the pt9 layer-bypass that rule
    forbids (an in-process test reaching past a production layer); it is the
    only way to assert this ledger side effect (here, its absence) end-to-end.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM ramp.transaction_log WHERE agent_id = %s", (agent_id,))
        row = cur.fetchone()
        return int(row[0]) if row else 0


def test_browse_writes_no_ledger_row(
    compose_stack: StackURLs,
    seeded: SeededFixture,  # noqa: ARG001 — ordering: seed ingests the demo catalog
) -> None:
    """A successful DiscoverResources does not write any ramp.transaction_log row."""
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    pre = _count_transaction_log_rows(dsn, agent_id=USD_AGENT_ID)

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
    # (a) browse succeeded
    assert resp.status_code == httpx.codes.OK, (
        f"browse must succeed against the demo URI; got {resp.status_code}: {resp.text[:512]}"
    )
    # (b) browse returned an offer the agent could have accepted
    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])
    assert offers, f"browse must surface at least one offer; body={resp.text[:512]}"

    # (c) browse wrote no ledger row — zero delta around the browse.
    post = _count_transaction_log_rows(dsn, agent_id=USD_AGENT_ID)
    assert post == pre, (
        f"browse must not write any ramp.transaction_log row; pre={pre} post={post} "
        f"(obligation 03: 'browse is a read-only operation. No ledger row is written.')"
    )
