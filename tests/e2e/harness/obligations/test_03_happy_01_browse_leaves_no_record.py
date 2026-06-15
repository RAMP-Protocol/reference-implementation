"""Obligation 03, happy-1: browse leaves no record on the buyer.

Obligation file: ``docs/obligations/03-browse-offers-without-committing.md``.

Scenario (verbatim — the second happy-path bullet):

> An agent receives the offer list, decides nothing, and walks away.
> The buyer's usage record is unchanged. Resource-owner billing systems
> see no activity.

The obligation file's "Implementation hints" section underlines this:

> For test authors: browse is a read-only operation. No ledger row is
> written. If the same agent then accepts an offer from the browse
> result, the acceptance is a separate observable event and writes
> exactly one ledger row.

This test asserts the read-only guarantee directly: it queries the
post-browse state of ``ramp.transaction_log`` (the authoritative ledger
the platform consults when answering "did this buyer transact?") and
asserts no row exists for the agent that did the browse. The
``ramp.transaction_log`` is the table ``ExecuteTransaction`` writes to
on acceptance, scoped by ``tenant_id`` + ``agent_id``. A row keyed by
the test's per-test (tenant, agent) pair would be a side effect of the
browse — exactly the property the obligation forbids.

Assertions:

(a) DiscoverResources succeeds (200) for the seeded URI.
(b) Browse returns an offer the agent could have accepted.
(c) After the browse, ``ramp.transaction_log`` contains zero rows
    keyed by the test's (tenant_id, agent_id). This is asserted
    against the running compose Postgres directly.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any, cast

import httpx
import psycopg
import pytest

from ..catalog_push import CatalogEntry, push_catalog
from ..conftest import COMPOSE_FILE, StackURLs
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    EDGE_PUBLIC_HOST,
    EDGE_PUBLIC_URL,
    SeededFixture,
    _resolve_pg_dsn,
    _upsert_agent,
    _upsert_tenant_ed25519,
    seed_stack,
)
from ..signing import sign_post


pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_OBLIGATION_TEXT = (
    "An agent receives the offer list, decides nothing, and walks away. "
    "The buyer's usage record is unchanged. Resource-owner billing systems "
    "see no activity."
)

_DISCOVER_PATH = "/ramp.v1.ExchangeService/DiscoverResources"

_TENANT_ID = "tenant-e2e-ob03-readonly"
_TENANT_DOMAIN = f"{_TENANT_ID}.local"
_AGENT_ID = "agent-e2e-ob03-readonly"


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Run the stack-wide seed (contributor key + default tenant)."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


@pytest.fixture(scope="module")
def readonly_catalog(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> Iterator[str]:
    """Seed per-test tenant + agent + one catalog row. Yield resource_uri."""
    del seeded
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    _upsert_tenant_ed25519(dsn, tenant_id=_TENANT_ID, domain=_TENANT_DOMAIN)
    _upsert_agent(dsn, agent_id=_AGENT_ID)

    suffix = uuid.uuid4().hex[:8]
    path = f"/premium/ob03-readonly-{suffix}.html"
    resource_uri = f"{EDGE_PUBLIC_URL}{path}"
    content_id = f"res-ob03-readonly-{suffix}"

    push_catalog(
        exchange_url=compose_stack.exchange,
        tenant_id=_TENANT_ID,
        entries=[
            CatalogEntry(domain=EDGE_PUBLIC_HOST, path=path, content_id=content_id),
        ],
        key_path=CONTRIBUTOR_KEY_PATH,
    )
    yield resource_uri


def _count_transaction_log_rows(dsn: str, *, tenant_id: str, agent_id: str) -> int:
    """Return the number of ramp.transaction_log rows for (tenant, agent)."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT COUNT(*)
              FROM ramp.transaction_log
             WHERE tenant_id = %s AND agent_id = %s
            """,
            (tenant_id, agent_id),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0


def test_browse_writes_no_ledger_row(
    compose_stack: StackURLs,
    readonly_catalog: str,
) -> None:
    """A successful DiscoverResources does not write any ramp.transaction_log row."""
    resource_uri = readonly_catalog
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))

    # Baseline: no transaction has been written for this (tenant, agent) pair.
    pre = _count_transaction_log_rows(dsn, tenant_id=_TENANT_ID, agent_id=_AGENT_ID)
    assert pre == 0, f"per-test (tenant, agent) must start with zero ledger rows; got pre={pre}"

    # Post-1rnxh: signing is mandatory on every /ramp.* request.
    resp = sign_post(
        f"{compose_stack.exchange}{_DISCOVER_PATH}",
        body={
            "requester": {
                "id": _AGENT_ID,
                "domain": _TENANT_DOMAIN,
                "uris": [resource_uri],
            },
        },
    )

    # (a) Browse succeeded
    assert resp.status_code == httpx.codes.OK, (
        f"browse must succeed against the seeded URI; got {resp.status_code}: {resp.text[:512]}"
    )

    # (b) Browse returned an offer the agent could have accepted
    payload = cast(dict[str, Any], resp.json())
    offers = cast(list[dict[str, Any]], payload.get("offers") or [])
    assert offers, f"browse must surface at least one offer; got body={resp.text[:512]}"

    # (c) Browse wrote no ledger row. The obligation: "the buyer's usage
    # record is unchanged. Resource-owner billing systems see no activity."
    post = _count_transaction_log_rows(dsn, tenant_id=_TENANT_ID, agent_id=_AGENT_ID)
    assert post == 0, (
        f"browse must not write any ramp.transaction_log row; got post={post} "
        f"(obligation 03: 'browse is a read-only operation. No ledger row is written.')"
    )
