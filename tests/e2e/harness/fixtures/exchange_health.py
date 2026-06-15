"""ADR-008 D5 — exchange-health cleanup fixture.

When a Broker test runs against an exchange whose health flag has
drifted to FALSE (because a prior test marked it unhealthy, or a probe
race left it stale), every subsequent DiscoverResources/Resolve call returns
empty — and the test silently passes for the wrong reason. ADR-008 D5
forbids that "tests pass on a sick stack" pattern: the cleanup mode
declares its dependence on a known-good baseline and runs this
fixture before each test to restore it.

Ownership: this fixture is owned by the cleanup mode, not by
individual tests. Tests declare ``stack_isolation("shared-clean-fixtures")``
(the f6mq peer's marker contract) and the framework's per-test hook
runs ``promote_drifted_exchange_health`` between tests. Tests do
NOT import or call this function directly.

The Broker-side periodic health probe deliberately remains out of
scope here — that's a config-flag-gated background goroutine the
Broker may add later. ADR-008 D5 says "if it grows beyond a small
probe, file a follow-up beads task and stop"; this module honours
that boundary.
"""

from __future__ import annotations

import logging

import psycopg

logger = logging.getLogger(__name__)

# SQL is intentionally narrow: re-promote ONLY rows whose `healthy`
# column has drifted to FALSE. We do NOT touch other columns
# (trust_level, priority, supported_profiles) so a test that
# deliberately downgraded an exchange's trust still survives the
# cleanup. ``last_health_check`` is bumped so the Broker's freshness
# heuristic sees the row as recently observed.
_PROMOTE_DRIFTED_HEALTH_SQL = """
UPDATE broker.exchanges
   SET healthy = TRUE,
       last_health_check = NOW(),
       updated_at = NOW()
 WHERE healthy = FALSE
"""


def promote_drifted_exchange_health(dsn: str) -> int:
    """Re-promote any exchange rows whose health flag has drifted to FALSE.

    Returns the number of rows promoted (0 on a clean stack). Idempotent:
    safe to call before every test in the ``shared-clean-fixtures``
    chain. Errors propagate — a cleanup fixture that silently swallows a
    DB failure is exactly the "ambiguous-state pass" defect ADR-008 D5
    exists to remove.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(_PROMOTE_DRIFTED_HEALTH_SQL)
        promoted = cur.rowcount
        conn.commit()
    if promoted > 0:
        logger.info(
            "exchange_health_cleanup: re-promoted %d drifted row(s)",
            promoted,
        )
    return promoted
