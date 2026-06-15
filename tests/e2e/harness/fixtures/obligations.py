"""ADR-008 D5 — reporting-obligation cleanup fixture.

Per-request RAMP transactions create rows in ``ramp.reporting_obligations``
with a wall-clock-anchored ``deadline``. When obligation tests share the
same compose stack, leftover rows from a previous test can mask a real
regression — the test passes because an earlier obligation row keeps the
buyer "in good standing" rather than because the production code under
test is correct.

Ownership: this fixture is owned by the ``shared-clean-fixtures`` mode
(ADR-008 D5). Tests declare
``@pytest.mark.stack_isolation("shared-clean-fixtures")`` and the
per-test hook runs this purge between tests. This is the FIRST entry in
the cleanup chain because every other gate (signed-URL, billing,
exchange-health) reads from a baseline this purge guarantees.
"""

from __future__ import annotations

import logging

import psycopg

logger = logging.getLogger(__name__)

# Truncate the obligations table at the start of every test in the
# shared-clean-fixtures chain. CASCADE is intentionally omitted —
# transaction_log rows reference reporting_obligations only via the
# obligation_id soft pointer (no FK), so a TRUNCATE on the obligations
# table alone restores the gate baseline without dragging unrelated
# tenant fixtures.
_PURGE_OBLIGATIONS_SQL = "TRUNCATE TABLE ramp.reporting_obligations"


def purge_reporting_obligations(dsn: str) -> int:
    """Truncate ``ramp.reporting_obligations`` and return rows-before count.

    Errors propagate — a cleanup fixture that silently swallows a DB
    failure is exactly the "ambiguous-state pass" defect ADR-008 D5
    exists to remove. Returns the row count observed before the
    truncate so the per-test hook can log how much state was carried
    over from the previous test.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM ramp.reporting_obligations")
        row = cur.fetchone()
        before = int(row[0]) if row else 0
        cur.execute(_PURGE_OBLIGATIONS_SQL)
        conn.commit()
    if before > 0:
        logger.info(
            "obligations_cleanup: purged %d carried-over row(s)",
            before,
        )
    return before
