"""Shared fixtures for the multi-exchange E2E suites.

The 3-exchange topology tests are split across two scenario files —
``test_multi_exchange.py`` (direct per-exchange isolation + broker fan-out) and
``test_multi_exchange_mcp.py`` (the account tools across all three, through the
MCP surface). The per-exchange identity constants, the discoverable-URI-per-
publisher constants, and the black-box per-DB ledger readers those files share
live here so none of them duplicates the others (the jscpd duplication budget is
zero). The MCP suite needs only the identity constants, which it takes from
``exchanges`` directly.
"""

from __future__ import annotations

import psycopg

from .conftest import COMPOSE_FILE
from .exchanges import EXCHANGE_A_DOMAIN, EXCHANGE_B_DOMAIN, EXCHANGE_C_DOMAIN
from .seed import (
    DEMO_MUSIC_DOMAIN,
    DEMO_PHILOSOPHY_DOMAIN,
    DEMO_SFX_DOMAIN,
    _resolve_pg_dsn_for_db,
)

# One discoverable URI per publisher catalog (FREE/affordable, so a plain
# discover yields an offer). philosophy: socrates (FREE EUR); music:
# paper-satellites (FLAT USD); sfx: rain-on-tin-roof (FREE USD).
_PHILOSOPHY_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/socrates.txt"
_MUSIC_URI = f"http://{DEMO_MUSIC_DOMAIN}/lyrics/paper-satellites.txt"
_SFX_URI = f"http://{DEMO_SFX_DOMAIN}/sfx/rain-on-tin-roof.json"


# Each offer.exchange domain maps to that exchange's OWN catalog DB. The
# usage record (ramp.reporting_obligations) and the transaction ledger row are
# written into the exchange's own DB, so the per-DB reads below are keyed on this
# mapping (resolveCaller + the obligation both live on the exchange's
# own DB).
_EXCHANGE_DOMAIN_TO_DB = {
    EXCHANGE_A_DOMAIN: "ramp",
    EXCHANGE_B_DOMAIN: "ramp_b",
    EXCHANGE_C_DOMAIN: "ramp_c",
}


def _usage_record(db_name: str, transaction_id: str) -> tuple[str | None, str | None]:
    """Read the per-DB usage record for ``transaction_id`` (BLACK-BOX).

    The transaction ledger has NO protocol read surface BY DESIGN (record-read is
    downstream observability over the operator's datastore, out of RAMP's protocol
    scope). A full-stack e2e observing the deployment datastore directly
    is the documented exception (mirrors test_00_happy_03). Returns
    ``(issued_report_id, validation_outcome)`` for the reporting obligation; a
    recorded report has a non-NULL ``issued_report_id`` + ``VALIDATED`` outcome.
    """
    dsn = _resolve_pg_dsn_for_db(str(COMPOSE_FILE), db_name)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT issued_report_id, validation_outcome
            FROM ramp.reporting_obligations
            WHERE transaction_id = %s
            """,
            (transaction_id,),
        )
        rows = cur.fetchall()
    if not rows:
        return None, None
    issued, outcome = rows[0]
    return issued, (str(outcome) if outcome is not None else None)


def _transaction_log_agent(db_name: str, transaction_id: str) -> str | None:
    """Read the ``ramp.transaction_log`` row's ``agent_id`` for ``transaction_id``.

    BLACK-BOX e2e exception (mirrors test_00_happy_03 / test_04_happy_00):
    the transaction ledger has NO protocol read surface BY DESIGN — record-read is
    downstream observability over the operator's datastore, out of RAMP's protocol
    scope. Observing the per-exchange deployment datastore directly is the only way
    to prove END-TO-END which exchange's OWN DB (ramp / ramp_b / ramp_c) recorded a
    given transaction — the topology-isolation signal. Returns the recorded
    ``agent_id`` (None when the transaction is absent from THIS DB).
    """
    dsn = _resolve_pg_dsn_for_db(str(COMPOSE_FILE), db_name)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT agent_id FROM ramp.transaction_log WHERE transaction_id = %s",
            (transaction_id,),
        )
        row = cur.fetchone()
    return None if row is None else str(row[0])
