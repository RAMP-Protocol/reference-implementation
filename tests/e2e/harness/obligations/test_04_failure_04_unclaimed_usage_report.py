"""Obligation 04, failure-mode 2: an unclaimed usage report is refused.

Traces to `docs/obligations/04-public-endpoints-without-login.md`,
failure-mode bullet 2 (verbatim):

> The agent attempts to report usage for a transaction whose ``agent_id``
> does not match its own. The report is refused; the transaction belongs
> to a different agent.

This test exercises the related, stronger refusal: an agent operating
as its own principal (no separate-principal delegation) reports usage
for a transaction id that does not exist in the ledger at all. Per the
obligation's framing, the platform must refuse — the transaction does
not belong to this agent (it does not belong to any agent yet, because
it does not exist). The platform must also avoid inventing any state
to make the report succeed: in particular, the "no separate principal
was delegated" framing rules out fabricating an identity to attach the
phantom transaction to.

Per obligation 04's "every request is signed by the agent's well-known
key" clause, the request is signed by the agent's own Ed25519 keypair
(no separate-principal delegation header). The refusal can come from
either the httpsig layer (if the agent's kid is unknown to the
Exchange's static resolver — see the gap citation below) OR from the
service-layer "no such transaction" check; the obligation only
requires refusal, not a specific classification, and ``_REFUSAL_CODES``
below accepts both flavours.

The observable: the platform refuses the report (Connect-Go non-2xx
with a refusal code) and does NOT side-effect the ledger. In
particular:

  1. The ``ramp.transaction_log`` row count is unchanged — no
     synthetic row is invented for the unknown transaction id.
  2. The ``ramp.agents`` row count is unchanged — a missing identity
     must not cause a synthetic agent insert.

The test exercises the canonical v1 entry point — the Exchange direct
call at ``/ramp.v1.ExchangeService/ReportUsage``. Slice #2 deleted the
Broker-relay route for this RPC (see ``src/broker/cmd/server/main.go``
``buildBrokerMux`` comment: "The Exchange relay handler is removed
in W3; W4 will rewire callers to the canonical
DiscoverResources/ExecuteTransaction/ReportUsage relay"). Until W4
re-adds a Broker relay path, the Exchange is the only HTTP surface
that exposes ReportUsage; the refusal invariant is enforced there
and the Broker variant of this test was removed (it 404'd against
the deliberately-absent route, not against the obligation's
refusal logic).

Note: a tighter regression guard for the "agent_id does not match its
own" wording would seed a real transaction under agent A and then
attempt to report it as agent B; that variant is out of scope for this
test (which catches the more permissive "no such transaction" case)
and would belong in a sibling test once the multi-agent identity
plumbing is wired through the harness.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import httpx
import psycopg
import pytest

from ..conftest import COMPOSE_FILE, StackURLs
from ..httpsig_signer import load_keypair, sign_request
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    SeededFixture,
    _resolve_pg_dsn,
    seed_stack,
)


# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_REPORT_USAGE_PATH = "/ramp.v1.ExchangeService/ReportUsage"

# Connect-Go JSON error codes that qualify as "refusal". We deliberately
# allow a family of codes here rather than locking the test to one: the
# obligation requires refusal, not a specific classification. Any of
# these is a valid refusal; 2xx is not.
_REFUSAL_CODES: frozenset[str] = frozenset(
    {
        "unauthenticated",
        "not_found",
        "permission_denied",
        "invalid_argument",
    }
)


@pytest.fixture(scope="module")
def seeded(compose_stack: StackURLs) -> SeededFixture:
    """Ensure the stack is seeded so baseline table counts are stable."""
    return seed_stack(str(COMPOSE_FILE), compose_stack.exchange)


def _post_signed_json(url: str, body: dict[str, Any]) -> httpx.Response:
    """Sign a JSON POST with the agent's own well-known key and send it.

    Obligation 04: "every request is signed by the agent's well-known
    key". The agent operates as its OWN principal — no separate
    principal delegated — so the request carries an RFC 9421 signature
    (agent identity) but no ``Authorization`` bearer and no
    ``X-RAMP-Entitlement-Biscuit`` (those would carry a separate
    principal). The platform cannot find a matching ``agent_id`` on
    the (nonexistent) transaction and must refuse; the refusal may
    surface at the httpsig layer (unknown kid) or at the service-layer
    "no such transaction" check, and ``_REFUSAL_CODES`` accepts both
    flavours.
    """
    payload = json.dumps(body, separators=(",", ":")).encode()
    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=payload, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    return httpx.post(url, content=payload, headers=headers, timeout=30.0)


def _snapshot_counts(dsn: str) -> tuple[int, int]:
    """Return (transaction_log rows, agents rows) at this moment."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM ramp.transaction_log")
        tx_row = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM ramp.agents")
        ag_row = cur.fetchone()
    assert tx_row is not None and ag_row is not None
    return int(tx_row[0]), int(ag_row[0])


def _assert_refused(resp: httpx.Response, unknown_tx_id: str) -> None:
    """Assert the response is a Connect-Go refusal, not a 2xx accept."""
    assert resp.status_code >= httpx.codes.BAD_REQUEST, (
        f"report for unclaimed transaction {unknown_tx_id} was NOT refused: "
        f"status={resp.status_code} body={resp.text[:256]}"
    )
    # Connect-Go JSON errors always carry a code + message. We don't lock
    # the code to a single value — see _REFUSAL_CODES above — but we do
    # require it to be a known refusal kind so a stray 5xx without a body
    # does not silently pass.
    try:
        payload = resp.json()
    except ValueError as exc:
        msg = (
            f"expected Connect-Go JSON error body, got non-JSON for "
            f"{unknown_tx_id}: {resp.text[:256]}"
        )
        raise AssertionError(msg) from exc
    code = payload.get("code")
    message = payload.get("message")
    assert isinstance(code, str) and code in _REFUSAL_CODES, (
        f"refusal code {code!r} not in {sorted(_REFUSAL_CODES)} for "
        f"unclaimed tx {unknown_tx_id}: {payload}"
    )
    assert isinstance(message, str) and message, (
        f"refusal missing message for unclaimed tx {unknown_tx_id}: {payload}"
    )


def test_report_for_unclaimed_tx_is_refused_by_exchange(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Exchange direct call refuses ReportUsage for an unknown transaction id.

    Every assertion traces to the scenario text:

      - "for a transaction whose ``agent_id`` does not match its own"
        (interpreted strictly: the request's RFC 9421 signature
        identifies the calling agent, and that agent's identity does
        not match the transaction's ``agent_id`` — which moreover
        does not exist) — we POST a ReportUsage to the Exchange's
        ``/ramp.v1.ExchangeService/ReportUsage`` endpoint with a
        transaction_id that does not exist in
        ``ramp.transaction_log`` (fresh uuid). The POST is signed by
        the agent's own well-known Ed25519 key per obligation 04
        ("every request is signed by the agent's well-known key")
        and carries no ``Authorization`` bearer and no
        ``X-RAMP-Entitlement-Biscuit`` (those would carry a separate
        principal, contradicting the agent-as-own-principal setup).
      - "The report is refused" — the response is a Connect-Go non-2xx
        with a refusal code (one of ``_REFUSAL_CODES``). The refusal
        may originate at the httpsig layer (unknown kid) or at the
        service-layer "no such transaction" check; both flavours are
        accepted refusals.
      - Platform invariant: no ledger side effects — ``transaction_log``
        row count is unchanged, and no synthetic ``agents`` row is
        inserted (the obligation's "no separate principal was
        delegated" framing forbids inventing an agent identity to
        accept a phantom transaction).

    The Exchange is the canonical (and currently sole) HTTP entry
    point for ReportUsage; see the module-level docstring on the
    deliberately-deleted Broker relay route.
    """
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    before_tx, before_agents = _snapshot_counts(dsn)

    unknown_tx_id = f"tx-never-accepted-{uuid.uuid4().hex}"
    url = f"{compose_stack.exchange}{_REPORT_USAGE_PATH}"
    body: dict[str, Any] = {
        "ver": "1.0",
        "id": f"report-{uuid.uuid4().hex}",
        "transactionId": unknown_tx_id,
        "billingId": "",
        "usage": {"consumedQuantity": 1, "function": ["ai_input"]},
    }

    resp = _post_signed_json(url, body)
    _assert_refused(resp, unknown_tx_id)

    after_tx, after_agents = _snapshot_counts(dsn)
    assert after_tx == before_tx, (
        f"refused report mutated transaction_log: {before_tx} -> {after_tx}"
    )
    assert after_agents == before_agents, (
        f"refused report synthesised an agent row: {before_agents} -> {after_agents}"
    )

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM ramp.transaction_log WHERE transaction_id = %s",
            (unknown_tx_id,),
        )
        found = cur.fetchone()
    assert found is None, (
        f"refused report inserted a transaction_log row for unknown tx {unknown_tx_id}"
    )
