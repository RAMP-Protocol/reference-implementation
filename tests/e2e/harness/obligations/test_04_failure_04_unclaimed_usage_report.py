"""Obligation 04, failure-mode 2: an unclaimed usage report is refused.

Traces to failure-mode bullet 2 (verbatim):

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
(no separate-principal delegation header). The caller's key resolves
from its own well-known directory, so the signature verifies and the
refusal comes from the service layer's no-obligation-for-transaction
check — surfaced as the single ``not_found`` code that
``_REFUSAL_CODES`` pins, so the test notices if a future change moves
the refusal to a different layer or classification.

The observable: the platform refuses the report (Connect-Go non-2xx
with a refusal code) and does NOT side-effect the ledger. In
particular:

  1. The ``ramp.transaction_log`` row count is unchanged — no
     synthetic row is invented for the unknown transaction id.
  2. The ``ramp.agents`` row count grows by at most the caller's own
     lazy registration — a missing identity must not cause a synthetic
     agent insert (see the in-test comment on the exact bound).

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

from ..connect_errors import assert_refused
from ..reporting import REPORT_USAGE_PATH, report_body
from ..exchanges import recipient_of
from ..conftest import COMPOSE_FILE, StackURLs
from ..httpsig_signer import load_keypair, sign_request
from ..seed import (
    CONTRIBUTOR_KEY_PATH,
    SeededFixture,
    _resolve_pg_dsn,
)

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")


# The Connect-Go JSON error code that qualifies as "refusal". Pinned to the
# one code the deployed path actually returns — the service layer's
# no-obligation-for-transaction check maps to ``not_found`` — so a change
# that moves the refusal to another layer or classification is noticed
# here instead of being absorbed silently.
_REFUSAL_CODES: frozenset[str] = frozenset({"not_found"})


def _post_signed_json(url: str, body: dict[str, Any]) -> httpx.Response:
    """Sign a JSON POST with the agent's own well-known key and send it.

    Obligation 04: "every request is signed by the agent's well-known
    key". The agent operates as its OWN principal — no separate
    principal delegated — so the request carries an RFC 9421 signature
    (agent identity) but no ``Authorization`` bearer and no
    ``X-RAMP-Entitlement-Biscuit`` (those would carry a separate
    principal). The platform cannot find a matching ``agent_id`` on
    the (nonexistent) transaction and must refuse with the service
    layer's no-obligation-for-transaction ``not_found`` (the only code
    ``_REFUSAL_CODES`` accepts).
    """
    payload = json.dumps(body, separators=(",", ":")).encode()
    kid, priv = load_keypair(CONTRIBUTOR_KEY_PATH)
    signed = sign_request(method="POST", target_uri=url, body=payload, kid=kid, priv=priv)
    headers = {**signed.headers, "Content-Type": "application/json"}
    return httpx.post(url, content=payload, headers=headers, timeout=30.0)


def _snapshot_counts(dsn: str) -> tuple[int, int]:
    """Return (transaction_log rows, agents rows) at this moment.

    BLACK-BOX e2e exception: the transaction ledger has NO
    protocol read surface BY DESIGN — record-read/reporting is downstream
    observability over the operator's datastore, out of RAMP's protocol scope,
    so no public read RPC will be added. A full-stack e2e observing the
    deployment's datastore directly is NOT the pt9 layer-bypass that rule
    forbids (an in-process test reaching past a production layer); it is the
    only way to assert these ledger side effects (here, their absence) end-to-end.
    """
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM ramp.transaction_log")
        tx_row = cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM ramp.agents")
        ag_row = cur.fetchone()
    assert tx_row is not None and ag_row is not None
    return int(tx_row[0]), int(ag_row[0])


def _assert_refused(resp: httpx.Response, unknown_tx_id: str) -> None:
    """Assert the response is a Connect-Go refusal, not a 2xx accept.

    The shared reader pins the code — see ``_REFUSAL_CODES`` above for which one
    and why — so a refusal that moves to another layer is noticed here instead
    of passing as "some 4xx".
    """
    assert_refused(resp, _REFUSAL_CODES, f"report for unclaimed transaction {unknown_tx_id}")


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
        carrying the pinned ``not_found`` refusal code (the service
        layer's no-obligation-for-transaction check; see
        ``_REFUSAL_CODES``).
      - Platform invariant: no ledger side effects — ``transaction_log``
        row count is unchanged (the obligation's "no separate principal
        was delegated" framing forbids inventing an agent identity to
        accept a phantom transaction). The ``agents`` table MAY grow by
        at most one: the request is signed by the caller's own published
        well-known key, so the Exchange lazy-registers that caller
        before refusing on the unknown transaction. That is the
        validly-signed caller registering itself — not a synthetic
        principal invented to accept the phantom tx; the refusal and the
        untouched ``transaction_log`` are the load-bearing guarantees.

    The Exchange is the canonical (and currently sole) HTTP entry
    point for ReportUsage; see the module-level docstring on the
    deliberately-deleted Broker relay route.
    """
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    before_tx, before_agents = _snapshot_counts(dsn)

    unknown_tx_id = f"tx-never-accepted-{uuid.uuid4().hex}"
    url = f"{compose_stack.exchange}{REPORT_USAGE_PATH}"
    body = report_body(
        exchange=recipient_of(compose_stack.exchange),
        transaction_id=unknown_tx_id,
        consumed_quantity=1,
    )

    resp = _post_signed_json(url, body)
    _assert_refused(resp, unknown_tx_id)

    after_tx, after_agents = _snapshot_counts(dsn)
    assert after_tx == before_tx, (
        f"refused report mutated transaction_log: {before_tx} -> {after_tx}"
    )
    # The ledger invariant above is load-bearing: NO phantom transaction is
    # accepted (the report is refused and leaves no transaction_log row, asserted
    # above/below). Lazy/just-in-time registration (ADR-009 D2, adopted
    # from v1.1) resolves the CALLER from its own well-known BEFORE the
    # no-such-transaction check, so a cryptographically-verified caller may
    # legitimately gain its own ramp.agents row — that is the real signer, NOT a
    # synthetic identity invented to accept the phantom tx (which would require a
    # row keyed to the tx's nonexistent agent_id). The agents table may therefore
    # grow by at most one (the caller's own lazy registration) and must never
    # decrease; never more.
    assert 0 <= after_agents - before_agents <= 1, (
        f"refused report changed agents by more than the lazy-registered "
        f"caller: {before_agents} -> {after_agents}"
    )

    # BLACK-BOX e2e exception — same rationale as
    # _snapshot_counts above: assert the unknown tx left no ledger row, observed
    # directly on the deployment datastore (no protocol read surface exists).
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM ramp.transaction_log WHERE transaction_id = %s",
            (unknown_tx_id,),
        )
        found = cur.fetchone()
    assert found is None, (
        f"refused report inserted a transaction_log row for unknown tx {unknown_tx_id}"
    )
