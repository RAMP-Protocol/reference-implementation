"""E2E: Exchange idempotency-replay conformance against the REAL Exchange.

Closes the ONE residual drift risk the mock-Exchange disposition kept open:
the broker-side
mock proves the broker relays a resent ``idempotency_key`` without dedup, but it
FAKES the Exchange's half by deriving ``tx_id`` deterministically from the key.
This suite proves the real half — ``ramp.proto`` conformance: *a replay returns
the original result rather than re-executing* (``exchange_batch.go``
``replayBatchResponse``: durable probe on the derived per-item key
``idempotency_key:offer_id`` over persisted ``transaction_log`` rows).

Round-trip honesty
------------------
The happy leg drives the FULL chain — agent → Broker relay (sig1 verify,
re-package, sig2) → real Exchange — twice with one ``idempotency_key``, and
asserts through the same public surface: both relays return 200 and the SAME
``transaction_id`` / ``retrieval_endpoint`` (the verbatim original response).
The no-double-charge half reads the ledger row count directly: a BLACK-BOX e2e
exception — the transaction ledger has NO protocol read surface BY
DESIGN, so observing the deployment's datastore is the only way to assert the
absent side effect (no second row, no second charge) end-to-end.

Foreign-agent negative (Doctrine #10)
-------------------------------------
The replay ownership gate lives in the EXCHANGE (``replayBatchResponse``: the
stored result is served only to a caller that proves possession of the agent
key the rows are bound to; a foreign principal gets PermissionDenied, never the
URL). It is asserted agent-direct on ``ExchangeService/ExecuteTransaction``
because that is the surface that owns the refusal — the Broker relay folds ANY
upstream whole-call error into a synthesized per-item CONTENT_UNAVAILABLE
denial (``relay/batch.go`` ``collectGroupDenials``), which cannot distinguish
the ownership refusal from plain unavailability. Same surface-selection
rationale as ``test_offer_redemption`` (tampering is only expressible where the
test holds the offer).
"""

from __future__ import annotations

import time
import uuid
from typing import Any, cast

import httpx
import psycopg
import pytest

from ramp_sdk.core import sign_offer_acceptance_jcs
from ramp_sdk import ProtocolVersion

from .broker_client import resolve
from .conftest import COMPOSE_FILE, StackURLs
from .httpsig_signer import load_keypair
from .relay import relay_execute
from .resolve_carriers import first_item_of, retrieval_endpoint_of
from .seed import DEMO_PHILOSOPHY_DOMAIN, SeededFixture, _resolve_pg_dsn
from .signing import USD_AGENT_KEY_PATH, sign_post

# ADR-008 D5 — declare stack-isolation contract.
pytestmark = pytest.mark.stack_isolation("shared-clean-fixtures")

_EXECUTE_PATH = "/ramp.v1.ExchangeService/ExecuteTransaction"

# 10,000.00 USD: above any plausible demo cost → the budget pre-flight always
# passes; this suite is about execute-time idempotency, not the budget gate.
_BUDGET_AMPLE = 1_000_000

# epicurus: PER_UNIT 0.0001/characters USD — a PAID resource on the PRIMARY
# exchange (`exchange`, catalog DB `ramp`), so the ledger reads below target the
# same DB the demo flow tests use. The sfx/music resources live on exchange-c/b
# with their own DBs (`ramp_c`/`ramp_b`) — using one of those here would route
# the relay to a different exchange than the ledger read (the first version of
# this suite made exactly that mistake).
_RESOURCE_URI = f"http://{DEMO_PHILOSOPHY_DOMAIN}/articles/philosophers/epicurus.txt"


def _discover_priced_offer(compose_stack: StackURLs, *, agent_id: str) -> dict[str, Any]:
    """Broker-Resolve the paid epicurus resource as its USD buyer; return the winning offer."""
    resp = resolve(
        compose_stack,
        {
            "agent_id": agent_id,
            "uri": _RESOURCE_URI,
            "intended_use": "ai-input",
            "budget_minor": _BUDGET_AMPLE,
            "currency": "USD",
        },
        key_path=USD_AGENT_KEY_PATH,
    )
    assert resp.status_code == httpx.codes.OK, resp.text
    payload = cast(dict[str, Any], resp.json())
    groups = cast(list[dict[str, Any]], payload.get("offer_groups") or [])
    offers = [o for g in groups for o in cast(list[dict[str, Any]], g.get("offers") or [])]
    assert offers, f"Resolve surfaced no offer to execute: {payload}"
    return offers[0]


def _ledger_rows_for_derived_key(derived_key: str) -> list[tuple[str, str]]:
    """(transaction_id, idempotency_key) rows for the derived per-item key.

    BLACK-BOX e2e exception: the ledger has no protocol read surface
    by design, so the no-double-charge side effect is observable only on the
    deployment's datastore — not an in-process layer bypass.
    """
    dsn = _resolve_pg_dsn(str(COMPOSE_FILE))
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT transaction_id, idempotency_key
            FROM ramp.transaction_log
            WHERE idempotency_key = %s
            """,
            (derived_key,),
        )
        return [(str(r[0]), str(r[1])) for r in cur.fetchall()]


def _execute_direct_with_key(
    exchange_url: str,
    offer: dict[str, Any],
    *,
    agent_id: str,
    domain: str,
    key_path: Any,
    idempotency_key: str,
) -> httpx.Response:
    """Agent-direct ExecuteTransaction presenting ``offer`` under a CALLER-CHOSEN key.

    Mirrors ``obligations/flow.execute_offer`` but takes ``idempotency_key``
    explicitly — the replay legs need the SAME key across calls (flow.py mints a
    fresh one per call). The acceptance is detached-signed with THIS caller's
    key over the presented offer signature + requester + the shared key, so a
    foreign caller presents a VALID acceptance of its own — the refusal under
    test is the replay ownership gate (bound-agent mismatch), never a malformed
    acceptance.
    """
    offer_signature = offer.get("signature")
    assert offer_signature, f"discovered offer carries no signature: {offer!r}"
    _, priv = load_keypair(key_path)
    acceptance_sig, acceptance_alg = sign_offer_acceptance_jcs(
        seed=priv.private_bytes_raw(),
        offer_sig=str(offer_signature),
        requester_id=agent_id,
        requester_domain=domain,
        idempotency_key=idempotency_key,
    )
    return sign_post(
        f"{exchange_url}{_EXECUTE_PATH}",
        body={
            "ver": ProtocolVersion,
            "idempotency_key": idempotency_key,
            "requester": {
                "id": agent_id,
                "domain": domain,
                "type": "REQUESTER_TYPE_AGENT",
            },
            "items": [
                {
                    "offer": offer,
                    "agent_acceptance": {
                        "signature": acceptance_sig,
                        "signature_algorithm": acceptance_alg,
                    },
                }
            ],
        },
        key_path=key_path,
    )


def test_relay_replay_same_key_returns_original_transaction_no_double_charge(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """Two broker-relayed executes under ONE idempotency_key → one transaction.

    The second relay must return the ORIGINAL result (same transaction_id, same
    signed retrieval_endpoint) rather than re-executing, and the ledger must
    hold exactly ONE row under the derived per-item key — no double charge.
    """
    agent_id = seeded.usd_agent_id
    offer = _discover_priced_offer(compose_stack, agent_id=agent_id)
    idem = f"idem-replay-{uuid.uuid4().hex}"

    first = relay_execute(
        compose_stack.broker,
        offer,
        agent_id=agent_id,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
        idempotency_key=idem,
    )
    assert first.status_code == httpx.codes.OK, first.text
    first_item = first_item_of(cast(dict[str, Any], first.json()))
    assert first_item is not None, f"first execute carried no items[0]: {first.text}"
    first_tx = first_item.get("transaction_id")
    first_url = retrieval_endpoint_of(first_item)
    assert first_tx, f"transaction_id missing from first execute: {first_item}"
    assert first_url, f"retrieval_endpoint missing from first execute: {first_item}"

    # The relay body is byte-identical on a replay (same offer, same requester,
    # same idempotency_key → the SAME deterministic Ed25519 acceptance), and
    # sig1's base covers `created` in whole seconds — two relays inside one
    # second would carry an IDENTICAL sig1, which the broker's anti-replay
    # store (keyID+signature) rightly refuses. Cross the second boundary so the
    # replay is a fresh signature over the same body, as a real retrying agent's
    # would be.
    time.sleep(1.1)

    second = relay_execute(
        compose_stack.broker,
        offer,
        agent_id=agent_id,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
        idempotency_key=idem,
    )
    assert second.status_code == httpx.codes.OK, (
        f"replayed idempotency_key must return the original result, got "
        f"{second.status_code}: {second.text[:512]}"
    )
    second_item = first_item_of(cast(dict[str, Any], second.json()))
    assert second_item is not None, f"replay carried no items[0]: {second.text}"

    # Conformance core: the replay IS the original result — same transaction,
    # same agent-bound signed URL (reconstructed verbatim from the persisted
    # row), never a second mint.
    assert second_item.get("transaction_id") == first_tx, (
        f"replay minted a NEW transaction: first={first_tx!r} "
        f"second={second_item.get('transaction_id')!r}"
    )
    assert retrieval_endpoint_of(second_item) == first_url, (
        "replay must return the ORIGINAL signed retrieval_endpoint verbatim"
    )
    assert second_item.get("billing_id") == first_item.get("billing_id"), (
        "replay must echo the original billing_id, not open a new billing leg"
    )

    # No double charge: exactly ONE ledger row under the derived per-item key,
    # and it is the first transaction (black-box datastore read — see helper).
    rows = _ledger_rows_for_derived_key(f"{idem}:{offer.get('offer_id')}")
    assert len(rows) == 1, f"expected exactly one ledger row for the replayed key, got {rows!r}"
    assert rows[0][0] == first_tx, (
        f"ledger row {rows[0][0]!r} does not match the returned transaction {first_tx!r}"
    )


def test_foreign_agent_replay_of_same_key_is_refused_without_leaking_url(
    compose_stack: StackURLs,
    seeded: SeededFixture,
) -> None:
    """A FOREIGN agent replaying someone else's idempotency_key+offer is refused.

    The stored result carries a signed URL bound to the ORIGINAL agent; the
    derived probe key is a client-chosen token, not a bearer secret. The
    Exchange's ownership gate must refuse the foreign principal
    (PermissionDenied) and never hand back the stored result — and the refusal
    must leave the ledger untouched (still exactly one row).
    """
    agent_id = seeded.usd_agent_id
    offer = _discover_priced_offer(compose_stack, agent_id=agent_id)
    idem = f"idem-foreign-{uuid.uuid4().hex}"

    # Original execute by the rightful buyer (broker relay, full chain).
    first = relay_execute(
        compose_stack.broker,
        offer,
        agent_id=agent_id,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=USD_AGENT_KEY_PATH,
        idempotency_key=idem,
    )
    assert first.status_code == httpx.codes.OK, first.text
    first_item = first_item_of(cast(dict[str, Any], first.json()))
    assert first_item is not None and first_item.get("transaction_id"), first.text
    first_url = retrieval_endpoint_of(first_item)
    assert first_url, f"precondition: the original execute must mint a URL: {first_item}"

    # Foreign registered agent presents the SAME key + SAME offer with a valid
    # acceptance of its OWN — agent-direct on the PRIMARY Exchange (the exchange
    # that issued this offer and persisted the rows), the surface that owns the
    # ownership refusal (the broker folds upstream errors into an
    # undifferentiated CONTENT_UNAVAILABLE denial; see module docstring).
    foreign = _execute_direct_with_key(
        compose_stack.exchange,
        offer,
        agent_id=seeded.nobilling_agent_id,
        domain=DEMO_PHILOSOPHY_DOMAIN,
        key_path=seeded.nobilling_agent_key_path,
        idempotency_key=idem,
    )
    assert foreign.status_code == httpx.codes.FORBIDDEN, (
        f"foreign replay must be PermissionDenied, got {foreign.status_code}: {foreign.text[:512]}"
    )
    # The stored result (the original agent's bound URL) must never leak on the
    # refusal body.
    assert first_url not in foreign.text, (
        "foreign replay refusal leaked the original agent's signed URL"
    )

    # Refusal left no ledger side effect: still exactly one row, the original's.
    rows = _ledger_rows_for_derived_key(f"{idem}:{offer.get('offer_id')}")
    assert len(rows) == 1, f"foreign replay must not add/remove ledger rows; got {rows!r}"
    assert rows[0][0] == first_item.get("transaction_id"), (
        "surviving ledger row must remain the ORIGINAL transaction"
    )
