"""Structural guard — the e2e suite MUST NOT send the single-offer wire shape.

Why this is a *structural* guard, not a behavioral e2e test
-----------------------------------------------------------
This suite pins a STRUCTURAL wire-shape
migration: stop the e2e harness + tests from sending the single-offer
``TransactionRequest`` body (top-level ``offer`` + ``agentAcceptance``) and from
reading single-offer top-level ``TransactionResponse`` result fields — always use
``items[]`` instead. Proto removal of the single-offer fields is the LATER task
(The exchange *already accepts both* the single-offer top-level shape
AND the ``items[]`` shape.

That last fact is what forces a structural guard rather than a behavioral red:
because the exchange already accepts ``items[]``, an ``items[]``-shaped happy-path
e2e test PASSES on HEAD too. There is no behavioral red available from the happy
path — the licensing/content/usage outcomes are identical across the two wire
shapes. This is the documented STRUCTURAL-DISEASE EXCEPTION — where no
behavioral red exists, a structural one stands in: the correct
red artifact is a source-scan guard that FAILS while the single-offer sender
shape still exists in ``tests/e2e/`` and turns GREEN once C2 migrates every
instance to ``items[]``.

What the guard flags (and what it deliberately does NOT)
--------------------------------------------------------
A SINGLE-OFFER ``TransactionRequest`` body is a ``dict`` literal that carries the
offer and the acceptance as *direct sibling keys at the top level of the request*:

    {                              # <- top-level TransactionRequest body
        "idempotency_key": ...,     # request-level marker
        "requester": {...},        # request-level marker
        "offer": offer,            # <- single-offer sender
        "agent_acceptance": {...},  # <- single-offer sender
    }

The legitimate ``items[]`` shape places ``offer`` + ``agentAcceptance`` inside a
per-ITEM dict that is an ELEMENT of the ``items`` list — and that per-item dict
carries ONLY ``offer`` + ``agentAcceptance``, with ``requester`` / ``idempotencyKey``
hoisted to the parent request:

    {
        "idempotency_key": ...,
        "requester": {...},
        "items": [
            {"offer": offer, "agent_acceptance": {...}},  # <- ALLOWED (items[]-nested)
        ],
    }

The AST distinction is therefore exact: flag a dict that has ``offer`` AND
``agentAcceptance`` as sibling keys *and also* a request-level sibling marker
(``requester`` or ``idempotencyKey`` or ``ver``). The items[]-nested per-item dict
has no such marker sibling, so it is never flagged. The broker
RESOLVE/discovery path never builds offer+agentAcceptance dicts at all, so it is
out of scope by construction.

This guard is a pure SOURCE SCAN — it imports nothing from the running stack and
needs no docker-compose infra. The ``stack_isolation("shared-without-cleanup")``
marker makes the autouse ``_stack_isolation_dispatch`` fixture a no-op (it would
otherwise run the DB cleanup chain, which needs Postgres). It collects and runs
under a plain ``uv run pytest`` against this file alone.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from .ast_scan import dict_string_keys, scan_tree

# Keys that mark a dict literal as a TOP-LEVEL TransactionRequest body (as
# opposed to an items[]-nested per-item dict, which carries only offer +
# agentAcceptance). The presence of ANY of these as a sibling of offer +
# agentAcceptance proves the offer/acceptance live at the request top level.
_REQUEST_LEVEL_MARKERS = frozenset({"requester", "idempotency_key", "ver"})

_OFFER_KEY = "offer"
_ACCEPTANCE_KEY = "agent_acceptance"


def _is_single_offer_body(node: ast.Dict) -> bool:
    """True iff ``node`` is a TOP-LEVEL single-offer TransactionRequest body.

    The dict must carry ``offer`` AND ``agentAcceptance`` as sibling keys AND at
    least one request-level marker (``requester`` / ``idempotencyKey`` / ``ver``).
    The items[]-nested per-item dict (``{offer, agentAcceptance}`` only) lacks any
    such marker and is therefore NOT flagged.
    """
    keys = dict_string_keys(node)
    if _OFFER_KEY not in keys or _ACCEPTANCE_KEY not in keys:
        return False
    return bool(keys & _REQUEST_LEVEL_MARKERS)


def _single_offer_offences(tree: ast.AST) -> list[tuple[int, str]]:
    """Every top-level single-offer sender body in ``tree``, as (line, "").

    The reason is empty: there is one shape this guard refuses, and the
    assertion below already names it.
    """
    return [
        (node.lineno, "")
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict) and _is_single_offer_body(node)
    ]


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_no_single_offer_wire_shape_in_e2e() -> None:
    """No e2e .py builds a top-level single-offer TransactionRequest body.

    Green since every sender was folded onto the items[] shape --
    ``relay.relay_execute``, ``obligations.flow.execute_offer`` and the inline
    obligation senders all build the envelope now. It is a ratchet from here: it
    fails the moment a new body puts ``offer`` and ``agent_acceptance`` back
    beside a request-level key.
    """
    hits = scan_tree(_single_offer_offences, exclude=Path(__file__))
    assert not hits, (
        f"Found {len(hits)} single-offer TransactionRequest sender(s) in tests/e2e/ "
        f"(top-level 'offer'+'agentAcceptance' siblings of a request-level marker). "
        f"Migrate each to the items[] shape:\n  " + "\n  ".join(hits)
    )


# ---------------------------------------------------------------------------
# Meta-tests for the guard itself (positive + negative). These keep the guard
# honest: they prove it flags the disease shape and does NOT flag the allowed
# items[]-nested shape — so the passing scan above means the senders are on the
# items[] shape, not that the matcher went blind.
# ---------------------------------------------------------------------------


def _hits_in_snippet(src: str) -> list[tuple[int, str]]:
    """Run the same detector over an inline snippet (no file I/O)."""
    return _single_offer_offences(ast.parse(src))


_SINGLE_OFFER_SNIPPET = """
body = {
    "ver": "1.0",
    "idempotency_key": idem,
    "offer_id": offer.get("offer_id"),
    "offer": offer,
    "requester": {"id": agent_id, "domain": domain, "type": "REQUESTER_TYPE_AGENT"},
    "agent_acceptance": {"signature": sig, "signature_algorithm": alg},
}
"""

_ITEMS_BATCH_SNIPPET = """
body = {
    "ver": "1.0",
    "idempotency_key": idem,
    "requester": {"id": agent_id, "domain": domain, "type": "REQUESTER_TYPE_AGENT"},
    "items": [
        {"offer": offer, "agent_acceptance": {"signature": sig, "signature_algorithm": alg}},
    ],
}
"""

# RESOLVE / discovery path: no offer+agentAcceptance dict at all.
_DISCOVERY_SNIPPET = """
body = {
    "id": qid,
    "requester": {"id": agent_id, "domain": domain, "type": "REQUESTER_TYPE_AGENT"},
    "uris": [uri],
}
"""

# A bare per-item dict on its own (as the batch builder appends) — only
# offer+agentAcceptance, no request-level marker.
_BARE_ITEM_SNIPPET = """
item = {"offer": offer, "agent_acceptance": {"signature": sig, "signature_algorithm": alg}}
"""


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_flags_single_offer_body() -> None:
    """POSITIVE meta-test: the guard flags a top-level single-offer body."""
    hits = _hits_in_snippet(_SINGLE_OFFER_SNIPPET)
    assert len(hits) == 1, f"expected the single-offer body flagged once, got {hits}"


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_items_batch_body() -> None:
    """NEGATIVE meta-test: the legitimate items[] batch body is NOT flagged."""
    assert _hits_in_snippet(_ITEMS_BATCH_SNIPPET) == [], (
        "items[]-nested per-item offer/agentAcceptance must not be flagged "
        "(this is the correct batch shape — relay_execute_batch / test_multi_exchange)"
    )


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_discovery_body() -> None:
    """NEGATIVE meta-test: the broker RESOLVE/discovery body is NOT flagged."""
    assert _hits_in_snippet(_DISCOVERY_SNIPPET) == [], (
        "the discovery/resolve request carries no offer+agentAcceptance and "
        "must never be flagged (discovery is out of C2 scope)"
    )


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_bare_item_dict() -> None:
    """NEGATIVE meta-test: a bare {offer, agentAcceptance} item dict is NOT flagged.

    This is the per-item dict the batch builder appends to ``items[]``. It carries
    no request-level marker, so it is the items[]-nested shape, not a single-offer
    request body.
    """
    assert _hits_in_snippet(_BARE_ITEM_SNIPPET) == [], (
        "a bare per-item {offer, agentAcceptance} dict (no requester/idempotencyKey "
        "sibling) is the allowed items[]-nested shape and must not be flagged"
    )
