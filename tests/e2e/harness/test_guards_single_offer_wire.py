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
from dataclasses import dataclass
from pathlib import Path

import pytest

# Root of the e2e tree this guard scans. Resolved relative to THIS file so the
# guard is location-stable whether run from the repo root, tests/e2e/, or the
# runner container.
_E2E_ROOT = Path(__file__).resolve().parent.parent  # tests/e2e/

# This guard file itself constructs example single-offer dict literals in its
# meta-tests; exclude it so the guard does not flag its own fixtures.
_SELF = Path(__file__).resolve()

# Keys that mark a dict literal as a TOP-LEVEL TransactionRequest body (as
# opposed to an items[]-nested per-item dict, which carries only offer +
# agentAcceptance). The presence of ANY of these as a sibling of offer +
# agentAcceptance proves the offer/acceptance live at the request top level.
_REQUEST_LEVEL_MARKERS = frozenset({"requester", "idempotency_key", "ver"})

_OFFER_KEY = "offer"
_ACCEPTANCE_KEY = "agent_acceptance"


@dataclass(frozen=True)
class _Hit:
    """A flagged single-offer sender dict literal."""

    path: Path
    lineno: int

    def __str__(self) -> str:
        rel = self.path.relative_to(_E2E_ROOT)
        return f"tests/e2e/{rel}:{self.lineno}"


def _dict_string_keys(node: ast.Dict) -> set[str]:
    """Return the set of constant-string keys of a dict literal node.

    Non-constant / non-string keys (``**spread``, computed keys) yield ``None``
    entries in ``node.keys`` and are simply ignored — a single-offer body always
    spells its keys as plain string literals, so this is sufficient and avoids
    false positives from dynamic dicts.
    """
    keys: set[str] = set()
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.add(key.value)
    return keys


def _is_single_offer_body(node: ast.Dict) -> bool:
    """True iff ``node`` is a TOP-LEVEL single-offer TransactionRequest body.

    The dict must carry ``offer`` AND ``agentAcceptance`` as sibling keys AND at
    least one request-level marker (``requester`` / ``idempotencyKey`` / ``ver``).
    The items[]-nested per-item dict (``{offer, agentAcceptance}`` only) lacks any
    such marker and is therefore NOT flagged.
    """
    keys = _dict_string_keys(node)
    if _OFFER_KEY not in keys or _ACCEPTANCE_KEY not in keys:
        return False
    return bool(keys & _REQUEST_LEVEL_MARKERS)


def _scan_source(path: Path) -> list[_Hit]:
    """Parse ``path`` and return every single-offer sender dict literal in it."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[_Hit] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict) and _is_single_offer_body(node):
            hits.append(_Hit(path=path, lineno=node.lineno))
    return hits


def _scan_e2e_tree() -> list[_Hit]:
    """Scan every ``.py`` under tests/e2e/ for single-offer sender bodies."""
    hits: list[_Hit] = []
    for path in sorted(_E2E_ROOT.rglob("*.py")):
        if path.resolve() == _SELF:
            continue
        hits.extend(_scan_source(path))
    return hits


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_no_single_offer_wire_shape_in_e2e() -> None:
    """No e2e .py builds a top-level single-offer TransactionRequest body.

    RED NOW (TDD): C2 has not migrated the 13 disposition-table instances yet,
    so this fails listing the current single-offer senders (relay.py::relay_execute,
    obligations/flow.py::execute_offer, and the inline obligation senders).
    GREEN after C2 folds every single-offer body onto the items[] shape.
    """
    hits = _scan_e2e_tree()
    assert not hits, (
        f"Found {len(hits)} single-offer TransactionRequest sender(s) in tests/e2e/ "
        f"(top-level 'offer'+'agentAcceptance' siblings of a request-level marker). "
        f"C2 must migrate each to the items[] shape:\n  " + "\n  ".join(str(h) for h in hits)
    )


# ---------------------------------------------------------------------------
# Meta-tests for the guard itself (positive + negative). These keep the guard
# honest: they prove it flags the disease shape and does NOT flag the allowed
# items[]-nested shape — so when the production scan flips GREEN after C2, we
# know it did so because the senders were migrated, not because the guard went
# blind.
# ---------------------------------------------------------------------------


def _hits_in_snippet(src: str) -> list[_Hit]:
    """Run the same detector over an inline snippet (no file I/O)."""
    tree = ast.parse(src)
    return [
        _Hit(path=Path("<snippet>"), lineno=node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict) and _is_single_offer_body(node)
    ]


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
