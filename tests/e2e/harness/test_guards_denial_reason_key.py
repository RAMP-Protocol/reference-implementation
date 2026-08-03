"""Structural guard — e2e tests MUST NOT read ``denialReason`` (camelCase) via ``.get()``.

The Exchange's parsed per-item response is snake_case: the denial cause is
``denial_reason``. A ``.get("denialReason")`` (protojson camelCase) on that dict
always returns ``None``, so it is never a legitimate read — yet it is an easy
copy-paste slip in a failure-branch diagnostic, where it silently prints ``None``
and misleads the operator reading a failed assertion.

This is a STRUCTURAL-DISEASE guard, not a behavioral test: the defect lives only
in the assertion's failure message, so it never changes a passing run's outcome.
Two copies of the slip existed (``test_00_failure_05_no_billing_arrangement`` and
``test_offer_redemption``); this guard turns GREEN once both are migrated to
``denial_reason`` and FAILS if any reappears.

The detector is AST-based (a ``.get()`` call whose sole string argument is
``denialReason``), so there is no regex-slip case — positive + negative
meta-tests suffice. It is a pure source scan: it imports nothing from the running
stack, and ``stack_isolation("shared-without-cleanup")`` makes the autouse
dispatch fixture a no-op so it needs no docker-compose infra.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_E2E_ROOT = Path(__file__).resolve().parent.parent  # tests/e2e/
_SELF = Path(__file__).resolve()

# The camelCase key that is always None on the snake_case parsed item dict.
_FORBIDDEN_GET_KEY = "denialReason"


def _forbidden_get_linenos(tree: ast.AST) -> list[int]:
    """Lines of every ``<x>.get("denialReason")`` call in ``tree``."""
    hits: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and len(node.args) >= 1
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == _FORBIDDEN_GET_KEY
        ):
            hits.append(node.lineno)
    return hits


def _scan_e2e_tree() -> list[str]:
    """Return ``tests/e2e/<rel>:<line>`` for every forbidden ``.get()`` call."""
    hits: list[str] = []
    for path in sorted(_E2E_ROOT.rglob("*.py")):
        if path.resolve() == _SELF:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits.extend(
            f"tests/e2e/{path.relative_to(_E2E_ROOT)}:{lineno}"
            for lineno in _forbidden_get_linenos(tree)
        )
    return hits


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_no_camelcase_denial_reason_get_in_e2e() -> None:
    """No e2e .py reads the always-None ``.get("denialReason")`` on a snake item."""
    hits = _scan_e2e_tree()
    assert not hits, (
        f'Found {len(hits)} `.get("denialReason")` read(s) in tests/e2e/ — the parsed '
        f'item is snake_case, so this always returns None. Use `.get("denial_reason")`:\n  '
        + "\n  ".join(hits)
    )


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_flags_camelcase_get() -> None:
    """POSITIVE meta-test: the detector flags a ``.get("denialReason")`` call."""
    tree = ast.parse('x = item.get("denialReason")')
    assert len(_forbidden_get_linenos(tree)) == 1


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_snake_get() -> None:
    """NEGATIVE meta-test: the correct ``.get("denial_reason")`` is NOT flagged."""
    tree = ast.parse('x = item.get("denial_reason")')
    assert _forbidden_get_linenos(tree) == []
