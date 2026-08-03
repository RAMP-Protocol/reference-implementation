"""Structural guard — e2e source MUST NOT contain a redundant ``X or X`` operand.

The camelCase→snake rename left a crop of no-op ``payload.get("k") or
payload.get("k")`` residue (``a or a`` evaluates to ``a``): cosmetic dead code
that reads as a deliberate fallback but expresses nothing. Twelve copies existed
across the harness and obligation suites; this guard turns GREEN once every
duplicated operand is collapsed and FAILS if any reappears (e.g. a future
copy-paste that ORs a ``.get()`` with itself).

This is a STRUCTURAL-DISEASE guard, not a behavioral test: ``a or a`` and ``a``
compute the same value, so it never changes a passing run's outcome. The detector
is AST-based — a ``BoolOp(Or)`` with two STRUCTURALLY IDENTICAL adjacent operands
(compared via ``ast.dump``) — so there is no regex-slip case and positive +
negative meta-tests suffice. It is a pure source scan: it imports nothing from the
running stack, and ``stack_isolation("shared-without-cleanup")`` makes the autouse
dispatch fixture a no-op so it needs no docker-compose infra.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_E2E_ROOT = Path(__file__).resolve().parent.parent  # tests/e2e/
_SELF = Path(__file__).resolve()


def _redundant_or_linenos(tree: ast.AST) -> list[int]:
    """Lines of every ``... or ...`` whose adjacent operands are identical."""
    hits: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or)):
            continue
        dumps = [ast.dump(v) for v in node.values]
        if any(a == b for a, b in zip(dumps, dumps[1:], strict=False)):
            hits.append(node.lineno)
    return hits


def _scan_e2e_tree() -> list[str]:
    """Return ``tests/e2e/<rel>:<line>`` for every redundant ``X or X``."""
    hits: list[str] = []
    for path in sorted(_E2E_ROOT.rglob("*.py")):
        if path.resolve() == _SELF or "node_modules" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        hits.extend(
            f"tests/e2e/{path.relative_to(_E2E_ROOT)}:{lineno}"
            for lineno in _redundant_or_linenos(tree)
        )
    return hits


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_no_redundant_or_in_e2e() -> None:
    """No e2e .py ORs an expression with a structurally identical copy of itself."""
    hits = _scan_e2e_tree()
    assert not hits, (
        f"Found {len(hits)} redundant `X or X` operand(s) in tests/e2e/ — `a or a` "
        f"is just `a`. Delete the duplicated operand:\n  " + "\n  ".join(hits)
    )


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_flags_duplicated_operand() -> None:
    """POSITIVE meta-test: ``x or x`` (and ``x or x or []``) are flagged."""
    assert len(_redundant_or_linenos(ast.parse('a = p.get("k") or p.get("k")'))) == 1
    assert len(_redundant_or_linenos(ast.parse('a = p.get("k") or p.get("k") or []'))) == 1


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_guard_ignores_distinct_operands() -> None:
    """NEGATIVE meta-test: a genuine ``a or b`` fallback is NOT flagged."""
    assert _redundant_or_linenos(ast.parse('a = p.get("k") or []')) == []
    assert _redundant_or_linenos(ast.parse("a = not x or x.length == 0")) == []
