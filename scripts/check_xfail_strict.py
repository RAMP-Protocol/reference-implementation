#!/usr/bin/env python3
"""Enforce ADR-008 D3: forbid pytest.mark.xfail(strict=False) under tests/.

docs/architecture/adr-008-testing-surface-isolation.md D3 requires every xfail
marker to be strict (``pytest.mark.xfail(strict=True)``). The lenient form
silently flips to xpass when production catches up, leaving the gap green; the
strict form breaks the build the moment the marker is no longer needed.

This check is AST-based, not a text grep: it flags *only* a call to ``xfail``
that carries ``strict=False``. A bare-token grep cannot tell that marker apart
from unrelated keyword arguments (e.g. a test helper's own ``strict`` parameter,
``zip(strict=False)``) or from the token appearing inside a docstring — those
are not ADR-008 D3 violations and must not fail the gate. The AST walk also
catches the multi-line marker form a single-line grep would miss.

Exits 0 when clean, 1 when a forbidden marker is found, 2 on a parse error.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = REPO_ROOT / "tests"

# Directories never scanned: virtual-envs, caches, vendored trees. Third-party
# code inside these uses strict=False legitimately and is not the gate's concern.
EXCLUDE_DIRS = frozenset(
    {
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        "node_modules",
    }
)


def _is_xfail_call(func: ast.expr) -> bool:
    """True when func names ``xfail`` (pytest.mark.xfail, mark.xfail, or a bare
    aliased ``xfail``)."""
    if isinstance(func, ast.Attribute):
        return func.attr == "xfail"
    if isinstance(func, ast.Name):
        return func.id == "xfail"
    return False


def _has_strict_false(call: ast.Call) -> bool:
    """True when the call carries a literal ``strict=False`` keyword."""
    return any(
        kw.arg == "strict"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is False
        for kw in call.keywords
    )


def _violations_in(path: Path) -> list[int]:
    """Return the line numbers of forbidden xfail(strict=False) calls in path."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _is_xfail_call(node.func)
        and _has_strict_false(node)
    ]


def _iter_test_files() -> list[Path]:
    return [
        p
        for p in TESTS_DIR.rglob("*.py")
        if not EXCLUDE_DIRS.intersection(p.parts)
    ]


def main() -> int:
    if not TESTS_DIR.is_dir():
        print(f"check_xfail_strict: tests/ not found at {TESTS_DIR}", file=sys.stderr)
        return 1

    findings: list[str] = []
    for path in sorted(_iter_test_files()):
        try:
            lines = _violations_in(path)
        except SyntaxError as exc:  # a malformed test file must not pass silently
            print(f"check_xfail_strict: cannot parse {path}: {exc}", file=sys.stderr)
            return 2
        rel = path.relative_to(REPO_ROOT)
        findings.extend(f"{rel}:{line}" for line in lines)

    if findings:
        joined = "\n".join(findings)
        print(
            "ADR-008 D3 violation — forbidden xfail(strict=False) under tests/:\n\n"
            f"{joined}\n\n"
            "Fix: change strict=False to strict=True. If the test currently passes\n"
            "under the strict marker, REMOVE the @pytest.mark.xfail decorator entirely\n"
            "(the test has become an honest regression guard). See\n"
            "docs/architecture/adr-008-testing-surface-isolation.md D3 for rationale.",
            file=sys.stderr,
        )
        return 1

    print("==> ADR-008 D3 check (no xfail(strict=False) under tests/) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
