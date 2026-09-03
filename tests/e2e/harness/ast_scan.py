"""The tree walk every source-scan guard in this package needs.

Four suites here answer the same question about different things: does any ``.py``
under ``tests/e2e/`` still contain a shape we have decided to be rid of? Each one
owns a matcher -- a redundant ``or``, a camelCase ``.get()``, a single-offer
request body, a body that does not stamp ``ver`` -- and each one used to own a
private copy of the walk that drives it, the root it walks from, and the helper
that reads a dict literal's string keys.

The copies had already drifted, in the way that matters most for a guard: what
they refuse to look at. ``no_redundant_or`` skipped ``node_modules``,
``ver_wire`` skipped ``.venv``, and ``denial_reason_key`` and
``single_offer_wire`` skipped neither -- so on a developer machine with a synced
virtualenv two of the four walked 3,861 files where the others walked 148. None
of that difference was a decision anyone made; it is what four independent
copies converge on. One walk with one exclusion set is what makes the four
guards agree on their own subject.

This module is deliberately not part of ``guard_harness``. That one exists to
drive a shipped script against a synthetic tree -- scratch git repositories,
gate runners, planted keys -- and a guard that only reads source needs none of
it.

It imports nothing beyond the standard library and reads no file outside
``tests/e2e/``, so importing it can never be what makes collection fail where
``scripts/`` is absent.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable
from pathlib import Path

E2E_ROOT = Path(__file__).resolve().parent.parent  # tests/e2e/

# Vendored trees: installed dependencies, not source this repository owns. A
# guard that walks into them reports on code no one here can edit, and pays for
# thousands of files to do it. Matched against path PARTS, so a directory of
# either name at any depth is skipped.
VENDORED_DIRS = frozenset({".venv", "node_modules"})

# A matcher reads one parsed file and returns (line, reason) for each offence.
# The reason may be empty when the guard's own failure message already says what
# the offence is; scan_tree then emits the location alone.
Matcher = Callable[[ast.AST], Iterable[tuple[int, str]]]


def dict_string_keys(node: ast.Dict) -> set[str]:
    """The literal string keys of ``node``.

    ``**spread`` entries and computed keys are ignored: they appear in
    ``node.keys`` as ``None`` or as a non-constant expression, and no wire body
    in this harness spells a key any way but a plain string literal.
    """
    return {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }


def source_files(*, exclude: Path | None = None) -> list[Path]:
    """Every ``.py`` this repository owns under ``tests/e2e/``, sorted.

    ``exclude`` drops one file, which each guard passes for itself: a guard's
    meta-cases spell the very shape it forbids, so scanning its own source would
    report its fixtures as offences.
    """
    skip = exclude.resolve() if exclude is not None else None
    return [
        path
        for path in sorted(E2E_ROOT.rglob("*.py"))
        if not (VENDORED_DIRS & set(path.parts)) and path.resolve() != skip
    ]


def scan_tree(matcher: Matcher, *, exclude: Path | None = None) -> list[str]:
    """Run ``matcher`` over every owned source file; return located offences.

    Each offence is rendered ``tests/e2e/<rel>:<line>``, with ``  <reason>``
    appended when the matcher supplied one. The path is relative so a failure
    message reads the same from the repository root, from ``tests/e2e/``, and
    from inside the runner image.
    """
    hits: list[str] = []
    for path in source_files(exclude=exclude):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(E2E_ROOT)
        hits.extend(
            f"tests/e2e/{rel}:{lineno}" + (f" — {reason}" if reason else "")
            for lineno, reason in matcher(tree)
        )
    return hits
