"""Shape gate on the e2e catalog feeds this harness owns.

The feeds under ``fixtures/catalog/`` back every catalog-driven scenario in the
suite. Most of what they carry is asserted only indirectly, by a scenario that
happens to pick one resource — so a term edited or dropped here surfaces as an
unrelated test failing for an unexplained reason, or not at all.

This test states the properties the suite depends on directly, so an edit that
breaks one fails here, at the file that changed.

The currency spread is the load-bearing one. The in-memory billing adapter
denominates every balance in ``billing.DemoCurrency`` ("USD"), so a USD term is
the only kind a funded buyer can transact: lose the USD terms and the priced
path loses its coverage while the suite still reports green. The EUR and GBP
terms are the currency-mismatch cases. The counts are pinned rather than merely
"more than one currency" because a silent drop of five of the nine USD terms
would still satisfy the looser check.

Reading the feeds is not reaching past a layer: this asserts on the fixture
INPUT, not on the state the system under test produced from it.
"""

from __future__ import annotations

import ast
import json
from collections import Counter
from pathlib import Path

import pytest

# Pure fixture-data test — no compose stack, no DB. Declare `isolated` so the
# autouse `_stack_isolation_dispatch` per-test cleanup chain (which needs a live
# Postgres DSN) is a no-op for this module.
pytestmark = pytest.mark.stack_isolation("isolated")

CATALOG_DIR = Path(__file__).resolve().parent / "fixtures" / "catalog"

FEEDS = ("philosophy.jsonl", "music.jsonl", "sfx.jsonl")

EXPECTED_CURRENCIES = {"EUR": 11, "USD": 9, "GBP": 6}
EXPECTED_RECORDS = 22
EXPECTED_TERMS = 26


def _records(name: str) -> list[dict]:
    path = CATALOG_DIR / name
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _all_records() -> list[dict]:
    return [record for name in FEEDS for record in _records(name)]


def _all_terms() -> list[dict]:
    return [term for record in _all_records() for term in record["terms"]]


@pytest.mark.parametrize("name", FEEDS)
def test_feed_is_parseable_jsonl(name: str) -> None:
    """Every line parses and carries the fields the ingest binary requires."""
    records = _records(name)
    assert records, f"{name} is empty"
    for record in records:
        for field in ("domain", "path", "terms"):
            assert field in record, f"{name}: record {record.get('path')} has no {field}"
        assert record["terms"], f"{name}: {record['path']} has no terms"


def test_record_and_term_counts() -> None:
    """The totals CATALOG-scale assertions and the README both quote."""
    assert len(_all_records()) == EXPECTED_RECORDS
    assert len(_all_terms()) == EXPECTED_TERMS


def test_currency_spread_is_preserved() -> None:
    """The three-currency mix the priced and mismatch paths both need.

    A drop to one currency silently removes either the funded-buyer priced path
    (USD) or the currency-mismatch cases (EUR, GBP).
    """
    counts = Counter(term["pricing"]["currency"] for term in _all_terms())
    assert dict(counts) == EXPECTED_CURRENCIES


def test_every_feed_has_a_free_term() -> None:
    """The EUR buyer is unfunded by construction, so it can only reach FREE terms.

    One per feed keeps that buyer usable on all three edge runtimes.
    """
    for name in FEEDS:
        rates = [
            term["pricing"].get("rate") for record in _records(name) for term in record["terms"]
        ]
        assert "0" in rates, f"{name} has no zero-rate term"


# ───── Ownership guard ──────────────────────────────────────────────────────


def _string_literals(tree: ast.AST) -> list[str]:
    """Every string constant in the module, comments excluded by construction."""
    return [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


def test_no_harness_module_builds_a_path_into_the_demo_fixtures() -> None:
    """The harness owns its catalog feeds; the demo fixtures belong to the deployment.

    The split is only real while nothing here reaches back across it. A module
    that rebuilds ``deploy/fixtures/demo/...`` gets a path that does not exist
    inside the runner image, which the Dockerfile no longer populates — and the
    failure surfaces as an ingest binary reporting "no such file or directory",
    minutes into an e2e run, far from the line that caused it.

    Read from the AST rather than the file text on purpose. Prose that mentions
    the old location is legitimate and appears in several comments; only a path
    actually constructed in code is a violation, and string constants are the
    only place such a path can come from.

    Both spellings are caught: the joined "deploy/fixtures/demo/x.jsonl" and the
    segment form Path("deploy") / "fixtures" / "demo", which a text search for
    the joined form misses. That second form is exactly how one survived the
    move.
    """
    harness = Path(__file__).resolve().parent
    offenders: list[str] = []
    for module in sorted(harness.glob("*.py")):
        if module.name == Path(__file__).name:
            continue
        literals = _string_literals(ast.parse(module.read_text()))
        joined = [v for v in literals if "deploy/fixtures/demo" in v]
        segments = {"deploy", "fixtures", "demo"}.issubset(set(literals))
        if joined or segments:
            offenders.append(f"{module.name}: {joined or 'built from segments'}")
    assert not offenders, (
        "harness modules must read their feeds from fixtures/catalog/, not from the "
        "deployment's demo fixtures:\n  " + "\n  ".join(offenders)
    )
