"""Meta-guard — the unresolvable-reference gate must never pass without reading.

``scripts/check-published-refs.sh`` is the only thing standing between the
published tree and pointers a public reader cannot open. It is wired into
``make quality``, so a green quality run is taken as evidence that no such
pointer exists.

That evidence is only worth anything if the gate can fail. It once could not:
``grep``'s "No such file or directory" went to a muted stderr and its non-zero
exit was swallowed by ``|| true``, so a renamed top-level directory silently
deleted the gate's coverage and it reported PASS having scanned nothing at all.
The same shape had already cost the publish tool two broken gates, one of which
returned success at the exact moment it found a stray file.

A guard that can go blind needs a test that watches it, and this is that test.
The four cases below are one per failure mode the gate has to survive:

    clean tree           -> PASS          (it does not cry wolf)
    planted violation    -> FAIL          (it can still see)
    missing search root  -> FAIL loudly   (it refuses to guess)
    waiver on the line   -> PASS          (the documented escape hatch works)

The third is the one that matters. The other three could all pass while the gate
scanned an empty tree.

Unlike its sibling guards, the subject here is a shell script rather than Python
source, so there is no pure detector function to feed inline snippets to. The
cases build synthetic trees under ``tmp_path`` and run the real script against
them through its ``--root`` argument — the seam exists for exactly this, and
testing the shipped artifact rather than a reimplementation of it is the point.
An argument rather than an environment variable, because a variable that selects
what a gate reads can redirect it in production too.

Pure subprocess work: no stack, no Docker, no database. The marks come from
``guard_harness.guard_marks``, whose docstring says why the isolation one is
there.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .conftest import REPO_ROOT
from .guard_harness import guard_marks, run_gate
from .published_paths import shared_array as _shared_array

# REPO_ROOT rather than a parents[N] walk: inside the runner container the
# harness sits at /runner/harness, which has fewer parents than the host layout,
# and computing the walk here raises at import — killing collection for the whole
# tier rather than this one module.
_GATE = REPO_ROOT / "scripts" / "check-published-refs.sh"

# The skip covers the container leg: scripts/ is not COPYed into the runner image
# and not bind-mounted, so there is nothing to drive there. The host `test-fast`
# target runs this module on every commit, so the skip costs no coverage.
pytestmark = guard_marks(skip_when=not _GATE.is_file())

# One reference of each kind the gate exists to reject. All are resolvable in
# this repository and unresolvable in the published one, which is the whole
# distinction under test.
# published-ref-allow: the fixture a gate is tested with has to be a real violation
_FULL_PATH_VIOLATION = "# see docs/design/design-exchange.md for the layering\n"
# An unpublished doc that exists only in the fixture tree. The gate derives its
# bare-basename patterns from whatever docs/*.md it finds outside
# docs/architecture, so the name the violation cites has to be a name the fixture
# actually creates — hence one constant used by both.
_UNPUBLISHED_DOC = "unpublished-note.md"
# The same class of target named WITHOUT the docs/ prefix. This is the form a
# path search misses, and it is caught only by that derived basename list — a
# half of the gate no case reached while the fixture contained no docs/*.md
# outside docs/architecture.
_BARE_NAME_VIOLATION = f"# see {_UNPUBLISHED_DOC} for the layering\n"
# published-ref-allow: as above
_CLAUDE_MD_VIOLATION = "# the repository conventions in CLAUDE.md require this\n"
_WAIVED_VIOLATION = (
    # published-ref-allow: as above — this one also demonstrates the waiver itself
    "# published-ref-allow: illustrating the escape hatch\n"
    "# see docs/design/design-exchange.md for the layering\n"
)
# A doc the publish tool puts ON the public tree even though this repo does not
# build it. Citing one is resolvable and must NOT be rejected.
_INHERITED_CITATION = "# the deployment walkthrough is in docs/HANDOFF-aws-demo.md\n"


def _build_tree(root: Path) -> None:
    """Materialise the minimum tree the gate considers a complete search set.

    Every directory, root file and allowlisted script named by the shared
    definition has to exist, because a missing one is itself a failure the gate
    reports — that is the behaviour the missing-root case asserts.

    The unpublished doc is not decoration. The gate derives the bare-basename
    half of its pattern set from whatever ``docs/*.md`` exists outside
    ``docs/architecture``; with none present that half compiles to nothing and
    never runs, which is how four separate ways of breaking the gate once passed
    this suite.
    """
    for directory in _shared_array("ALLOW_DIRS"):
        (root / directory).mkdir(parents=True, exist_ok=True)
    for name in _shared_array("ALLOW_ROOT_FILES"):
        (root / name).touch()
    for script in _shared_array("ALLOW_SCRIPTS"):
        dest = root / script
        dest.parent.mkdir(parents=True, exist_ok=True)
        src = REPO_ROOT / script
        # The two the gate itself needs are copied verbatim; the rest only have
        # to exist, since the gate requires every allowlisted script as a root.
        dest.write_bytes(src.read_bytes() if src.is_file() else b"")

    (root / "docs" / _UNPUBLISHED_DOC).write_text("# not a published doc\n")
    for inherited in _shared_array("INHERIT_FROM_MAIN"):
        target = root / inherited
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


def _run_gate(root: Path) -> subprocess.CompletedProcess[str]:
    """This gate's parameters. The mechanics are shared, and only these differ."""
    return run_gate(root, _GATE.name)


def test_gate_passes_on_a_clean_tree(tmp_path: Path) -> None:
    """A tree with no dangling pointers is reported clean."""
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text("# ordinary configuration\n")

    proc = _run_gate(tmp_path)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS" in proc.stdout, proc.stdout


def test_gate_flags_a_reference_in_a_published_root_file(tmp_path: Path) -> None:
    """A pointer into an unpublished docs/ path fails, naming file and line.

    ``docker-compose.yml`` is deliberate: the root build files ship, and were
    once outside the gate's search set entirely, so two live pointers passed
    clean for as long as that list was maintained by hand.
    """
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(_FULL_PATH_VIOLATION)

    proc = _run_gate(tmp_path)

    assert proc.returncode == 1, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "docker-compose.yml:1:" in proc.stdout, proc.stdout


def test_gate_fails_loudly_when_a_search_root_is_absent(tmp_path: Path) -> None:
    """A missing search root aborts — it must never be read as "nothing found".

    This is the regression the whole file exists for. The gate previously
    reported PASS here, so every other assertion in this module could hold while
    it scanned an empty tree.
    """
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(_FULL_PATH_VIOLATION)
    # Rename a top-level directory the way an ordinary refactor would.
    (tmp_path / "src").rename(tmp_path / "src_moved")

    proc = _run_gate(tmp_path)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, f"gate passed with a missing search root:\n{combined}"
    assert "search root" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_gate_flags_a_bare_filename(tmp_path: Path) -> None:
    """A doc named without its docs/ prefix is the same violation.

    This is the form a path search misses, and the only case that exercises the
    basename list the gate derives from the unpublished docs on disk. Without it,
    that derivation can be deleted outright and this suite stays green.
    """
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(_BARE_NAME_VIOLATION)

    proc = _run_gate(tmp_path)

    assert proc.returncode == 1, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "docker-compose.yml:1:" in proc.stdout, proc.stdout


def test_gate_accepts_a_citation_of_an_inherited_doc(tmp_path: Path) -> None:
    """A doc the publish PUTS on the public tree is resolvable, not dangling.

    The basename derivation sweeps in every ``docs/*.md`` outside
    ``docs/architecture``, which includes the aws-demo handoff — a file this repo
    does not build but the publish inherits onto the public branch. Subtracting
    the inherited set is what keeps citing one legal, and nothing else in this
    suite notices if that subtraction is removed.
    """
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(_INHERITED_CITATION)

    proc = _run_gate(tmp_path)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"


def test_gate_flags_a_reference_to_the_conventions_file(tmp_path: Path) -> None:
    # published-ref-allow: naming the file under test is unavoidable here
    """The conventions file does not travel, so naming it is a dangling pointer.

    One case per pattern family the gate carries, so deleting a family from the
    pattern list cannot pass unnoticed.
    """
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(_CLAUDE_MD_VIOLATION)

    proc = _run_gate(tmp_path)

    assert proc.returncode == 1, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"


def test_gate_scans_published_scripts(tmp_path: Path) -> None:
    """A violation inside an allowlisted script is caught.

    The published scripts are search roots in their own right. Before that, they
    were reached through a prefix denylist standing in for "not published", which
    skipped any published script whose name happened to match one of its
    prefixes.
    """
    _build_tree(tmp_path)
    (tmp_path / "scripts" / "devstack.sh").write_text(_FULL_PATH_VIOLATION)

    proc = _run_gate(tmp_path)

    assert proc.returncode == 1, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "scripts/devstack.sh:1:" in proc.stdout, proc.stdout


def test_waiver_comment_suppresses_a_deliberate_reference(tmp_path: Path) -> None:
    """The documented per-line escape hatch works, on the preceding line."""
    _build_tree(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(_WAIVED_VIOLATION)

    proc = _run_gate(tmp_path)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS" in proc.stdout, proc.stdout
