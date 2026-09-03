"""Meta-guard — the image-version gate must actually catch a partial release edit.

The three deployment documents used to name the published image version twelve
times between them. They now declare it once each, and every command in a
document reuses that variable. The gate under test is what keeps that shape: it
forbids a literal version tag on a published image, requires exactly one
declaration per document, and requires the three to agree.

The rule that matters is the third. A release edits three lines, and forgetting
one leaves a document naming a tag nobody published — which reads as correct
right up to the operator's "not found". Nothing else in the suite would notice.

The first rule is a subtraction rather than a list of forbidden shapes: every
tagged reference to a published image is collected, and the sanctioned forms are
taken out of it. So the cases below cover more than a version literal — :latest
and a v-prefixed tag are both misses from the sanctioned set, and a rule that
enumerated forbidden shapes let them both through.

Every case asserts on the gate's own wording rather than on its exit code. Most
of them exit non-zero, so a code-only assertion would let one pass while a
different rule fired.

Pure subprocess work: no stack, no Docker, no database. The marks come from
``guard_harness.guard_marks``, whose docstring says why the isolation one is
there. The fixture — the three documents, the scan roots, the tree builder —
lives in ``deployment_docs``, because the suite guarding the release tool needs
exactly the same one.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from .deployment_docs import (
    DECLARED_VERSION,
    GATE,
    SCAN_ROOTS,
    build_tree,
    copy_gate_into,
    doc_body,
    write_docs,
)
from .guard_harness import commit_all, guard_marks, run_gate

_VERSION = DECLARED_VERSION

pytestmark = guard_marks(skip_when=not GATE.is_file())


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    build_tree(root, branch="main", committer="image version guard")
    return root


def _run_gate(root: Path) -> subprocess.CompletedProcess[str]:
    """This gate's parameters. The mechanics are shared, and only these differ."""
    return run_gate(root, GATE.name)


def test_gate_passes_on_a_clean_tree(tree: Path) -> None:
    """Three documents, one declaration each, all agreeing.

    Without this the negative cases below prove nothing: a gate that failed for
    an unrelated reason would satisfy every one of them.
    """
    proc = _run_gate(tree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    # The agreed version is in the PASS line, so a reader of CI output can see
    # what the gate concluded rather than only that it concluded something.
    assert f"PASS  the deployment documents agree on one image version ({_VERSION})" in proc.stdout


@pytest.mark.parametrize(
    "tag",
    [
        # A hardcoded version is how the twelve-site version would come back:
        # one line at a time, in a file nobody re-reads.
        "9.9.9",
        # A moving minor pointer, which ADR-024 D2 rules out along with :latest.
        "1.0",
        # ADR-024 D2 forbids this one by name, and this guard is the only
        # automated defence of that decision.
        "latest",
        # Never resolves. The workflow strips the leading v, so the registry only
        # ever holds the bare version, and a document written this way sends the
        # operator to a "not found" — the defect the documents were rewritten to
        # remove.
        "v9.9.9",
        # The sanctioned :dev has to match a whole tag, not a prefix of one.
        "development",
    ],
)
def test_an_unsanctioned_tag_is_rejected(tree: Path, tag: str) -> None:
    """Anything outside the sanctioned set is reported, not just a version.

    The rule collects every tagged reference and subtracts the sanctioned forms.
    Enumerating forbidden shapes instead is what let the last three of these
    parameters through while the gate printed PASS.
    """
    (tree / "docs" / "some-note.md").write_text(f"image: ghcr.io/ramp-protocol/broker:{tag}\n")
    commit_all(tree, f"add a note pinning :{tag}")

    proc = _run_gate(tree)

    assert proc.returncode == 1, proc.stdout
    assert "unsanctioned image tag" in proc.stdout, proc.stdout
    # The file has to be named, or the reader has to grep for it themselves.
    assert "docs/some-note.md" in proc.stdout, proc.stdout


def test_the_braced_variable_form_is_sanctioned(tree: Path) -> None:
    """``:${VERSION}`` is the same reference as ``:$VERSION``, not a literal.

    Rejecting it would fail the line with a message saying it pinned a version,
    which is untrue of either spelling. This pins the sanctioned set from the
    side the negative cases above cannot reach.
    """
    (tree / "docs" / "compose-note.md").write_text(
        "image: ghcr.io/ramp-protocol/broker:${VERSION}\n"
    )
    commit_all(tree, "add a note using the braced form")

    proc = _run_gate(tree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS" in proc.stdout, proc.stdout


def test_an_untracked_file_is_ignored(tree: Path) -> None:
    """A draft nobody publishes is not a defect in what ships.

    The working copy holds scratch notes, and failing the build over a version
    string in one would be an alarm about a file that never leaves the machine.
    Same reason the secret scan reads the tracked list rather than the disk.
    """
    (tree / "docs" / "scratch.md").write_text("image: ghcr.io/ramp-protocol/broker:9.9.9\n")

    proc = _run_gate(tree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "PASS" in proc.stdout, proc.stdout


def test_an_uncommitted_edit_to_a_tracked_file_is_rejected(tree: Path) -> None:
    """Tracked-only reads the file LIST from git, and the content from disk.

    Otherwise the gate would pass on the commit that introduces the violation and
    only fail on the next one, which is the wrong commit to fail.
    """
    (tree / "docs" / "some-note.md").write_text("placeholder\n")
    commit_all(tree, "add a note")
    (tree / "docs" / "some-note.md").write_text("image: ghcr.io/ramp-protocol/broker:9.9.9\n")

    proc = _run_gate(tree)

    assert proc.returncode == 1, proc.stdout
    assert "unsanctioned image tag" in proc.stdout, proc.stdout


def test_a_tree_that_is_not_a_git_repository_is_refused(tmp_path: Path) -> None:
    """Refusing beats reporting clean on a tree it could not read.

    The tracked-file list is the whole basis of the first rule. Without a
    repository there is none, and an empty list would let every later check pass
    having examined nothing.
    """
    root = tmp_path / "plain"
    for directory in SCAN_ROOTS:
        (root / directory).mkdir(parents=True, exist_ok=True)
    write_docs(root)
    copy_gate_into(root)

    proc = _run_gate(root)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "not a git repository" in combined, combined
    assert "PASS" not in proc.stdout, combined


def test_a_document_with_no_declaration_is_rejected(tree: Path) -> None:
    """Deleting the declaration is how the reduction gets reverted."""
    (tree / "src/broker/DEPLOYMENT.md").write_text(doc_body("broker", declarations=0))

    proc = _run_gate(tree)

    assert proc.returncode == 1, proc.stdout
    assert "src/broker/DEPLOYMENT.md: 0 VERSION= declaration(s)" in proc.stdout, proc.stdout


def test_a_document_with_two_declarations_is_rejected(tree: Path) -> None:
    """Two declarations is the half-done edit: one of them is already stale."""
    (tree / "src/identity/DEPLOYMENT.md").write_text(doc_body("identity", declarations=2))

    proc = _run_gate(tree)

    assert proc.returncode == 1, proc.stdout
    assert "src/identity/DEPLOYMENT.md: 2 VERSION= declaration(s)" in proc.stdout, proc.stdout


def test_one_document_declaring_a_different_version_is_rejected(tree: Path) -> None:
    """The partial release edit — the case this gate exists for.

    Every document is individually well-formed, so rules 1 and 2 both pass. Only
    comparing them across files catches it.
    """
    (tree / "src/broker/DEPLOYMENT.md").write_text(doc_body("broker", version="0.9.0"))

    proc = _run_gate(tree)

    assert proc.returncode == 1, proc.stdout
    assert "different versions" in proc.stdout, proc.stdout
    # All three are listed, so the odd one out is visible without opening a file.
    assert "src/broker/DEPLOYMENT.md: 0.9.0" in proc.stdout, proc.stdout
    assert f"src/exchange/DEPLOYMENT.md: {_VERSION}" in proc.stdout, proc.stdout
