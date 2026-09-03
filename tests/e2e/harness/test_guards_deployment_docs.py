"""Meta-guard — the deployment-document list must have exactly one home.

Two tools act on that list: the agreement gate, which requires one ``VERSION=``
declaration per document and requires them all to match, and the release tool
that rewrites those lines. They used to hold a copy each and nothing compared
the two, which failed silently in one direction: a document the release tool
knew about and the gate did not was rewritten and then never checked, so it
could name a version nobody published while the gate reported PASS.

The case that matters here is the first one. It writes a definition listing a
FOURTH document, and then asserts that one edit changed the behavior of BOTH
tools — the gate now governs that document, and the release tool now rewrites it
and names its image. A tool that kept a private list, or re-declared one after
sourcing the shared file, fails its half. That is a property a search for a
stray array literal cannot establish and this can.

The rest are refusals. A definition that is missing, that lists nothing, or that
defines nothing under the expected name are all states where a tool could
plausibly do nothing and call it success, so each one is pinned to a message.

Pure subprocess work: no stack, no Docker, no network. Both remotes are local
bare repositories.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from .conftest import REPO_ROOT
from .deployment_docs import DECLARED_VERSION, DOCS, GATE, build_tree, doc_body
from .guard_harness import GIT_TIMEOUT, git, guard_marks, run_git

# The waiver marker must sit on the line itself or the one directly above it.
# published-ref-allow: a test that drives a script has to name it; the skip below says why it is absent
_RELEASE_TOOL = REPO_ROOT / "release-version.sh"

# Must match the release tool's own default: _run_release below never passes
# --branch, so a mismatch makes the tool refuse every case in this file.
_BRANCH = "master"
_NEW_VERSION = "1.0.0-rc.2"

# The document a shared-list edit adds. Its directory name is also its image
# name, which is what the release tool's epilogue derives.
_FOURTH_SERVICE = "newsvc"
_FOURTH_DOC = f"src/{_FOURTH_SERVICE}/DEPLOYMENT.md"

_FOUR_DOC_DEFINITION = (
    "#!/usr/bin/env bash\n"
    "DEPLOYMENT_DOCS=(\n" + "".join(f"  {doc}\n" for doc in (*DOCS, _FOURTH_DOC)) + ")\n"
)

pytestmark = guard_marks(
    skip_when=not _RELEASE_TOOL.is_file(),
    # published-ref-allow: the skip reason has to name what is missing
    reason="release-version.sh is not published, so it is absent from the runner image",
)


def _make_fixture(tmp_path: Path) -> tuple[Path, Path]:
    """A release branch with the shipped documents, plus two bare remotes."""
    repo = tmp_path / "repo"
    origin = tmp_path / "origin.git"
    public = tmp_path / "public.git"

    build_tree(repo, branch=_BRANCH, committer="deployment docs guard")
    for bare in (origin, public):
        git("init", "-q", "--bare", "-b", "main", str(bare))
    run_git(repo, "remote", "add", "origin", str(origin))
    run_git(repo, "remote", "add", "public", str(public))
    run_git(repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
    run_git(repo, "fetch", "-q", "origin")
    return repo, origin


def _commit_and_publish(repo: Path, message: str) -> None:
    """Land a fixture edit the way the release tool's preconditions require.

    It refuses a dirty tree, and it refuses a branch that is ahead of its remote.
    A test that edits the fixture and forgets this gets a refusal about unpushed
    commits instead of the behavior it meant to drive.
    """
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-qm", message)
    run_git(repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
    run_git(repo, "fetch", "-q", "origin")


def _write_four_doc_definition(repo: Path) -> None:
    """One edit: the shared list gains a document, and that document exists."""
    (repo / "scripts" / "deployment-docs.sh").write_text(_FOUR_DOC_DEFINITION)
    target = repo / _FOURTH_DOC
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(doc_body(_FOURTH_SERVICE))


def _run_release(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """The release tool, driven from inside ``repo``."""
    return subprocess.run(
        ["bash", str(_RELEASE_TOOL), *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=GIT_TIMEOUT,
    )


def _run_gate(repo: Path) -> subprocess.CompletedProcess[str]:
    """The gate, from the copy the fixture carries."""
    return subprocess.run(
        ["bash", str(repo / "scripts" / GATE.name), "--root", str(repo)],
        capture_output=True,
        text=True,
        check=False,
        timeout=GIT_TIMEOUT,
    )


def _declared(repo: Path, doc: str) -> str:
    lines = (repo / doc).read_text().splitlines()
    return next(line[len("VERSION=") :] for line in lines if line.startswith("VERSION="))


# ---------------------------------------------------------------------------
# One list, both tools
# ---------------------------------------------------------------------------


def test_a_document_added_to_the_shared_list_becomes_governed_by_the_gate(
    tmp_path: Path,
) -> None:
    """The half that used to fail silently.

    Before the list was shared, a document the gate did not know about could
    declare anything at all and the gate still printed PASS — its commands use
    the sanctioned ``:$VERSION`` form, so no other rule looks at it either. Here
    the fourth document disagrees with the other three, and the gate has to say
    so and name it.
    """
    repo, _ = _make_fixture(tmp_path)
    _write_four_doc_definition(repo)
    (repo / _FOURTH_DOC).write_text(doc_body(_FOURTH_SERVICE, version="0.9.0"))
    _commit_and_publish(repo, "add a fourth deployment document")

    proc = _run_gate(repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode == 1, combined
    assert "different versions" in proc.stdout, combined
    assert f"{_FOURTH_DOC}: 0.9.0" in proc.stdout, combined


def test_a_document_added_to_the_shared_list_is_rewritten_by_the_release_tool(
    tmp_path: Path,
) -> None:
    """The other half, driven by the SAME edit as the case above.

    One file changed, and both tools moved. If the release tool had kept a list
    of its own, the fourth document would keep its old version here and the
    commit would touch three paths.
    """
    repo, origin = _make_fixture(tmp_path)
    _write_four_doc_definition(repo)
    _commit_and_publish(repo, "add a fourth deployment document")
    head_before = _head(repo)

    proc = _run_release(repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    for doc in (*DOCS, _FOURTH_DOC):
        assert _declared(repo, doc) == _NEW_VERSION, f"{doc} was not rewritten\n{combined}"

    changed = run_git(repo, "show", "--name-only", "--pretty=format:", "HEAD").stdout.split()
    assert sorted(changed) == sorted((*DOCS, _FOURTH_DOC)), combined
    assert run_git(repo, "rev-parse", "HEAD~1").stdout.strip() == head_before, combined
    assert git("-C", str(origin), "rev-parse", f"refs/heads/{_BRANCH}").stdout.strip() == _head(
        repo
    ), combined


def test_the_epilogue_names_every_image_the_shared_list_implies(tmp_path: Path) -> None:
    """The epilogue is a view of the list, so it moves with the list.

    It used to spell the three image names out. A release that added a fourth
    service would have told the operator to check three of the four images it had
    just published, and the missing one is exactly the one nobody would think to
    look at.
    """
    repo, _ = _make_fixture(tmp_path)
    _write_four_doc_definition(repo)
    _commit_and_publish(repo, "add a fourth deployment document")

    proc = _run_release(repo, _NEW_VERSION, "--yes")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    for service in ("exchange", "broker", "identity", _FOURTH_SERVICE):
        expected = f"docker pull ghcr.io/ramp-protocol/{service}:{_NEW_VERSION}"
        assert expected in proc.stdout, f"missing: {expected}\n{proc.stdout}"


# ---------------------------------------------------------------------------
# A definition that cannot be used is refused, never worked around
# ---------------------------------------------------------------------------


# Each broken definition, with the wording the tool owes the reader for it.
#
# The expected fragment is per case on purpose. A single loose assertion — "the
# filename appears somewhere" — is satisfied by bash's own "No such file or
# directory", so it cannot tell the tool's diagnosis apart from a raw error, and
# the check that produces the diagnosis could be deleted with the suite still
# passing. Measured: it was.
_BROKEN_DEFINITIONS = [
    # No file at all: a tree that shipped the gate and not its list.
    ("missing", None, "cannot read", "is missing"),
    # Present and empty. Both tools would otherwise loop over nothing — silently
    # on bash 5, and under the bash 3.2 that macOS ships with an "unbound
    # variable" from a line the reader did not write.
    (
        "empty",
        "#!/usr/bin/env bash\nDEPLOYMENT_DOCS=()\n",
        "lists no deployment documents",
        "lists no documents",
    ),
    # Sources cleanly, defines nothing under the expected name: what a
    # half-finished rename leaves behind, and the state where a tool is most
    # likely to carry on as though the list were simply short.
    (
        "wrong name",
        "#!/usr/bin/env bash\nDOCS=(\n  src/exchange/DEPLOYMENT.md\n)\n",
        "defines no DEPLOYMENT_DOCS",
        "defines no DEPLOYMENT_DOCS",
    ),
]


def _break_definition(repo: Path, name: str, body: str | None) -> None:
    definition = repo / "scripts" / "deployment-docs.sh"
    if body is None:
        definition.unlink()
    else:
        definition.write_text(body)
    _commit_and_publish(repo, f"break the shared definition: {name}")


@pytest.mark.parametrize(
    ("name", "body", "expected"),
    [(name, body, gate_msg) for name, body, gate_msg, _ in _BROKEN_DEFINITIONS],
)
def test_the_gate_refuses_a_definition_it_cannot_use(
    tmp_path: Path, name: str, body: str | None, expected: str
) -> None:
    """No PASS, and a sentence that says which of the three things went wrong."""
    repo, _ = _make_fixture(tmp_path)
    _break_definition(repo, name, body)

    proc = _run_gate(repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "PASS" not in proc.stdout, combined
    assert expected in combined, combined


@pytest.mark.parametrize(
    ("name", "body", "expected"),
    [(name, body, tool_msg) for name, body, _, tool_msg in _BROKEN_DEFINITIONS],
)
def test_the_release_tool_refuses_a_definition_it_cannot_use(
    tmp_path: Path, name: str, body: str | None, expected: str
) -> None:
    """It refuses, says why, and leaves every document alone.

    A tool that stopped for the right reason but had already rewritten something
    would still have to be cleaned up by hand.
    """
    repo, _ = _make_fixture(tmp_path)
    _break_definition(repo, name, body)
    head_before = _head(repo)

    proc = _run_release(repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert expected in combined, combined
    for doc in DOCS:
        assert _declared(repo, doc) == DECLARED_VERSION, f"{doc} was edited\n{combined}"
    assert _head(repo) == head_before, combined
    assert run_git(repo, "status", "--porcelain").stdout == "", combined


def _head(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD").stdout.strip()
