"""Meta-guard — the release tool must refuse every release it says it refuses.

The tool under test rewrites the one ``VERSION=`` line in each of the three
deployment documents, runs the agreement gate over the result, commits, and
pushes that commit to the private remote. Everything after that — publishing the
source snapshot and tagging the public commit — stays in the operator's hands.

Two of its rules carry most of the weight, and both are here in force:

The version grammar. The publishing workflow derives the image tag from the git
tag with a semver rule. A version with a leading zero produces no tag at all and
the workflow stops, AFTER the three documents have been bumped and pushed. A
version carrying build metadata is worse, because it fails quietly: the image
publishes under a shorter name while all three documents name the longer one, and
the agreement gate reports PASS because the three agree with each other.

The rollback, which covers everything from the first rewrite to the commit. The
documents are rewritten one at a time and then checked, so a failure anywhere in
that window can leave some rewritten and others not — or, past the gate, all of
them rewritten and staged. Four cases drive it from both ends: a gate that always
refuses, a document that cannot be written partway through the loop, a commit
that a hook rejects, and a push that fails after the commit landed, where the
restore is disarmed and has to stay silent.

Pure subprocess work: no stack, no Docker, no network. Both remotes are local
bare repositories, so ``git fetch``, ``git ls-remote`` and ``git push`` all run
for real against something on disk.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest

from .conftest import REPO_ROOT
from .deployment_docs import DECLARED_VERSION, DOCS, build_tree, doc_body
from .guard_harness import GIT_TIMEOUT, git, guard_marks, run_git

# A file mode does not stop uid 0, so the cases that make a document read-only
# would quietly become happy-path runs under root and assert nothing at all.
_ROOT_IGNORES_FILE_MODES = pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root writes through a read-only file, so this failure cannot be staged",
)

# The waiver marker must sit on the line itself or the one directly above it —
# a second explanatory line in between puts it out of the gate's reach.
# published-ref-allow: a test that drives a script has to name it; the skip below says why it is absent
_SCRIPT = REPO_ROOT / "release-version.sh"

# The branch the tool refuses to run anywhere but on. Every assertion below that
# names a branch interpolates this constant rather than repeating the literal, so
# renaming the release branch is one edit here and not a hunt for stale copies.
_BRANCH = "master"

# What the fixture bumps TO. Free of every tag in the fixture, so the
# tag-already-taken rule stays out of the way of the cases about other rules.
_NEW_VERSION = "1.0.0-rc.2"

# The tool is local-only and deliberately absent from the published tree, so it
# is not in the runner image either. Skipping keeps the suite honest where it
# cannot run; the host per-commit tier is where it does.
pytestmark = guard_marks(
    skip_when=not _SCRIPT.is_file(),
    # published-ref-allow: the skip reason has to name what is missing
    reason="release-version.sh is not published, so it is absent from the runner image",
)


class Fixture(NamedTuple):
    """The working repository and the two bare repositories standing in for remotes."""

    repo: Path
    origin: Path
    public: Path


def _make_fixture(tmp_path: Path, *, push_branch: bool = True) -> Fixture:
    """A release branch with the three documents, and two bare remotes on disk.

    ``push_branch`` is what the missing-tracking-ref case turns off. Everything
    else needs the branch on the remote, because the tool compares against it.
    """
    repo = tmp_path / "repo"
    origin = tmp_path / "origin.git"
    public = tmp_path / "public.git"

    build_tree(repo, branch=_BRANCH, committer="release guard")
    for bare in (origin, public):
        git("init", "-q", "--bare", "-b", "main", str(bare))

    run_git(repo, "remote", "add", "origin", str(origin))
    run_git(repo, "remote", "add", "public", str(public))
    if push_branch:
        run_git(repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
        run_git(repo, "fetch", "-q", "origin")

    return Fixture(repo=repo, origin=origin, public=public)


@pytest.fixture
def tree(tmp_path: Path) -> Fixture:
    return _make_fixture(tmp_path)


def _run(
    repo: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Drive the real tool from inside ``repo``.

    The working directory is what selects the tree — the tool resolves its
    repository with ``git rev-parse --show-toplevel`` — so there is no argument
    that could redirect a real run somewhere else.

    stdin is /dev/null on purpose. The tool refuses to start when it cannot ask
    for confirmation, and inheriting pytest's stdin would make that rule fire or
    not depending on whether the suite was run from a terminal.

    ``env`` exists only so one case can point TMPDIR at a directory it can count
    afterwards. It selects where scratch files are written, never which tree is
    read — the same line the shared gate runner draws around its own ``env``.
    Callers merge rather than replace: a bare dict would drop PATH, HOME and
    every GIT_* variable out from under the tool.
    """
    return subprocess.run(
        ["bash", str(_SCRIPT), *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=GIT_TIMEOUT,
        env=env,
    )


def _head(repo: Path) -> str:
    return run_git(repo, "rev-parse", "HEAD").stdout.strip()


def _declared(repo: Path, docs: tuple[str, ...] = DOCS) -> list[str]:
    """The version each document declares right now.

    ``docs`` is a parameter because the suite that proves both tools read one
    shared list drives a tree with a fourth document, and the default here is the
    three-entry literal that would not see it.
    """
    values = []
    for doc in docs:
        lines = (repo / doc).read_text().splitlines()
        values += [line[len("VERSION=") :] for line in lines if line.startswith("VERSION=")]
    return values


def _assert_untouched(
    tree: Fixture,
    head_before: str,
    proc: subprocess.CompletedProcess[str],
    docs: tuple[str, ...] = DOCS,
) -> None:
    """No edit, no commit, nothing staged.

    Asserted after every refusal. A tool that refuses AND leaves the tree changed
    has done the damage anyway, and the exit code alone would not show it.

    ``docs`` carries the same reason as the one on ``_declared``.
    """
    combined = proc.stdout + proc.stderr
    assert _head(tree.repo) == head_before, combined
    assert run_git(tree.repo, "status", "--porcelain").stdout == "", combined
    assert _declared(tree.repo, docs) == [DECLARED_VERSION] * len(docs), combined


# ---------------------------------------------------------------------------
# The version grammar
# ---------------------------------------------------------------------------


def test_a_leading_v_is_refused_by_name(tree: Fixture) -> None:
    """The git tag carries the v and the image tag does not.

    A generic "not valid semver" would send the operator looking for a different
    mistake, so this one gets its own message naming the version without the v.
    """
    head_before = _head(tree.repo)

    proc = _run(tree.repo, f"v{_NEW_VERSION}", "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "no leading v" in combined, combined
    assert f"use '{_NEW_VERSION}'" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_build_metadata_is_refused_with_the_reason(tree: Fixture) -> None:
    """The one bad version that would otherwise fail silently.

    A + cannot appear in a Docker tag, and semver precedence ignores everything
    after it, so the image would publish as 1.0.0 while the documents told the
    operator to pull 1.0.0+build.5. The agreement gate would report PASS, because
    all three documents would agree with each other.
    """
    head_before = _head(tree.repo)

    proc = _run(tree.repo, "1.0.0+build.5", "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "build metadata is refused" in combined, combined
    # The message has to say what WOULD have been published, or the reader has no
    # way to see why this is different from an ordinary format complaint.
    assert "publish as '1.0.0'" in combined, combined
    _assert_untouched(tree, head_before, proc)


@pytest.mark.parametrize(
    "version",
    [
        # Short forms. The action parses neither.
        "1.0",
        "1",
        # Leading zeros are not semver, in any of the three positions.
        "01.0.0",
        "1.00.0",
        "1.0.0-01",
        # An empty prerelease part. The trailing dot is easy to leave behind when
        # editing a version by hand.
        "1.0.0-rc.2.",
        # Not a version at all.
        "latest",
        # A whole-string match is what rejects this. grep anchors per LINE, so a
        # piped grep would read the first line, find a valid version, and accept
        # a value whose second line is a command.
        "1.0.0\nrm -rf /",
    ],
)
def test_a_version_the_workflow_could_not_build_is_refused(tree: Fixture, version: str) -> None:
    """Each of these produces an empty tag list in the publishing workflow.

    That run fails, but only after these documents have been bumped, committed and
    pushed — which is the "names a tag nobody published" state the whole mechanism
    exists to prevent.
    """
    head_before = _head(tree.repo)

    proc = _run(tree.repo, version, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "not a valid semver version" in combined, combined
    _assert_untouched(tree, head_before, proc)


# ---------------------------------------------------------------------------
# Preconditions on the repository
# ---------------------------------------------------------------------------


def test_a_run_from_another_branch_is_refused(tree: Fixture) -> None:
    """The push refspec is built from the branch name, so this can only ever
    push the branch the operator is standing on."""
    run_git(tree.repo, "checkout", "-q", "-b", "some-feature")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert f"on branch 'some-feature', expected '{_BRANCH}'" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_a_dirty_working_tree_is_refused(tree: Fixture) -> None:
    """Two things depend on a clean tree.

    The commit adds three named paths and must not sweep in anything else, and
    the rollback restores those three files, which would discard uncommitted work
    sitting in them.
    """
    (tree.repo / "docs" / "scratch.md").write_text("work in progress\n")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "uncommitted changes" in combined, combined
    assert _head(tree.repo) == head_before, combined
    assert _declared(tree.repo) == [DECLARED_VERSION] * len(DOCS), combined


def test_a_missing_tracking_ref_is_diagnosed(tmp_path: Path) -> None:
    """Without this check git answers with "fatal: ambiguous argument".

    That is a raw error rather than a statement of what is wrong, and it arrives
    from a command the operator did not run.
    """
    fixture = _make_fixture(tmp_path, push_branch=False)
    head_before = _head(fixture.repo)

    proc = _run(fixture.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert f"'origin/{_BRANCH}' does not exist after fetching" in combined, combined
    assert "ambiguous argument" not in combined, combined
    _assert_untouched(fixture, head_before, proc)


def test_a_branch_behind_the_remote_is_refused(tree: Fixture) -> None:
    """The push would be rejected. Saying so beats letting git say it later."""
    (tree.repo / "docs" / "later.md").write_text("added upstream\n")
    run_git(tree.repo, "add", "-A")
    run_git(tree.repo, "commit", "-qm", "upstream work")
    run_git(tree.repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
    run_git(tree.repo, "reset", "--hard", "-q", "HEAD~1")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert f"behind 'origin/{_BRANCH}' by 1 commit(s)" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_a_branch_ahead_of_the_remote_is_refused(tree: Fixture) -> None:
    """Unpushed commits would ride along with the bump push.

    The release commit is meant to go out on its own, so whoever reads the branch
    later sees one commit that did one thing.
    """
    (tree.repo / "docs" / "mine.md").write_text("not pushed yet\n")
    run_git(tree.repo, "add", "-A")
    run_git(tree.repo, "commit", "-qm", "local work")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert f"ahead of 'origin/{_BRANCH}' by 1 unpushed commit(s)" in combined, combined
    assert _head(tree.repo) == head_before, combined


# ---------------------------------------------------------------------------
# Preconditions on the documents
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("declarations", [0, 2])
def test_a_document_without_exactly_one_declaration_is_refused(
    tree: Fixture, declarations: int
) -> None:
    """Rewriting one line cannot repair a document whose shape is already wrong.

    Zero means the declaration was deleted and the commands below it resolve to
    nothing; two means a previous edit was left half-done and one of them is
    already stale.
    """
    (tree.repo / "src/broker/DEPLOYMENT.md").write_text(
        doc_body("broker", declarations=declarations)
    )
    run_git(tree.repo, "add", "-A")
    run_git(tree.repo, "commit", "-qm", "break the broker document")
    run_git(tree.repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
    run_git(tree.repo, "fetch", "-q", "origin")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert f"has {declarations} 'VERSION=' declaration(s), expected exactly 1" in combined, combined
    assert _head(tree.repo) == head_before, combined


def test_a_version_that_is_already_declared_is_refused(tree: Fixture) -> None:
    """There would be nothing to commit, and an empty release commit is a lie."""
    head_before = _head(tree.repo)

    proc = _run(tree.repo, DECLARED_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "already declare" in combined, combined
    _assert_untouched(tree, head_before, proc)


# ---------------------------------------------------------------------------
# The tag must still be free
# ---------------------------------------------------------------------------


def test_a_tag_that_exists_locally_is_refused(tree: Fixture) -> None:
    """A version already cut is not a version to cut again."""
    run_git(tree.repo, "tag", f"v{_NEW_VERSION}")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "already exists in this repository" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_a_tag_that_exists_only_on_the_public_remote_is_refused(tree: Fixture) -> None:
    """The public remote is consulted, and it is the one that matters.

    The tag is deleted locally after being pushed, so the local check above
    cannot be what catches it — this drives the remote lookup and nothing else.
    The public repository is where a released version is actually visible, and a
    machine that has never fetched that tag would otherwise cut it twice.
    """
    run_git(tree.repo, "tag", f"v{_NEW_VERSION}")
    run_git(tree.repo, "push", "-q", "public", f"v{_NEW_VERSION}")
    run_git(tree.repo, "tag", "-d", f"v{_NEW_VERSION}")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "already exists on 'public'" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_a_tag_on_the_private_remote_is_refused_after_the_fetch_brings_it_back(
    tree: Fixture,
) -> None:
    """Deleting it locally does not hide it, because the fetch happens first.

    git follows tags on any object it fetches, so a tag pushed to the private
    remote comes back into this repository during the precondition fetch. The
    refusal therefore arrives from the local check rather than the remote one.
    That is the right outcome by a different route, and worth pinning: someone
    reordering the fetch after the tag checks would silently lose it.
    """
    run_git(tree.repo, "tag", f"v{_NEW_VERSION}")
    run_git(tree.repo, "push", "-q", "origin", f"v{_NEW_VERSION}")
    run_git(tree.repo, "tag", "-d", f"v{_NEW_VERSION}")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "already exists in this repository" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_a_missing_public_remote_is_refused_rather_than_skipped(tree: Fixture) -> None:
    """An unanswered question is not a free tag.

    Carrying on without the public remote would turn the check that stops a
    version being released twice into a check that never runs.
    """
    run_git(tree.repo, "remote", "remove", "public")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "no 'public' remote" in combined, combined
    _assert_untouched(tree, head_before, proc)


# ---------------------------------------------------------------------------
# Confirmation, dry run, and the happy path
# ---------------------------------------------------------------------------


def test_a_run_that_cannot_be_confirmed_refuses_before_committing(tree: Fixture) -> None:
    """The check sits with the preconditions, not at the prompt.

    Asked at the prompt it would refuse having already made a commit, and the
    operator would find a release commit that was never pushed and never meant to
    exist.
    """
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "stdin is not a terminal" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_dry_run_writes_nothing(tree: Fixture) -> None:
    """It reports what would change and stops."""
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--dry-run")

    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert "DRY RUN complete" in combined, combined
    # The old and the new value are both named, so the operator can check the
    # direction of the bump before running it for real.
    assert f"{DECLARED_VERSION} -> {_NEW_VERSION}" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_the_happy_path_edits_commits_and_pushes(tree: Fixture) -> None:
    """One commit, three files, and the remote holds it afterwards."""
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert _declared(tree.repo) == [_NEW_VERSION] * len(DOCS), combined

    # Exactly one commit, and it touches the three documents and nothing else.
    new_head = _head(tree.repo)
    assert new_head != head_before, combined
    parent = run_git(tree.repo, "rev-parse", "HEAD~1").stdout.strip()
    assert parent == head_before, combined
    changed = run_git(tree.repo, "show", "--name-only", "--pretty=format:", "HEAD").stdout.split()
    assert sorted(changed) == sorted(DOCS), combined

    # The push happened, and it landed on the release branch.
    on_remote = git("-C", str(tree.origin), "rev-parse", f"refs/heads/{_BRANCH}").stdout.strip()
    assert on_remote == new_head, combined

    # Nothing left behind.
    assert run_git(tree.repo, "status", "--porcelain").stdout == "", combined


def test_the_epilogue_tags_the_public_commit_and_never_this_branch(tree: Fixture) -> None:
    """The one instruction that could destroy the separation between the trees.

    This branch and the public repository share no history, so the publish
    rebuilds the public tree as a fresh snapshot commit. Tagging a commit from
    HERE and pushing that tag would send this branch's whole private history to a
    public repository, and it cannot be taken back.

    So the epilogue has to do three things: print the lookup that shows the
    commit, print a push whose source is that sha rather than a ref, and say why
    the sha is read first. Dropping the lookup would turn the push back into a
    ref the operator never sees resolved.
    """
    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "git rev-parse public/main" in proc.stdout, proc.stdout
    assert f"<the sha that printed>:refs/tags/v{_NEW_VERSION}" in proc.stdout, proc.stdout
    # A push whose source is the ref itself is what the sha form replaced. Its
    # absence is the property, so assert it rather than trusting the two above.
    assert "public public/main:refs/tags/" not in proc.stdout, proc.stdout
    assert "share NO history" in proc.stdout, proc.stdout
    assert "cannot be taken back" in proc.stdout, proc.stdout
    # The shadowing hazard is the reason the sha is read first, and it is the
    # part a later editor would trim as verbose.
    assert "refs/heads before refs/remotes" in proc.stdout, proc.stdout
    # The dangerous command is shown as the thing NOT to do, so an operator who
    # was about to type it recognises it before they do.
    assert f"git tag v{_NEW_VERSION} &&" in proc.stdout, proc.stdout


# ---------------------------------------------------------------------------
# The rollback
# ---------------------------------------------------------------------------


def test_a_failing_gate_restores_the_documents(tree: Fixture) -> None:
    """The gate runs after the edit, so its refusal has to undo the edit.

    Without the restore, a refused release leaves three half-edited documents in
    the working tree for whoever looks next — and the reason they are there is in
    a terminal that has since been closed.
    """
    gate = tree.repo / "scripts" / "check-image-version.sh"
    gate.write_text("#!/usr/bin/env bash\necho 'refused, for the sake of this test'\nexit 1\n")
    run_git(tree.repo, "add", "-A")
    run_git(tree.repo, "commit", "-qm", "replace the gate with one that always refuses")
    run_git(tree.repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
    run_git(tree.repo, "fetch", "-q", "origin")
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "the deployment documents were restored" in combined, combined
    _assert_untouched(tree, head_before, proc)


def test_a_missing_gate_is_refused(tmp_path: Path) -> None:
    """An edit nothing checks is the state this whole mechanism exists to avoid."""
    fixture = _make_fixture(tmp_path)
    (fixture.repo / "scripts" / "check-image-version.sh").unlink()
    run_git(fixture.repo, "add", "-A")
    run_git(fixture.repo, "commit", "-qm", "remove the gate")
    run_git(fixture.repo, "push", "-q", "origin", f"HEAD:refs/heads/{_BRANCH}")
    run_git(fixture.repo, "fetch", "-q", "origin")
    head_before = _head(fixture.repo)

    proc = _run(fixture.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "the edit would go unchecked" in combined, combined
    # The documents are untouched, and the refusal came before the edit rather
    # than from the restore path.
    assert _declared(fixture.repo) == [DECLARED_VERSION] * len(DOCS), combined
    assert _head(fixture.repo) == head_before, combined


# ---------------------------------------------------------------------------
# The restore covers the whole edit-through-commit window, not just the gate
# ---------------------------------------------------------------------------


@_ROOT_IGNORES_FILE_MODES
def test_a_document_that_cannot_be_written_restores_the_earlier_ones(tree: Fixture) -> None:
    """A failure partway through the rewrite loop puts back what it already did.

    The documents are rewritten one at a time. Make the second unwritable and the
    first has already changed on disk by the time the tool gives up. Without a
    restore covering the edit itself, that first document is left carrying a
    version the other two do not, the tree is dirty, and the next run refuses on
    the clean-tree precondition — leaving the operator to work out the cleanup.
    """
    (tree.repo / DOCS[1]).chmod(0o444)
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    # The tool's own diagnosis, and ONLY that. The raw redirection error names a
    # line of the script rather than the document, so its absence is asserted
    # too — the message is added by one conditional and suppressed by the braces
    # inside it, and without both the operator reads the wrong thing first.
    assert "check that it is writable" in combined, combined
    assert "Permission denied" not in combined, combined
    assert "the deployment documents were restored" in combined, combined
    _assert_untouched(tree, head_before, proc)


@_ROOT_IGNORES_FILE_MODES
def test_a_failed_write_leaves_no_temporary_file(tree: Fixture, tmp_path: Path) -> None:
    """The rewrite works through a temporary file, and it has to clean it up.

    The failing write used to abort the script one line before the removal, so
    every attempt left a copy of a deployment document behind in the temporary
    directory.
    """
    scratch = tmp_path / "tmpdir"
    scratch.mkdir()
    (tree.repo / DOCS[1]).chmod(0o444)

    proc = _run(
        tree.repo,
        _NEW_VERSION,
        "--yes",
        env={**os.environ, "TMPDIR": str(scratch)},
    )

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    # mktemp's own naming, rather than "the directory is empty": git also uses
    # TMPDIR, and a broader assertion would fail for reasons unrelated to this.
    leaked = sorted(p.name for p in scratch.glob("tmp.*"))
    assert leaked == [], f"left behind: {leaked}\n{combined}"


def test_a_refused_commit_restores_and_unstages_every_document(tree: Fixture) -> None:
    """The window runs to the commit, and the restore has to undo staging too.

    A commit can fail for reasons outside this tool — a pre-commit hook, a
    signing key that expired. By then every document is rewritten AND staged.
    This also pins WHICH restore is used: `git checkout -- <paths>` reads the
    index, so after `git add` it puts the edited content back and leaves it
    staged. Only the form that reads HEAD clears both.
    """
    hook = tree.repo / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\necho 'hook: refusing this commit' >&2\nexit 1\n")
    hook.chmod(0o755)
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "the deployment documents were restored" in combined, combined
    # _assert_untouched covers the version, the porcelain and the head together;
    # an empty porcelain here is what proves nothing was left staged.
    _assert_untouched(tree, head_before, proc)


def test_a_failed_push_keeps_the_commit_and_claims_no_restore(tree: Fixture) -> None:
    """Past the commit the restore is disarmed, and has to stay quiet.

    Restoring from HEAD after the commit would reproduce what is already on disk,
    so leaving the trap armed changes no file. What it changes is what the
    operator is told: they would read that the documents were restored on a run
    that restored nothing. The absence of that line is the only observable
    difference, which is why it is what this asserts.
    """
    # A receiving hook, not a read-only directory: git writes into subdirectories
    # that already exist, so taking write permission off the bare repository's top
    # level does not stop a push. Measured — the push succeeded and this case
    # passed for the wrong reason.
    hook = tree.origin / "hooks" / "pre-receive"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho 'remote: refusing this push' >&2\nexit 1\n")
    hook.chmod(0o755)
    head_before = _head(tree.repo)

    proc = _run(tree.repo, _NEW_VERSION, "--yes")

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "the deployment documents were restored" not in combined, combined
    # The commit is the operator's to keep, retry or undo.
    assert _declared(tree.repo) == [_NEW_VERSION] * len(DOCS), combined
    assert run_git(tree.repo, "rev-parse", "HEAD~1").stdout.strip() == head_before, combined
    assert run_git(tree.repo, "status", "--porcelain").stdout == "", combined
