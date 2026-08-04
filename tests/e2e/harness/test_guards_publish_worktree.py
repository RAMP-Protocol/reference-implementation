"""Meta-guard — who is allowed to own the two things every publish destroys.

``--worktree`` names a path the tool wipes with ``rm -rf``, so it carries an
ownership guard. The property it enforces is narrow: the path is accepted only
when it does not exist, or when it is a LINKED worktree of this repository with
``publish-staging`` checked out. Nothing else is a path the tool made. An
earlier version asked instead whether the path was "a worktree of this
repository", which the main checkout answers yes to — it is the first entry git
prints — so the guard stayed silent and the wipe deleted the repository,
measured at 144 entries to 0 with ``.git`` gone.

The staging BRANCH is deleted and recreated on every run too, on the default
path with no seam involved, so it is guarded in the same block and covered here.

These cases are separate from the gate suite because every case there passes a
worktree path that does not exist, so none of them can reach either guard. The
scaffolding both suites share lives in ``publish_harness``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from .guard_harness import commit_all, run_git
from .publish_harness import (
    PUBLISH_GUARD_MARKS,
    branch_sha,
    repo_is_intact,
    run_publish,
)

pytestmark = PUBLISH_GUARD_MARKS


_SENTINEL = "work nobody backed up\n"


def _spelling_as_is(source: Path, tmp_path: Path) -> str:
    return str(source)


def _spelling_round_trip(source: Path, tmp_path: Path) -> str:
    return str(source / ".." / source.name)


def _spelling_trailing_dot(source: Path, tmp_path: Path) -> str:
    # A plain string, and it must stay one. ``Path`` drops a lone "." component
    # in its constructor as well as in ``/``, so building this path with pathlib
    # at any point produces the bare root and this case silently becomes a copy
    # of the first one — measured. ".." survives pathlib, "." does not.
    return f"{source}/."


def _spelling_symlink(source: Path, tmp_path: Path) -> str:
    link = tmp_path / "root-link"
    link.symlink_to(source, target_is_directory=True)
    return str(link)


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param(_spelling_as_is, id="as-is"),
        pytest.param(_spelling_round_trip, id="dot-dot-round-trip"),
        pytest.param(_spelling_trailing_dot, id="trailing-dot"),
        pytest.param(_spelling_symlink, id="symlink"),
    ],
)
def test_repo_root_is_refused_however_it_is_spelled(
    publish_fixture: tuple[Path, Path, Path],
    tmp_path: Path,
    spelling,  # noqa: ANN001 — a factory taking (source, tmp_path), see the params above
) -> None:
    """The caller's own repository is never a disposable staging path.

    This is the case the tool shipped without. The old check asked git whether
    the path was a worktree of this repository; the main checkout is the first
    worktree git lists, so it answered yes, the check stayed silent, and the wipe
    destroyed the repository while the banner promised the main tree was
    untouched.

    Four spellings of one directory. The first two are the measured data loss.
    The last two are refused by the old check as well, but only by accident —
    it compared strings, so a trailing "." missed and a symlink would have missed
    too. They are here to prove the refusal is decided by path identity rather
    than by how the path was typed.
    """
    source, bare, _ = publish_fixture
    sentinel = source / "internal" / "sentinel.txt"
    sentinel.write_text(_SENTINEL)

    proc = run_publish(source, bare, spelling(source, tmp_path))

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "refusing to delete" in combined, combined
    assert "the working tree this run is standing in" in combined, combined
    assert repo_is_intact(source), combined
    assert sentinel.is_file() and sentinel.read_text() == _SENTINEL, combined


def _target_plain_dir(source: Path, bare: Path, tmp_path: Path) -> Path:
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "keep.txt").write_text(_SENTINEL)
    return plain


def _target_dir_inside_the_repo(source: Path, bare: Path, tmp_path: Path) -> Path:
    inside = source / "scratch"
    inside.mkdir()
    (inside / "keep.txt").write_text(_SENTINEL)
    return inside


def _target_bare_repo(source: Path, bare: Path, tmp_path: Path) -> Path:
    return bare


def _target_regular_file(source: Path, bare: Path, tmp_path: Path) -> Path:
    afile = tmp_path / "afile"
    afile.write_text(_SENTINEL)
    return afile


@pytest.mark.parametrize(
    ("arrangement", "clause"),
    [
        pytest.param(_target_plain_dir, "not inside a git repository", id="plain-dir"),
        pytest.param(_target_dir_inside_the_repo, "not the root of one", id="dir-inside-repo"),
        pytest.param(_target_bare_repo, "not inside a git repository", id="bare-repo"),
        pytest.param(_target_regular_file, "it is not a directory", id="regular-file"),
    ],
)
def test_a_path_that_is_not_a_staging_worktree_is_refused(
    publish_fixture: tuple[Path, Path, Path],
    tmp_path: Path,
    arrangement,  # noqa: ANN001 — a factory taking (source, bare, tmp_path)
    clause: str,
) -> None:
    """Four paths the tool did not create, each refused for its own reason.

    The reasons are asserted separately rather than as one "refused" outcome. A
    branch of the guard that no case takes is a branch nothing checks, and a
    typo in it stays invisible until the day it fires.
    """
    source, bare, _ = publish_fixture
    target = arrangement(source, bare, tmp_path)

    proc = run_publish(source, bare, target)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "refusing to delete" in combined, combined
    assert clause in combined, combined
    assert target.exists(), combined


def test_registered_sibling_worktree_with_uncommitted_work_is_refused(
    publish_fixture: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    """A peer worktree is not ours to wipe, and its uncommitted work is not saved.

    Measured on the old check: the run deleted the peer worktree, took the
    uncommitted file with it, and reported success with exit 0. This repository
    creates sibling worktrees routinely, so the loss is not hypothetical.
    """
    source, bare, _ = publish_fixture
    sibling = tmp_path / "sidework"
    run_git(source, "worktree", "add", "-q", "-b", "sidework", str(sibling), "source")
    unsaved = sibling / "unsaved.txt"
    unsaved.write_text(_SENTINEL)

    proc = run_publish(source, bare, sibling)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "not 'publish-staging'" in combined, combined
    assert unsaved.is_file() and unsaved.read_text() == _SENTINEL, combined


def test_detached_staging_worktree_is_refused(
    publish_fixture: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    """A worktree with no branch cannot be shown to be ours, so it is refused.

    The staging branch is the only evidence the tool has that it created a
    worktree. A detached HEAD carries none, and the old check destroyed the
    directory anyway.

    This case also pins the shape of the guard's git calls. Reading the branch
    with a bare assignment from a failing command substitution would end the run
    silently under ``set -e``, before any refusal is printed, and the clause
    below would then be absent.
    """
    source, bare, worktree = publish_fixture
    run_git(source, "worktree", "add", "-q", "--detach", str(worktree), "source")

    proc = run_publish(source, bare, worktree)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "its HEAD is detached" in combined, combined
    assert worktree.is_dir(), combined


def test_main_worktree_is_refused_when_the_publish_runs_from_a_linked_worktree(
    publish_fixture: tuple[Path, Path, Path],
    tmp_path: Path,
) -> None:
    """The main worktree stays protected even when it is not the invocation root.

    The tool derives its repository root from the directory it is invoked in, so
    a run started inside a linked worktree has a root that is NOT the main
    checkout. A guard that only compared the target against that root would let
    the main worktree through, and deleting it takes the shared git directory and
    every other linked worktree with it.

    The main worktree is put on the staging branch here on purpose: every other
    check the guard makes would accept it, so only the main-worktree test can
    refuse this arrangement.
    """
    source, bare, _ = publish_fixture
    linked = tmp_path / "linked"
    run_git(source, "worktree", "add", "-q", "-b", "alt", str(linked), "source")
    run_git(source, "checkout", "-qb", "publish-staging")

    proc = run_publish(source, bare, source, cwd=linked)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "it is a MAIN worktree" in combined, combined
    assert repo_is_intact(source), combined
    assert (linked / ".git").exists(), combined


def test_a_staging_branch_this_run_did_not_create_is_not_deleted(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """The branch deletion is reachable on the default path, with no seam at all.

    Every run deletes and recreates the staging branch. When the branch is
    checked out nowhere, the tool cannot tell its own residue from a branch the
    operator made, and deleting it destroys commits. Two ways to reach that
    state: an operator names a branch ``publish-staging`` themselves, or they
    follow only the first half of the two-command cleanup line the dry run
    prints.

    The remote assertion is the second half of the point. A refusal that arrives
    after the tool has already added a git remote has mutated the repository it
    refused to act on.
    """
    source, bare, worktree = publish_fixture
    run_git(source, "checkout", "-qb", "publish-staging")
    (source / "keepme.txt").write_text("a commit of my own\n")
    commit_all(source, "work on a branch of my own")
    before = branch_sha(source, "publish-staging")
    run_git(source, "checkout", "-q", "source")

    proc = run_publish(source, bare, worktree)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "refusing to delete branch" in combined, combined
    assert branch_sha(source, "publish-staging") == before, combined
    remotes = run_git(source, "remote").stdout.split()
    assert "public" not in remotes, combined


def test_consecutive_publishes_reuse_the_staging_worktree(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """The second run in a row must still work.

    The dry run deliberately leaves the worktree and the branch behind for the
    operator to inspect, so the next run finds both already there. This is the
    case a guard that is too strict breaks, and it is the only case that catches
    that — every other case here asserts a refusal, which a broken guard would
    satisfy.
    """
    source, bare, worktree = publish_fixture

    first = run_publish(source, bare, worktree)
    assert first.returncode == 0, first.stdout + first.stderr
    assert worktree.is_dir(), first.stdout

    second = run_publish(source, bare, worktree)

    combined = second.stdout + second.stderr
    assert second.returncode == 0, combined
    assert "DRY RUN complete" in second.stdout, combined
    assert "refusing" not in combined, combined


def test_stale_registration_with_a_missing_directory_still_runs(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """A registration whose directory is gone is our own residue, not a refusal.

    An operator who deletes the staging directory by hand leaves git still
    listing it, with the staging branch recorded against it. The guard has to
    read that listing BEFORE the run prunes it: once the registration is pruned,
    a branch checked out nowhere is exactly what the branch guard refuses, and
    the tool's own leftovers would deadlock every later run.
    """
    source, bare, worktree = publish_fixture
    run_git(source, "worktree", "add", "-q", "-b", "publish-staging", str(worktree), "source")
    shutil.rmtree(worktree)

    proc = run_publish(source, bare, worktree)

    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert "DRY RUN complete" in proc.stdout, combined
    assert "refusing" not in combined, combined
