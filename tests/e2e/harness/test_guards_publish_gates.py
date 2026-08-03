"""Meta-guard — the publish tool's gates must actually reject what they name.

The publish tool builds a curated snapshot of this repository and pushes it to
the public reference implementation. It is the only thing standing between the
private tree and an irreversible public push, and it carries nine gates. The tool
itself is deliberately not part of the published set, which is why this module
skips when it cannot find it.

Its own comments record four separate occasions on which one of those gates
reported success while a problem was in front of it: two under ``set -o
pipefail`` where ``grep -q`` closed the pipe and the SIGPIPE became the
pipeline's status — one of which failed OPEN, returning success at the exact
moment it found a stray file; an all-or-nothing checkout that dropped LICENSE
from the public repo and continued; and a ``go vet`` without the ``integration``
tag that reported clean on a tree which did not compile. None was
regression-tested. This file is that missing test.

Each case drives the real script against a scratch repository and asserts one
gate. The fixture repo is a miniature of the published set: enough for the
allowlists to resolve, small enough to build in milliseconds. A bare repository
alongside it stands in for the public remote, so nothing reaches the network and
no real remote is consulted.

``--skip-build`` is passed throughout. Gate 8 compiles Go and runs a test
package; on a fixture tree there is nothing to compile, and the gate under test
in every case here is a path, secret or reference check.

The two seams — ``--remote-url`` and ``--worktree`` — are ARGUMENTS. Neither
reads the environment, and that is deliberate: an ambient variable that selects
what a gate acts on can redirect a real publish, which is a defect this
repository has already had once, in the reference gate this file's sibling
guards.

``--worktree`` names a path the tool wipes with ``rm -rf``, so it carries an
ownership guard, and the guard has its own cases at the end of this file. The
property it enforces is narrow: the path is accepted only when it does not exist,
or when it is a LINKED worktree of this repository with ``publish-staging``
checked out. Nothing else is a path the tool made. An earlier version asked
instead whether the path was "a worktree of this repository", which the main
checkout answers yes to — it is the first entry git prints — so the guard stayed
silent and the wipe deleted the repository, measured at 144 entries to 0 with
``.git`` gone. The staging BRANCH is deleted and recreated on every run too, on
the default path with no seam involved, so it is guarded in the same block.

**Two of the nine gates are not driven here, because nothing can reach them.**
The staged tree is built by checking out exactly the allowlisted paths, so a
stray root document or an unlisted ``scripts/`` entry in the source can never
appear in it — the root-doc and scripts-allowlist gates only fire if the
allowlist itself is widened, which is the defence-in-depth role their own
comment claims. The forbidden-path gate IS reachable, but only for the two
entries that live *under* an allowlisted directory: the local dev-keys folder
and the e2e key fixtures. Those are the cases below. Writing a test that
appeared to drive the other two would assert a path the tool cannot take.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from .conftest import REPO_ROOT
from .published_paths import shared_array as _shared_array

# The waiver marker must sit on the line itself or the one directly above it —
# a second explanatory line in between puts it out of the gate's reach.
# published-ref-allow: a test that drives a script has to name it; the skip below says why it is absent
_PUBLISH = REPO_ROOT / "publish-public.sh"

# The one root file whose content a gate depends on. See _make_source_repo.
_SECRET_SCAN_CONFIG = ".gitleaks.toml"

# Planted key material is written with a NEUTRAL extension on purpose. The real
# repository's ignore rules exclude *.pem and *.key, so a planted key under
# either name would vanish the moment anyone made the fixture inherit them.
_PLANTED_KEY_PATH = "internal/leaked-signing-key.txt"

# The publish tool is local-only and deliberately absent from the published tree,
# so it is not in the runner image either. gitleaks is a hard requirement of the
# secret gate and not installed everywhere. Skipping keeps this module honest
# where it cannot run; the host per-commit tier is where it does.
pytestmark = [
    pytest.mark.stack_isolation("isolated"),
    pytest.mark.skipif(
        not _PUBLISH.is_file(),
        # published-ref-allow: the skip reason has to name what is missing
        reason="publish-public.sh is not published, so it is absent from the runner image",
    ),
    pytest.mark.skipif(
        shutil.which("gitleaks") is None,
        reason="the publish requires gitleaks; without it every run aborts at the secret gate",
    ),
]


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, timeout=60)


def _make_source_repo(root: Path) -> None:
    """A miniature of the published set, committed on a branch named ``source``.

    Every allowlisted path exists because the publish checks each one out of the
    source ref by name; a missing one aborts the run before any gate is reached.
    """
    root.mkdir(parents=True, exist_ok=True)
    _git(root, "init", "-q", "-b", "source")
    _git(root, "config", "user.email", "guard@example.invalid")
    _git(root, "config", "user.name", "publish guard")

    for directory in _shared_array("ALLOW_DIRS"):
        (root / directory).mkdir(parents=True, exist_ok=True)
        (root / directory / ".keep").write_text("")

    # Root files are materialised per-file, not uniformly, and each case has a
    # reason. Do not collapse this back into a blanket empty write.
    for name in _shared_array("ALLOW_ROOT_FILES"):
        if name == _SECRET_SCAN_CONFIG:
            # This file's CONTENT is a gate's ruleset. gitleaks resolves
            # <source>/.gitleaks.toml in place of its defaults, so an empty file
            # is a zero-rule config and the secret gate silently becomes a no-op
            # — measured: the planted key below scans clean against an empty one.
            # It is copied verbatim for the same reason the gate scripts are.
            (root / name).write_bytes((REPO_ROOT / name).read_bytes())
        else:
            # Everything else only has to exist for the allowlist checkout to
            # succeed; no gate reads its content. The ignore files in particular
            # must stay EMPTY: this fixture commits planted files with
            # `git add -A`, and the real .gitignore excludes *.pem and *.key, so
            # copying it verbatim would silently drop the planted evidence.
            (root / name).write_text("")
    (root / "go.mod").write_text("module example.invalid/fixture\n\ngo 1.26\n")

    for script in _shared_array("ALLOW_SCRIPTS"):
        dest = root / script
        dest.parent.mkdir(parents=True, exist_ok=True)
        src = REPO_ROOT / script
        # The reference gate and the definition it reads are copied verbatim,
        # because gate 9 runs them against the staged tree. The rest only need to
        # exist for the allowlist checkout to succeed.
        dest.write_bytes(src.read_bytes() if src.is_file() else b"")

    # The gate derives bare-name patterns from unpublished docs, and the publish
    # inherits this one onto the public branch rather than building it here.
    (root / "docs" / "unpublished-note.md").write_text("# not published\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "fixture source tree")


def _make_public_remote(bare: Path, source: Path) -> None:
    """A bare repo standing in for the public remote, seeded with the scaffolding.

    The publish bases its snapshot on the public branch and asserts the inherited
    files survived, so the remote has to carry them already — exactly as the real
    public repository does.
    """
    seed = source.parent / "public-seed"
    seed.mkdir(parents=True, exist_ok=True)
    _git(seed, "init", "-q", "-b", "v1")
    _git(seed, "config", "user.email", "guard@example.invalid")
    _git(seed, "config", "user.name", "publish guard")
    for inherited in _shared_array("INHERIT_FROM_MAIN"):
        target = seed / inherited
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# {inherited} on the public branch\n")
    # Padding so the shrink guard has a base to compare against; the curated tree
    # is far smaller than the real one, so without this every run trips it.
    for i in range(40):
        (seed / f"legacy-{i}.txt").write_text("carried over from the previous snapshot\n")
    _git(seed, "add", "-A")
    _git(seed, "commit", "-qm", "public base")

    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "v1", str(bare)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    _git(seed, "remote", "add", "origin", str(bare))
    _git(seed, "push", "-q", "origin", "v1")


def _run_publish(
    source: Path, bare: Path, worktree: Path | str, *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Dry run — no --push, so nothing is ever committed to the fixture remote.

    ``cwd`` defaults to the source repository, which is how the tool is normally
    invoked. One case runs it from a linked worktree instead, because the tool
    derives its repository root from the invocation directory.
    """
    return subprocess.run(
        [
            "bash",
            str(_PUBLISH),
            "--source",
            "source",
            "--branch",
            "v1",
            "--remote-url",
            str(bare),
            "--worktree",
            str(worktree),
            "--skip-build",
        ],
        cwd=str(cwd if cwd is not None else source),
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


@pytest.fixture
def publish_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A source repo, a bare stand-in for the public remote, and a worktree path."""
    source = tmp_path / "source"
    bare = tmp_path / "public.git"
    worktree = tmp_path / "worktree"
    _make_source_repo(source)
    _make_public_remote(bare, source)
    return source, bare, worktree


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)


def _repo_is_intact(repo: Path) -> bool:
    """Did the repository survive the run?

    ``.git`` is checked with ``exists()`` rather than ``is_dir()`` on purpose: in
    a linked worktree it is a FILE holding a pointer to the shared admin
    directory, so ``is_dir()`` would report a surviving worktree as destroyed.
    """
    return (repo / ".git").exists() and (repo / "go.mod").is_file()


def _branch_sha(repo: Path, branch: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", f"refs/heads/{branch}"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )
    return out.stdout.strip()


def test_clean_tree_reaches_the_dry_run_summary(publish_fixture: tuple[Path, Path, Path]) -> None:
    """The happy path completes every gate and stops short of pushing.

    Without this the negative cases below prove nothing: a script that aborted
    for an unrelated reason would satisfy all of them.
    """
    source, bare, worktree = publish_fixture

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "DRY RUN complete" in proc.stdout, proc.stdout


def test_forbidden_path_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A path the tree must never carry aborts the run.

    This is the defence-in-depth layer: nothing should reach it under the
    allowlists, so a hit here means an allowlist is wrong.
    """
    source, bare, worktree = publish_fixture
    keys = source / "deploy" / "dev-keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "ed25519-private.pem").write_text("# local development key\n")
    _commit(source, "add a forbidden path")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    assert "forbidden" in (proc.stdout + proc.stderr).lower(), proc.stdout + proc.stderr


def test_planted_key_is_rejected_by_the_secret_scan(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """A real private key on an ordinary published path aborts at the secret gate.

    This is the gate that matters most — the last automated check before an
    irreversible public push — and it was the one with no effective coverage:
    the fixture handed it an empty ruleset, so deleting the gitleaks call
    outright left every case in this module green.

    The key is generated here rather than committed, because a committed one
    would trip the scanner on the real tree. It is planted under ``internal/``,
    which the forbidden-path gate does not name, so the run reaches the secret
    scan and no earlier abort can satisfy the assertion.
    """
    source, bare, worktree = publish_fixture
    key = ed25519.Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    (source / _PLANTED_KEY_PATH).write_bytes(key)
    _commit(source, "plant a private key on a published path")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    # The gate's own message, not merely a non-zero exit: several earlier gates
    # abort too, and asserting on the exit code alone would let this case pass
    # while the secret scan did nothing.
    assert "gitleaks reported potential secrets" in (proc.stdout + proc.stderr), (
        proc.stdout + proc.stderr
    )


def test_key_fixture_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A private key forced back under the e2e fixtures directory is refused.

    That directory is gitignored, so a key normally cannot reach the tree at all
    — but two did, added with a forced git add four days after a fix deliberately
    untracked five of them. This is the layer that catches the next one.
    """
    source, bare, worktree = publish_fixture
    fixtures = source / "tests" / "e2e" / "harness" / "fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    (fixtures / "agent_demo_key.json").write_text('{"private_key": "not-a-real-seed"}\n')
    _commit(source, "add a key fixture")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    assert "forbidden" in (proc.stdout + proc.stderr).lower(), proc.stdout + proc.stderr


def test_missing_go_mod_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A tree that is not a Go module at all is not publishable.

    The sibling of the fail-open above: this check reported the file MISSING on a
    tree that contained it, for the same reason and in the same idiom.
    """
    source, bare, worktree = publish_fixture
    (source / "go.mod").unlink()
    _commit(source, "drop go.mod")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    assert "go.mod" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr


def test_missing_inherited_file_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A file the public branch carries must not vanish from the snapshot.

    The checkout that fetches these was once all-or-nothing and only warned, so a
    single missing entry silently dropped every one of them — which is how
    LICENSE left the public repository while the publish reported success.
    """
    source, bare, worktree = publish_fixture
    seed = source.parent / "public-seed"
    (seed / "LICENSE").unlink()
    _commit(seed, "remove LICENSE from the public branch")
    _git(seed, "push", "-q", "origin", "v1")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    assert "LICENSE" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr


def test_unresolvable_reference_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """The staged tree must not point at anything that does not travel with it.

    The reference gate runs over the curated tree here, not over the working
    copy — the tree being scanned is the tree being pushed.
    """
    source, bare, worktree = publish_fixture
    # published-ref-allow: the fixture a gate is tested with has to be a real violation
    (source / "internal" / "note.go").write_text("// see docs/design/design-exchange.md\n")
    _commit(source, "add an unresolvable reference")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    combined = proc.stdout + proc.stderr
    assert "unresolvable reference" in combined, combined


def test_shrink_guard_trips_when_the_tree_collapses(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """A snapshot far smaller than the base is a broken allowlist, not an edit.

    A dropped allowlist entry shows up here as a cliff rather than as a typo, and
    the snapshot model would otherwise delete every file it failed to reproduce.
    """
    source, bare, worktree = publish_fixture
    seed = source.parent / "public-seed"
    for i in range(400):
        (seed / f"bulk-{i}.txt").write_text("previous snapshot content\n")
    _commit(seed, "grow the public branch")
    _git(seed, "push", "-q", "origin", "v1")

    proc = _run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    assert "allowlist looks broken" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr


def test_mismatched_remote_url_is_rejected(tmp_path: Path) -> None:
    """An existing remote pointing somewhere else must not be published to.

    The check reads both URLs. `git remote get-url` returns the FETCH url, and a
    configured pushurl sends the push elsewhere while leaving that one intact —
    so verifying only the fetch leg leaves the leg that actually publishes
    unverified.
    """
    source = tmp_path / "source"
    bare = tmp_path / "public.git"
    elsewhere = tmp_path / "elsewhere.git"
    _make_source_repo(source)
    _make_public_remote(bare, source)
    subprocess.run(
        ["git", "init", "-q", "--bare", str(elsewhere)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    # A remote already configured under the publish's name, pushing elsewhere.
    _git(source, "remote", "add", "public", str(bare))
    _git(source, "remote", "set-url", "--push", "public", str(elsewhere))

    proc = _run_publish(source, bare, tmp_path / "worktree")

    assert proc.returncode != 0, proc.stdout
    assert "PUSHES to" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Ownership of the two things every run destroys: the staging worktree path and
# the staging branch. Every case above passes a worktree path that does not
# exist, so none of them can reach either guard.
# ---------------------------------------------------------------------------

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

    proc = _run_publish(source, bare, spelling(source, tmp_path))

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "refusing to delete" in combined, combined
    assert "the working tree this run is standing in" in combined, combined
    assert _repo_is_intact(source), combined
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

    proc = _run_publish(source, bare, target)

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
    _git(source, "worktree", "add", "-q", "-b", "sidework", str(sibling), "source")
    unsaved = sibling / "unsaved.txt"
    unsaved.write_text(_SENTINEL)

    proc = _run_publish(source, bare, sibling)

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
    _git(source, "worktree", "add", "-q", "--detach", str(worktree), "source")

    proc = _run_publish(source, bare, worktree)

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
    _git(source, "worktree", "add", "-q", "-b", "alt", str(linked), "source")
    _git(source, "checkout", "-qb", "publish-staging")

    proc = _run_publish(source, bare, source, cwd=linked)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "it is a MAIN worktree" in combined, combined
    assert _repo_is_intact(source), combined
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
    _git(source, "checkout", "-qb", "publish-staging")
    (source / "keepme.txt").write_text("a commit of my own\n")
    _commit(source, "work on a branch of my own")
    before = _branch_sha(source, "publish-staging")
    _git(source, "checkout", "-q", "source")

    proc = _run_publish(source, bare, worktree)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "refusing to delete branch" in combined, combined
    assert _branch_sha(source, "publish-staging") == before, combined
    remotes = subprocess.run(
        ["git", "-C", str(source), "remote"],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.split()
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

    first = _run_publish(source, bare, worktree)
    assert first.returncode == 0, first.stdout + first.stderr
    assert worktree.is_dir(), first.stdout

    second = _run_publish(source, bare, worktree)

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
    _git(source, "worktree", "add", "-q", "-b", "publish-staging", str(worktree), "source")
    shutil.rmtree(worktree)

    proc = _run_publish(source, bare, worktree)

    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined
    assert "DRY RUN complete" in proc.stdout, combined
    assert "refusing" not in combined, combined
