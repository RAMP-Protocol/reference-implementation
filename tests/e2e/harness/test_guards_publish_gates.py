"""Meta-guard — the publish tool's gates must actually reject what they name.

The tool's own comments record four separate occasions on which one of its gates
reported success while a problem was in front of it: two under ``set -o
pipefail`` where ``grep -q`` closed the pipe and the SIGPIPE became the
pipeline's status — one of which failed OPEN, returning success at the exact
moment it found a stray file; an all-or-nothing checkout that dropped LICENSE
from the public repo and continued; and a ``go vet`` without the ``integration``
tag that reported clean on a tree which did not compile. None was
regression-tested. This file is that missing test.

Each case drives the real script against a scratch repository and asserts one
property — a gate's refusal, or what the allowlist does and does not carry into
the snapshot. The scaffolding it runs against lives in ``publish_harness``, and
the ownership of the staging worktree has its own suite in
``test_guards_publish_worktree.py``.

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

import re
from pathlib import Path

from .guard_harness import commit_all, git, private_key_pem, run_git
from .published_paths import shared_array
from .publish_harness import (
    PUBLISH_GUARD_MARKS,
    make_public_remote,
    make_source_repo,
    run_publish,
)

pytestmark = PUBLISH_GUARD_MARKS

# Planted key material is written with a NEUTRAL extension on purpose. The real
# repository's ignore rules exclude *.pem and *.key, so a planted key under
# either name would vanish the moment anyone made the fixture inherit them.
_PLANTED_KEY_PATH = "internal/leaked-signing-key.txt"

# The image-publishing workflow has to travel to the public repository, because
# the publish rebuilds that tree from the allowlist and deletes everything else —
# a workflow authored on GitHub would survive only until the next publish. A
# stand-in is planted here rather than the real file: what the pair of cases
# below asserts is that the PATH is carried, not what the workflow contains.
_WORKFLOW_PATH = ".github/workflows/publish-images.yml"

# The one ALLOW_DIRS entry that is a dot-directory. It is also the only entry
# with no private use at all — the pipeline this repository runs ignores it — so
# it exists purely to be published, and a mistake here is invisible locally.
_WORKFLOW_DIR_ENTRY = ".github"

# Any ALLOW_DIRS entry proves the source-ref precondition. schemas is the one no
# other case in this module touches, so removing it cannot interact with one of
# them.
_ALLOW_DIR_ON_SOURCE = "schemas"


def test_clean_tree_reaches_the_dry_run_summary(publish_fixture: tuple[Path, Path, Path]) -> None:
    """The happy path completes every gate and stops short of pushing.

    Without this the negative cases below prove nothing: a script that aborted
    for an unrelated reason would satisfy all of them.
    """
    source, bare, worktree = publish_fixture

    proc = run_publish(source, bare, worktree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "DRY RUN complete" in proc.stdout, proc.stdout


def _plant_workflow(source: Path) -> None:
    """Write the stand-in workflow into the fixture source repo and commit it."""
    workflow = source / _WORKFLOW_PATH
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("name: publish\n")
    commit_all(source, "add the image-publishing workflow")


def test_workflow_reaches_the_staged_tree(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A file under .github is carried into the snapshot that gets pushed.

    The publish does not copy the working tree. It wipes a worktree and puts
    back only the allowlisted paths, so a directory absent from ALLOW_DIRS is
    silently dropped rather than reported. .github is the only dot-directory on
    the allowlist, and nothing else in this module asserts that one survives the
    rebuild.
    """
    source, bare, worktree = publish_fixture
    _plant_workflow(source)

    proc = run_publish(source, bare, worktree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    # The dry run exits before the worktree is torn down and tells the operator
    # to inspect it, so the staged tree itself is the primary evidence.
    assert (worktree / _WORKFLOW_PATH).is_file(), proc.stdout
    # And the operator has to SEE it: the additions listing is the only place a
    # file that is new on the public repo shows up during review.
    assert f"+ {_WORKFLOW_PATH}" in proc.stdout, proc.stdout


def test_workflow_is_dropped_when_its_directory_leaves_the_allowlist(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """Removing .github from ALLOW_DIRS stops the workflow travelling.

    The case above could pass for two different reasons — the allowlist carries
    the directory, or the snapshot copies more than the allowlist says. Only
    this one separates them. It also records what happens if someone deletes the
    entry: the publish still SUCCEEDS, in silence, and the public repository
    loses the workflow at the following snapshot.
    """
    source, bare, worktree = publish_fixture
    _plant_workflow(source)

    # Edit the fixture's own copy of the shared definition, which the publish
    # sources from its working directory. The comments in that file also mention
    # the directory, so the array entry is matched as a whole line.
    paths_file = source / "scripts" / "published-paths.sh"
    before = paths_file.read_text()
    after = re.sub(rf"^  {re.escape(_WORKFLOW_DIR_ENTRY)}$\n", "", before, flags=re.MULTILINE)
    assert after != before, (
        f"{_WORKFLOW_DIR_ENTRY} was not found as an ALLOW_DIRS entry, so this case would "
        "assert nothing. Check the array's formatting in scripts/published-paths.sh."
    )
    paths_file.write_text(after)
    commit_all(source, "drop the workflow directory from the allowlist")

    proc = run_publish(source, bare, worktree)

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert not (worktree / _WORKFLOW_PATH).exists(), proc.stdout
    assert f"+ {_WORKFLOW_PATH}" not in proc.stdout, proc.stdout


def test_forbidden_path_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A path the tree must never carry aborts the run.

    This is the defence-in-depth layer: nothing should reach it under the
    allowlists, so a hit here means an allowlist is wrong.
    """
    source, bare, worktree = publish_fixture
    keys = source / "deploy" / "dev-keys"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "ed25519-private.pem").write_text("# local development key\n")
    commit_all(source, "add a forbidden path")

    proc = run_publish(source, bare, worktree)

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
    (source / _PLANTED_KEY_PATH).write_bytes(private_key_pem())
    commit_all(source, "plant a private key on a published path")

    proc = run_publish(source, bare, worktree)

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
    commit_all(source, "add a key fixture")

    proc = run_publish(source, bare, worktree)

    assert proc.returncode != 0, proc.stdout
    assert "forbidden" in (proc.stdout + proc.stderr).lower(), proc.stdout + proc.stderr


def test_a_source_ref_missing_an_allowlisted_directory_is_rejected(
    publish_fixture: tuple[Path, Path, Path],
) -> None:
    """The precondition has to name the directory, rather than leaving git to.

    Every allowlisted path is checked out FROM the source ref, one command per
    array, and `git checkout <ref> -- a b c` is all-or-nothing: it exits non-zero
    having written none of the paths it was given. So a missing directory already
    stopped the run before this arm existed, and what the arm adds is the
    diagnosis.

    That is why this case asserts on the tool's own wording. Git's pathspec error
    also exits non-zero and also names the directory, so a case that checked only
    the exit code and the name would pass with the arm reverted.
    """
    source, bare, worktree = publish_fixture
    assert _ALLOW_DIR_ON_SOURCE in shared_array("ALLOW_DIRS"), (
        f"{_ALLOW_DIR_ON_SOURCE} is not an ALLOW_DIRS entry, so this case would assert "
        "nothing. Pick another entry from the shared definition."
    )
    run_git(source, "rm", "-rq", "--", _ALLOW_DIR_ON_SOURCE)
    commit_all(source, f"drop {_ALLOW_DIR_ON_SOURCE} from the source ref")

    proc = run_publish(source, bare, worktree)

    # The listing goes to stdout and the explanation to stderr, so a check on
    # either alone reads half the message.
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert _ALLOW_DIR_ON_SOURCE in combined, combined
    assert "allowlisted but absent on" in combined, combined
    # The precondition runs before the staging worktree is created, so a run
    # stopped there did no work at all.
    assert not worktree.exists(), combined


def test_missing_go_mod_is_rejected(publish_fixture: tuple[Path, Path, Path]) -> None:
    """A tree that is not a Go module at all is not publishable.

    The sibling of the fail-open above: this check reported the file MISSING on a
    tree that contained it, for the same reason and in the same idiom.
    """
    source, bare, worktree = publish_fixture
    (source / "go.mod").unlink()
    commit_all(source, "drop go.mod")

    proc = run_publish(source, bare, worktree)

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
    commit_all(seed, "remove LICENSE from the public branch")
    run_git(seed, "push", "-q", "origin", "v1")

    proc = run_publish(source, bare, worktree)

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
    commit_all(source, "add an unresolvable reference")

    proc = run_publish(source, bare, worktree)

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
    commit_all(seed, "grow the public branch")
    run_git(seed, "push", "-q", "origin", "v1")

    proc = run_publish(source, bare, worktree)

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
    make_source_repo(source)
    make_public_remote(bare, source)
    git("init", "-q", "--bare", str(elsewhere))
    # A remote already configured under the publish's name, pushing elsewhere.
    run_git(source, "remote", "add", "public", str(bare))
    run_git(source, "remote", "set-url", "--push", "public", str(elsewhere))

    proc = run_publish(source, bare, tmp_path / "worktree")

    assert proc.returncode != 0, proc.stdout
    assert "PUSHES to" in (proc.stdout + proc.stderr), proc.stdout + proc.stderr
