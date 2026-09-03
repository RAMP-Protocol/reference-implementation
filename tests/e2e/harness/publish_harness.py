"""Shared scaffolding for the publish tool's guard suites.

Only what belongs to this tool. Running git against a scratch repository, running
a shipped gate against a synthetic tree, and the marks a structural guard suite
declares are none of them publish-specific, and they live in ``guard_harness``,
which this module imports. The split is what lets a suite that guards some other
script reuse the mechanics without importing a module whose subject is the
publish.

The publish tool builds a curated snapshot of this repository and pushes it to
the public reference implementation. It is the only thing standing between the
private tree and an irreversible public push, and it carries nine gates. The
tool itself is deliberately not part of the published set, which is why the
suites that drive it skip when they cannot find it.

Two suites use what is here. ``test_guards_publish_gates.py`` asserts what the
gates refuse and what the allowlist carries into the snapshot;
``test_guards_publish_worktree.py`` asserts who is allowed to own the staging
worktree and branch the tool destroys on every run. They were one module until
their combined length passed the cap this repository puts on a test file.

Every case drives the real script against a scratch repository. The fixture repo
is a miniature of the published set: enough for the allowlists to resolve, small
enough to build in milliseconds. A bare repository alongside it stands in for the
public remote, so nothing reaches the network and no real remote is consulted.

``--skip-build`` is passed throughout. Gate 8 compiles Go and runs a test
package; on a fixture tree there is nothing to compile, and the gate under test
in every case is a path, secret, reference or ownership check.

The two seams — ``--remote-url`` and ``--worktree`` — are ARGUMENTS. Neither
reads the environment, and that is deliberate: an ambient variable that selects
what a gate acts on can redirect a real publish, which is a defect this
repository has already had once, in the reference gate these suites' sibling
guards.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ._compose import REPO_ROOT
from .guard_harness import (
    GITLEAKS_ABSENT,
    SECRET_SCAN_CONFIG,
    commit_all,
    git,
    guard_marks,
    init_scratch_repo,
    run_git,
)
from .published_paths import shared_array as _shared_array

# The waiver marker must sit on the line itself or the one directly above it —
# a second explanatory line in between puts it out of the gate's reach.
# published-ref-allow: a test that drives a script has to name it; the skip below says why it is absent
_PUBLISH = REPO_ROOT / "publish-public.sh"

# The publish tool is local-only and deliberately absent from the published tree,
# so it is not in the runner image either. gitleaks is a hard requirement of the
# secret gate and not installed everywhere. Skipping keeps both suites honest
# where they cannot run; the host per-commit tier is where they do.
PUBLISH_GUARD_MARKS = [
    *guard_marks(
        skip_when=not _PUBLISH.is_file(),
        # published-ref-allow: the skip reason has to name what is missing
        reason="publish-public.sh is not published, so it is absent from the runner image",
    ),
    GITLEAKS_ABSENT,
]


# A docs/ file no allowlist names. It gives the reference gate a bare basename to
# derive a pattern from, and it gives the docs/ allowlist a negative case: the
# snapshot must leave it behind. Exported so the case that asserts that reads the
# same name the fixture writes.
UNPUBLISHED_DOC = "docs/unpublished-note.md"


def make_source_repo(root: Path) -> None:
    """A miniature of the published set, committed on a branch named ``source``.

    Every allowlisted path exists because the publish checks each one out of the
    source ref by name; a missing one aborts the run before any gate is reached.
    The allowlisted docs/ files are materialised for a second reason too: the
    publish asserts each one reached the staged tree, so an absent one fails even
    if the checkout somehow succeeded without it.
    """
    init_scratch_repo(root, branch="source", committer="publish guard")

    for directory in _shared_array("ALLOW_DIRS"):
        (root / directory).mkdir(parents=True, exist_ok=True)
        (root / directory / ".keep").write_text("")

    for doc in _shared_array("ALLOW_DOC_FILES"):
        dest = root / doc
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(f"# {doc} in the fixture source tree\n")

    # Root files are materialised per-file, not uniformly, and each case has a
    # reason. Do not collapse this back into a blanket empty write.
    for name in _shared_array("ALLOW_ROOT_FILES"):
        if name == SECRET_SCAN_CONFIG:
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
    (root / UNPUBLISHED_DOC).write_text("# not published\n")
    commit_all(root, "fixture source tree")


def edit_fixture_definition(source: Path, pattern: str, replacement: str, message: str) -> None:
    """Rewrite one line of the fixture's own copy of the shared definition.

    This is the seam that makes the publish tool's allowlist gates reachable at
    all. The tool derives its repository root from the directory it is invoked in
    and sources ``scripts/published-paths.sh`` from there, ``run_publish`` invokes
    it inside ``source``, and ``make_source_repo`` copies the real file in because
    it is an ALLOW_SCRIPTS entry — so editing that copy changes the arrays the
    tool actually reads, without touching this repository's own definition.

    ``pattern`` is a multiline regex and is expected to match exactly one array
    entry. A miss is raised rather than ignored: the comments in that file mention
    the same paths the arrays do, so a pattern that was meant to match an entry
    and matched nothing would leave the definition untouched and the case would
    pass against an unmodified tool, proving nothing.
    """
    paths_file = source / "scripts" / "published-paths.sh"
    before = paths_file.read_text()
    after = re.sub(pattern, replacement, before, count=1, flags=re.MULTILINE)
    if after == before:
        raise AssertionError(
            f"the pattern {pattern!r} matched no line of the fixture's published-paths.sh, "
            "so this case would run against an unmodified allowlist and assert nothing. "
            "Check the array's formatting in scripts/published-paths.sh."
        )
    paths_file.write_text(after)
    commit_all(source, message)


def make_public_remote(bare: Path, source: Path) -> None:
    """A bare repo standing in for the public remote, seeded with the scaffolding.

    The publish bases its snapshot on the public branch and asserts the inherited
    files survived, so the remote has to carry them already — exactly as the real
    public repository does.
    """
    seed = source.parent / "public-seed"
    init_scratch_repo(seed, branch="v1", committer="publish guard")
    for inherited in _shared_array("INHERIT_FROM_MAIN"):
        target = seed / inherited
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# {inherited} on the public branch\n")
    # Padding so the shrink guard has a base to compare against; the curated tree
    # is far smaller than the real one, so without this every run trips it.
    for i in range(40):
        (seed / f"legacy-{i}.txt").write_text("carried over from the previous snapshot\n")
    commit_all(seed, "public base")

    git("init", "-q", "--bare", "-b", "v1", str(bare))
    run_git(seed, "remote", "add", "origin", str(bare))
    run_git(seed, "push", "-q", "origin", "v1")


def run_publish(
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


def repo_is_intact(repo: Path) -> bool:
    """Did the repository survive the run?

    ``.git`` is checked with ``exists()`` rather than ``is_dir()`` on purpose: in
    a linked worktree it is a FILE holding a pointer to the shared admin
    directory, so ``is_dir()`` would report a surviving worktree as destroyed.
    """
    return (repo / ".git").exists() and (repo / "go.mod").is_file()


def branch_sha(repo: Path, branch: str) -> str:
    return run_git(repo, "rev-parse", f"refs/heads/{branch}").stdout.strip()
