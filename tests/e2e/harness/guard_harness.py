"""Scaffolding every structural guard suite needs.

Six suites in this directory assert that something shipped in this repository
refuses what it says it refuses. Five of them do it by driving a shipped script
against a synthetic tree; the sixth reads the real workflow files and drives
nothing. What they need overlaps rather than coincides — all six declare the same
marks, four build a scratch git repository, three run a gate script, two plant a
private key — and every piece of it was written once per suite until this module
existed, in copies that had already started to differ. One gate runner grew an
``env`` parameter and a longer timeout; the other two did not.

None of it is publish-specific. ``publish_harness`` sits on top of this module and
keeps only what belongs to driving the publish tool: the miniature published tree,
the stand-in remote, and the invocation. A suite that guards some other script has
this module to import from, and no reason to reach into that one.

The guards that drive no script at all -- the ones that only read source under
``tests/e2e/`` and report a shape -- share ``ast_scan`` instead: the tree walk, the
exclusion set and the dict-key reader. Nothing here is useful to them, so a
source-scan helper belongs there rather than in this module.

A module of its own rather than something in ``conftest``: it takes no fixture
arguments, and several modules import it at import time to build their marks
before any test runs. It also imports nothing from this package, so ``conftest``
imports it at module top like anything else.

That is true of ``publish_harness`` too, and it did not used to be.
``conftest`` owned ``REPO_ROOT``, ``publish_harness`` read it from there, and
``conftest`` could therefore only import ``publish_harness`` from inside a
function body. ``REPO_ROOT`` now lives in ``_compose``; both modules read it
from there and neither imports ``conftest`` at all. Test modules still import
``conftest`` freely — they are leaves, and nothing imports them back.
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

# Fixture git calls are small and local. A minute is generous for the slowest of
# them and short enough that a hung call fails the suite rather than the job.
GIT_TIMEOUT = 60

# The gates are offline source scans and finish in well under this. The secret
# gate is the exception and raises it at the call site, because gitleaks does
# real work over the whole tree.
GATE_TIMEOUT = 120

# One address for every scratch repository. The committer NAME varies per suite,
# so a commit in a failure message names the fixture that made it; the address
# does not need to, and .invalid can never resolve (RFC 6761).
COMMITTER_EMAIL = "guard@example.invalid"

# The secret scanner resolves its ruleset from this file in the tree it scans, so
# a fixture that leaves it empty turns the scan into a no-op that reports clean.
SECRET_SCAN_CONFIG = ".gitleaks.toml"

# scripts/ is not copied into the e2e runner image, so on that tier a gate suite
# has nothing to drive. Every suite that runs a script under scripts/ skips for
# this reason, in these words.
GATE_ABSENT_REASON = "scripts/ is absent from the e2e runner image; this guard runs on the host"

# One instance, shared by every suite that needs it — the secret-gate suite reads
# it directly, and the two publish suites get it through PUBLISH_GUARD_MARKS.
# Applying a MarkDecorator does not mutate it, so one object serves all three.
GITLEAKS_ABSENT = pytest.mark.skipif(
    shutil.which("gitleaks") is None,
    reason="gitleaks is not installed, and the gate under test refuses to run without it",
)


def git(*args: str) -> subprocess.CompletedProcess[str]:
    """Run git for a fixture, and hand back what it printed.

    It RETURNS the result rather than discarding it. The callers that need stdout
    used to hand-roll their own ``subprocess.run`` for exactly that reason, and
    so did the two that create a bare repository, which have no repository to
    ``-C`` into and so cannot go through ``run_git``.

    ``text=True`` is for those readers: they want ``.stdout`` as a string. It is
    not a better failure message — ``CalledProcessError`` renders only the
    command and the exit status, never the captured output.
    """
    return subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT,
    )


def run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """``git`` inside ``repo``."""
    return git("-C", str(repo), *args)


def commit_all(repo: Path, message: str) -> None:
    """Stage everything in ``repo``, including deletions, and commit it."""
    run_git(repo, "add", "-A")
    run_git(repo, "commit", "-qm", message)


def init_scratch_repo(root: Path, *, branch: str, committer: str) -> None:
    """Create ``root`` and make it an empty repository with a fixed identity.

    The branch name is a parameter because every caller depends on its own: the
    publish tool is told which ref to read and which to write, and a fixture
    built on the wrong branch drives nothing.
    """
    root.mkdir(parents=True, exist_ok=True)
    run_git(root, "init", "-q", "-b", branch)
    run_git(root, "config", "user.email", COMMITTER_EMAIL)
    run_git(root, "config", "user.name", committer)


def run_gate(
    root: Path,
    gate: str,
    *,
    reads_root: bool = True,
    env: dict[str, str] | None = None,
    timeout: int = GATE_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    """Run the copy of ``gate`` that ``root`` carries.

    The root is passed as an argument, never through the environment: an ambient
    variable that selects the tree a gate reads can redirect it in production too.

    ``reads_root`` says whether the gate SCANS a tree. Most do, and take --root
    to say which. One does not: check-buildx.sh asks the local docker whether the
    buildx plugin is installed, which is a property of the machine rather than of
    a tree. Handing it a flag it does not parse would be a seam that looks
    meaningful and is not, so it is not handed one. ``root`` still selects WHICH
    COPY of the script runs, which is the runner's other job and the reason a
    gate that reads no tree still belongs here.

    Nothing enforces this for a gate that ignores unknown arguments, and that is
    said rather than left to be assumed: set ``reads_root=True`` for the buildx
    gate and its suite still passes, because a bash script that never reads "$@"
    does not notice. The flag is a statement about the gate's contract, not a
    check on it.

    This parameter exists because the alternative was worse: the buildx suite
    wrote its own subprocess call while importing this module's timeout and its
    marks — reaching in for the constants and re-implementing the function that
    uses them. That is the shape this module's docstring records happening once
    already, when one gate runner grew an ``env`` parameter and a longer timeout
    and the other two did not.

    ``env`` exists only so one suite can put a deliberately broken scanner, or a
    stub docker, on PATH — it selects which binary runs, never which tree is
    read. Leaving it at ``None`` inherits the caller's environment, which is
    exactly what passing no ``env`` at all would do.
    """
    cmd = ["bash", str(root / "scripts" / gate)]
    if reads_root:
        cmd += ["--root", str(root)]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )


def guard_marks(*, skip_when: bool, reason: str = GATE_ABSENT_REASON) -> list[pytest.MarkDecorator]:
    """The two marks a structural guard suite declares.

    ``stack_isolation("isolated")`` makes the autouse cleanup dispatch a no-op,
    which would otherwise resolve a live Postgres DSN these suites have no use
    for.

    The skip takes the caller's own condition rather than a path this function
    tests for itself. One suite asks whether a file is present and another asks
    about a directory, and a shared ``exists()`` would quietly weaken both.
    """
    return [
        pytest.mark.stack_isolation("isolated"),
        pytest.mark.skipif(skip_when, reason=reason),
    ]


def private_key_pem() -> bytes:
    """A real, freshly generated Ed25519 private key.

    Generated rather than pasted as a constant: a committed literal key is the
    thing the secret gate exists to keep out of the tree, and a guard's own
    fixture is not exempt from that.
    """
    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
