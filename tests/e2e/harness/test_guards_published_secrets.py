"""Meta-guard — the published-set secret scan must never pass without reading.

``scripts/check-published-secrets.sh`` runs the secret scanner over the tracked
files the publish ships, and it is wired into ``make quality``. A green quality
run is therefore taken as evidence that no key sits on a published path. That
evidence is worth something only if the gate can fail, and only if it fails for
the right inputs.

Both halves are under test here, because this gate has two ways to be wrong and
they pull in opposite directions:

    a key on a published path        -> FAIL   (it can see)
    a key on a path that never ships -> PASS   (it does not cry wolf)

The second half is not politeness. This repository keeps unpublished design docs
that quote key material, and generated local dev keys sit inside ``deploy/``
while being gitignored. A gate that reported those would be turned off within a
week, so the cases below pin every category it is supposed to ignore as
carefully as the ones it must catch.

Three properties get their own cases because each was a deliberate design
decision that a later refactor could quietly undo:

    tracked files only     — a directory walk would report gitignored dev keys
    working-tree content   — reading the committed blob would miss a pasted key
                             that has not been committed yet, which is the state
                             a developer is actually in when the gate runs
    the exemption is narrow — the terraform fixture path is allowlisted in
                             .gitleaks.toml; its sibling directories are not

The fixture builds a real git repository rather than a plain directory, because
"tracked" is a git notion and the gate lists its files with ``git ls-files``.
``.gitleaks.toml`` is copied verbatim for the same reason the publish guard copies
it: an empty file is a zero-rule config, and a zero-rule config makes every case
below pass.

Pure subprocess work: no stack, no Docker, no database. The marks come from
``guard_harness.guard_marks``, whose docstring says why the isolation one is
there.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from .conftest import REPO_ROOT
from .guard_harness import (
    GITLEAKS_ABSENT,
    SECRET_SCAN_CONFIG,
    commit_all,
    guard_marks,
    init_scratch_repo,
    private_key_pem,
    run_gate,
    run_git,
)
from .published_paths import first_entry, shared_array

# REPO_ROOT rather than a parents[N] walk: inside the runner container the
# harness sits at /runner/harness, which has fewer parents than the host layout,
# and computing the walk here raises at import — killing collection for the whole
# tier rather than this one module.
_GATE = REPO_ROOT / "scripts" / "check-published-secrets.sh"

# This gate is the slow one: gitleaks reads every file in the tree, where the
# sibling gates are greps. The shared default is sized for those.
_SCAN_TIMEOUT = 300

# The exempted path, and a sibling that is not exempted. Both are inside the
# published set; the only difference between them is the allowlist entry, which
# is exactly the distinction these cases exist to pin.
_EXEMPT_FIXTURE = "deploy/terraform/modules/compose-stack/tests/planted.tftest.hcl"
_UNEXEMPT_SIBLING = "deploy/terraform/modules/aws-vm/tests/planted.tftest.hcl"

pytestmark = [*guard_marks(skip_when=not _GATE.is_file()), GITLEAKS_ABSENT]


def _build_repo(root: Path) -> None:
    """Materialise a committed miniature of the published set.

    Every directory, docs/ file, root file and allowlisted script the shared
    definition names has to exist, because the gate treats a missing search root
    as a failure rather than as nothing to scan — that is the behaviour the
    missing-root case asserts.
    """
    init_scratch_repo(root, branch="main", committer="published secrets guard")

    for directory in shared_array("ALLOW_DIRS"):
        (root / directory).mkdir(parents=True, exist_ok=True)
        (root / directory / ".keep").write_text("")

    for doc in shared_array("ALLOW_DOC_FILES"):
        (root / doc).parent.mkdir(parents=True, exist_ok=True)
        (root / doc).write_text(f"# {doc}\n")

    for name in shared_array("ALLOW_ROOT_FILES"):
        if name == SECRET_SCAN_CONFIG:
            (root / name).write_bytes((REPO_ROOT / name).read_bytes())
        else:
            # The ignore files must stay EMPTY. This fixture commits planted key
            # files with `git add -A`, and the real .gitignore excludes *.pem, so
            # a verbatim copy would leave the planted files untracked and every
            # negative case below would pass for the wrong reason.
            (root / name).write_text("")

    for script in shared_array("ALLOW_SCRIPTS"):
        dest = root / script
        dest.parent.mkdir(parents=True, exist_ok=True)
        src = REPO_ROOT / script
        # The gate and its shared definition are copied verbatim, because the
        # subject under test is the shipped artifact. The rest only have to exist.
        dest.write_bytes(src.read_bytes() if src.is_file() else b"")

    # The unexempted sibling directory. Without it, the case that plants a key
    # there would be testing a path that does not exist in the fixture.
    (root / _UNEXEMPT_SIBLING).parent.mkdir(parents=True, exist_ok=True)
    (root / _EXEMPT_FIXTURE).parent.mkdir(parents=True, exist_ok=True)

    # An unpublished doc tree, so the "not published" case has somewhere to plant.
    (root / "docs" / "design").mkdir(parents=True, exist_ok=True)
    (root / "docs" / "design" / "note.md").write_text("# not a published doc\n")

    commit_all(root, "baseline")


def _run_gate(root: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """This gate's parameters. The mechanics are shared, and only these differ.

    ``env`` is one of them: it exists only to place a broken scanner on PATH, and
    it selects which gitleaks binary runs, never which tree is read.
    """
    return run_gate(root, _GATE.name, env=env, timeout=_SCAN_TIMEOUT)


def _plant(root: Path, relative: str, *, commit: bool) -> None:
    """Write a real private key at ``relative`` and optionally commit it."""
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(private_key_pem())
    if commit:
        run_git(root, "add", "-f", relative)
        run_git(root, "commit", "-qm", f"plant {relative}")


@pytest.fixture
def published_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    _build_repo(root)
    return root


def test_clean_tree_passes(published_repo: Path) -> None:
    """The gate does not cry wolf on a tree with no key material.

    Without this the negative cases prove nothing: a gate that failed everything
    would satisfy every one of them.
    """
    proc = _run_gate(published_repo)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout, proc.stdout


def test_clean_run_reports_how_much_it_read(published_repo: Path) -> None:
    """A PASS names the number of files scanned.

    The count is the operator's only signal that the run covered the tree rather
    than an empty directory, and a PASS over nothing is the exact failure this
    module exists to catch.
    """
    proc = _run_gate(published_repo)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "files scanned" in proc.stdout, proc.stdout
    assert "(0 files scanned)" not in proc.stdout, proc.stdout


@pytest.mark.parametrize(
    "relative",
    [
        "src/planted.pem",
        "internal/planted.pem",
        "deploy/planted.pem",
        _UNEXEMPT_SIBLING,
        "scripts/check-published-refs.sh",
        "sqlc.yaml",
    ],
    ids=[
        "src",
        "internal",
        "deploy",
        "terraform-sibling",
        "inside-an-allowlisted-script",
        "inside-a-root-build-file",
    ],
)
def test_a_key_on_a_published_path_is_rejected(published_repo: Path, relative: str) -> None:
    """Every published root is actually scanned, not just the first one.

    The parametrisation is one case per root class rather than a single planted
    key, because the roots are assembled from four separate arrays and a bug that
    dropped one of them would SLIP PAST a single-path test aimed at a surviving
    array: that test's key is still found, the gate still exits non-zero, and the
    dropped array is never missed. The first four paths cover ALLOW_DIRS, the
    fifth ALLOW_SCRIPTS and the sixth ALLOW_ROOT_FILES; ALLOW_DOC_FILES has its
    own case below, for a reason that case explains.

    Two of them are array ENTRIES written out here rather than read from the
    shared definition — the script and the root build file. Neither needs a drift
    guard: an entry that leaves its array stops being a search root, so the gate
    finds nothing, the run exits 0 and the case goes red on its own. That is the
    same signal a renamed entry would give. The other four name a file planted
    under an allowlisted directory, so only the directory has to still be listed.

    The last two overwrite a file the fixture already created instead of adding a
    new one: an unlisted path under scripts/ is never published, so a key there
    is correctly ignored, and only a key inside a file that ships is a finding.
    """
    _plant(published_repo, relative, commit=True)

    proc = _run_gate(published_repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    # The gate's own message, not merely a non-zero exit: the missing-root and
    # scanner-absent paths also exit non-zero, and asserting on the code alone
    # would let this case pass while the scan never ran.
    assert "potential secrets in the published tree" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_a_key_in_an_allowlisted_doc_is_rejected(published_repo: Path) -> None:
    """The ALLOW_DOC_FILES root is read, not merely listed.

    Those files sit under no other root — ALLOW_DIRS carries docs/architecture
    and nothing else beneath docs/ — so that array is the only reason any of them
    is scanned at all. Remove it from the gate's SEARCH_ROOTS and the scan set
    shrinks by exactly those files while every other case here still passes. Only
    this one goes red.

    It is a case of its own rather than a seventh parameter above, and the
    distinction is not cosmetic. A parametrize list is evaluated when the module
    is imported, so resolving the path there would fail at import wherever
    scripts/ is absent — the runner container — and pytest answers an import
    failure by aborting the whole session rather than skipping the module. That
    regression is what the sibling collection guard exists to catch; there is no
    sense re-introducing it in the file that closes this gap.
    """
    doc = first_entry("ALLOW_DOC_FILES")
    _plant(published_repo, doc, commit=True)

    proc = _run_gate(published_repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    # As above: the gate's own wording, since several other paths also exit
    # non-zero without having scanned anything.
    assert "potential secrets in the published tree" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_a_key_in_an_unpublished_path_is_ignored(published_repo: Path) -> None:
    """A docs/ path that no allowlist names never ships, so it is not this gate's business.

    Most of docs/ is in that position. Two things travel: docs/architecture as a
    subtree, and the files named one by one in ALLOW_DOC_FILES, by their own
    array. Everything else stays behind. The case above plants a key in one of
    the files that ship; this one plants it on a path that does not.

    The design docs quote key material in places. Reporting them would make the
    gate noisy enough to be disabled, and would say nothing about what the public
    repository receives.
    """
    # published-ref-allow: a test that pins which paths are unpublished has to name one
    _plant(published_repo, "docs/design/planted.pem", commit=True)

    proc = _run_gate(published_repo)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout, proc.stdout


def test_an_untracked_key_under_a_published_root_is_ignored(published_repo: Path) -> None:
    """The gate lists tracked files, so gitignored local output is out of scope.

    Generated dev keys live under deploy/ on every developer machine that has run
    the local stack. They are gitignored and never published, and a directory walk
    would report them on every single run.
    """
    _plant(published_repo, "deploy/untracked.pem", commit=False)

    proc = _run_gate(published_repo)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout, proc.stdout


def test_an_uncommitted_key_in_a_tracked_file_is_rejected(published_repo: Path) -> None:
    """The scan reads the working tree, not the committed blob.

    This is the state a developer is in when `make quality` runs: the key has
    been pasted into a file that git already tracks, and it has not been
    committed. Reading the committed content instead would report clean at the
    one moment the finding is still cheap to fix.
    """
    tracked = published_repo / "src" / ".keep"
    tracked.write_bytes(private_key_pem())

    proc = _run_gate(published_repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "potential secrets in the published tree" in combined, combined


def test_the_terraform_fixture_exemption_applies(published_repo: Path) -> None:
    """The allowlisted terraform test fixture is exempt, and that is deliberate.

    The compose-stack suite feeds the module PEM-shaped and password-shaped
    values so it can assert what the rendered cloud-init does and does not
    contain, and its provider mocks mean the suite reaches no cloud account. The
    scanner cannot tell those fixtures from real material, so .gitleaks.toml
    exempts the path.

    Paired with the terraform-sibling case above, which plants the same key one
    directory across and must still fail. Together they pin the exemption as
    narrow rather than as "terraform is not scanned".
    """
    _plant(published_repo, _EXEMPT_FIXTURE, commit=True)

    proc = _run_gate(published_repo)

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout, proc.stdout


def test_a_missing_search_root_fails_loudly(published_repo: Path) -> None:
    """A renamed root aborts — it must never be read as "nothing found".

    This is the failure mode that cost the sibling reference gate its coverage:
    it scanned nothing and reported PASS. Here the same shape would mean an
    entire published directory stopped being scanned for secrets.
    """
    run_git(published_repo, "mv", "src", "src_moved")

    proc = _run_gate(published_repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "search root" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_an_untracked_scanner_config_is_refused(published_repo: Path) -> None:
    """A .gitleaks.toml the scan cannot reach means the default ruleset, not ours.

    gitleaks falls back to its defaults when the file is absent from the tree it
    scans, so the run would still finish and could still report PASS — over a
    rule set nobody in this repository has vetted, and without any of the
    reviewed exemptions.

    The config is untracked here rather than deleted, and that is the whole
    point. Deleting it is already caught one step earlier, because the file is
    also a required search root; only an untracked one reaches the copy step,
    gets skipped by ``git ls-files``, and arrives at the scanner as an absence.
    The assertion names a phrase unique to this check for the same reason —
    matching on the file name alone would pass on the missing-root message.
    """
    run_git(published_repo, "rm", "-q", "--cached", SECRET_SCAN_CONFIG)

    proc = _run_gate(published_repo)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "default ruleset" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_a_tree_with_no_tracked_files_is_refused(tmp_path: Path) -> None:
    """Zero files scanned is a broken run, not a clean one.

    Every search root exists on disk here, so the missing-root check is satisfied
    and nothing upstream objects — but nothing has been committed, so the file
    list comes back empty. The scanner would happily report no leaks over an
    empty directory, which is the strongest possible PASS backed by the weakest
    possible evidence.
    """
    root = tmp_path / "untracked-repo"
    _build_repo(root)
    # Unstage everything while leaving the working tree exactly as it was, so the
    # roots still exist and only the tracked set is empty.
    run_git(root, "rm", "-rq", "--cached", ".")

    proc = _run_gate(root)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "no tracked files" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_a_scanner_that_fails_to_run_is_not_read_as_clean(
    published_repo: Path, tmp_path: Path
) -> None:
    """A scanner exit above 1 means the scan did not happen, and must not pass.

    gitleaks uses exit 1 for "findings" and 0 for "clean", so any other status is
    the tool itself failing — a bad config, a missing rule file, an unreadable
    tree. Collapsing that into either answer is how a scanner gate goes quietly
    blind, and the shim here is the only way to reach the branch without breaking
    a real installation.
    """
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    shim = shim_dir / "gitleaks"
    shim.write_text("#!/usr/bin/env bash\necho 'simulated scanner failure' >&2\nexit 2\n")
    shim.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{shim_dir}:{env['PATH']}"

    proc = _run_gate(published_repo, env=env)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "scan itself failed" in combined, combined
    assert "PASS" not in proc.stdout, proc.stdout


def test_a_non_git_tree_is_refused(tmp_path: Path) -> None:
    """Outside a repository the published file set cannot be listed.

    The gate scans tracked files. Without git there is no such set, and the
    alternative — falling back to a directory walk — would be a second, untested
    behaviour that reports a different answer than the one under test here.
    """
    root = tmp_path / "plain"
    root.mkdir()
    (root / "scripts").mkdir()
    shutil.copy(_GATE, root / "scripts" / _GATE.name)
    shutil.copy(REPO_ROOT / "scripts" / "published-paths.sh", root / "scripts")

    proc = _run_gate(root)

    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "PASS" not in proc.stdout, proc.stdout
