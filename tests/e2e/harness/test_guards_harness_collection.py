"""Meta-guard — importing this package must not require ``scripts/``.

The guard suites read ``scripts/published-paths.sh`` and drive the shell gates
next to it. None of that exists in the e2e runner image. Its final stage copies
in the harness, the harness's ``pyproject.toml``, the demo fixtures and
``testdata``; the compose file mounts the signing keys, the compose file itself,
the docker socket and the revocation directory. ``scripts/`` arrives by neither
route. Each of those suites therefore carries a skip mark, and on the host —
where the files do exist — they run for real. That arrangement works only while
the absence is discovered at RUN time.

Discover it at IMPORT time instead and the skip mark never gets a chance, because
pytest has to import a module before it can read ``pytestmark``. What pytest does
with an exception raised during import is not "skip this module": it records a
collection error and ends the run with ``Interrupted: N errors during
collection``. The modules that imported fine are collected and then never run,
which is easy to mistake for a configuration problem rather than a failure.

That is not hypothetical. Two module-scope lines of the form
``shared_array("ALLOW_DOC_FILES")[0]`` did exactly this: the rest of the package
collected cleanly, those two raised on import, and a healthy unrelated module
never ran. The individual lines are gone; this case is what stops the next one,
whatever array or file it reaches for.

Deliberately carries no SKIP mark, unlike its sibling guards — only the isolation
mark they all share. It reads no gate and drives no shell script, so there is
nothing for it to skip on, and it has to run in both places: on the host it is
the only thing watching, and in the container it still holds because it supplies
the missing root itself.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

HARNESS_DIR = Path(__file__).resolve().parent

# Long enough for a cold interpreter to import every module in the package.
# Collection does no I/O beyond that, so this is generous rather than tuned.
_COLLECT_TIMEOUT = 180


def _collection_aborted(combined: str) -> list[str]:
    """Return the lines of pytest output that report a COLLECTION abort.

    Matched against pytest's own markers, not the substring "error" anywhere in
    the output. That output lists every collected node id, so a bare substring
    match forbids the word "error" in any test name in the package -- which is a
    normal word for a test about an error detail, and cost one an afternoon.

    A collection failure prints "ERROR <module>" in the short summary and
    "Interrupted: N error(s) during collection"; neither can collide with a
    lowercase node id. Both spellings are matched because either can appear
    alone: -q trims the short summary on some runs, and the Interrupted line is
    absent when a plugin swallows the exception.

    Pure so it can be driven directly. The caller runs a real pytest subprocess
    and can only produce the passing path, so until this was a function of its
    own the detector had never been observed firing.
    """
    return [
        line
        for line in combined.splitlines()
        if line.startswith("ERROR ") or "during collection" in line
    ]


@pytest.mark.stack_isolation("isolated")
def test_the_package_collects_without_the_scripts_directory(tmp_path: Path) -> None:
    """Collection succeeds when REPO_ROOT holds no ``scripts/``.

    ``conftest`` derives REPO_ROOT from the compose file's parent, and takes that
    file's path from RAMP_E2E_COMPOSE_FILE when it is set. Pointing that variable
    at an otherwise empty directory reproduces the container exactly, without a
    container: every path the guard suites reach for is absent, and the only
    correct response is to skip them and collect everything else.

    ``--collect-only`` is load-bearing twice over. It imports every module, which
    is the whole subject here, and it executes no test, so the inner run cannot
    reach this case and recurse into itself.
    """
    fake_root = tmp_path / "root-without-scripts"
    fake_root.mkdir()
    # Only the file conftest resolves REPO_ROOT from. Its content is never read.
    (fake_root / "docker-compose.e2e.yml").touch()
    assert not (fake_root / "scripts").exists(), "the fixture must not supply scripts/"

    env = dict(os.environ)
    env["RAMP_E2E_COMPOSE_FILE"] = str(fake_root / "docker-compose.e2e.yml")

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--collect-only", str(HARNESS_DIR)],
        cwd=str(HARNESS_DIR.parent),
        capture_output=True,
        text=True,
        check=False,
        timeout=_COLLECT_TIMEOUT,
        env=env,
    )

    combined = proc.stdout + proc.stderr
    # Three outcomes have to be told apart, and the exit status alone separates
    # none of them: a collection error and a plain usage mistake in the command
    # above both exit non-zero, and a run that imported nothing at all would exit
    # 0. The wording assertions are what distinguish the three.
    #
    # Matched against pytest's OWN markers, not the substring "error" anywhere in
    # the output. That output lists every collected node id, so a bare substring
    # match forbids the word "error" in any test name in the package — which is a
    # normal word for a test about an error detail, and cost one an afternoon.
    # A collection failure prints "ERROR <module>" in the short summary and
    # "Interrupted: N error(s) during collection"; neither can collide with a
    # lowercase node id.
    aborted = _collection_aborted(combined)
    assert not aborted, (
        "importing the harness raised with scripts/ absent, so pytest aborted "
        "collection and NO test in the package would run. Something now reads the "
        f"shared definition at module scope; move it into a test body.\n\n{combined}"
    )
    assert proc.returncode == 0, combined
    # Only meaningful once `aborted` is empty: pytest prints "N tests collected,
    # 1 error" on the failing path too, so this line alone separates nothing.
    assert "tests collected" in combined, combined


@pytest.mark.stack_isolation("shared-without-cleanup")
def test_the_abort_detector_reads_pytests_markers_not_the_word_error() -> None:
    """The detector fires on a real abort and stays quiet on a clean run.

    Three cases, and the first is the one that matters. A clean collection lists
    every node id it found, and a package that tests error handling has the word
    "error" all through those ids -- so a detector matching the bare substring
    reports an abort on a run where nothing went wrong. The other two are the two
    spellings pytest actually uses to say collection stopped.

    Drives the pure function rather than the subprocess: the subprocess can only
    produce the passing case, which is exactly why the failing ones were never
    seen.
    """
    clean = (
        "harness/test_error_detail.py::test_error_reason_is_decoded PASSED\n"
        "harness/test_guards_denial_reason_key.py::test_no_camelcase_error_key PASSED\n"
        "2 tests collected in 0.42s"
    )
    assert _collection_aborted(clean) == [], (
        "reported an abort on a clean run whose node ids merely contain the word "
        "'error' -- the detector is matching text, not pytest's markers"
    )

    short_summary = "ERROR harness/test_seed.py\n1 error in 0.11s"
    assert _collection_aborted(short_summary) == ["ERROR harness/test_seed.py"]

    interrupted = "!!!! Interrupted: 2 errors during collection !!!!"
    assert _collection_aborted(interrupted) == [interrupted]
