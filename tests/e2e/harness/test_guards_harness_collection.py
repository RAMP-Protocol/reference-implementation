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
    assert "error" not in combined.lower(), (
        "importing the harness raised with scripts/ absent, so pytest aborted "
        "collection and NO test in the package would run. Something now reads the "
        f"shared definition at module scope; move it into a test body.\n\n{combined}"
    )
    assert proc.returncode == 0, combined
    assert "tests collected" in combined, combined
