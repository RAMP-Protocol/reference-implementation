"""Meta-guard — the buildx gate must actually refuse a docker without the plugin.

``scripts/check-buildx.sh`` is a prerequisite of ``make e2e-up``. It exists
because compose falls back to Docker's legacy builder SILENTLY when the buildx
plugin is missing, and the only symptom is a stack-up that takes most of an hour
instead of a minute.

Nothing exercised it. On any machine that has ever run the e2e suite the plugin
is installed, so the failing branch never ran — invert the condition or empty the
body and every gate in the repository still passes. A gate nobody has watched
fail is a gate nobody knows the state of.

The plugin is stubbed rather than uninstalled: a temporary directory is put at
the front of PATH holding a ``docker`` that answers however the case wants. That
drives the real script, with its real condition, against both answers.

Pure subprocess work: no stack, no Docker, no database. The marks come from
``guard_harness.guard_marks``, whose docstring says why the isolation one is
there.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from .conftest import REPO_ROOT
from .guard_harness import GATE_TIMEOUT, guard_marks

GATE = REPO_ROOT / "scripts" / "check-buildx.sh"

pytestmark = guard_marks(skip_when=not GATE.is_file())


def _docker_stub(tmp_path: Path, *, buildx_exit: int) -> Path:
    """A directory holding a ``docker`` that exits ``buildx_exit`` for buildx.

    Only the buildx subcommand is answered, because that is the only call the
    gate makes. A stub that answered everything would be a stub the gate could
    drift away from without this suite noticing.
    """
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "docker"
    stub.write_text(
        '#!/usr/bin/env bash\nif [ "$1" = "buildx" ]; then exit %d; fi\nexit 0\n' % buildx_exit
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    return stub_dir


def _run_gate(stub_dir: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = f"{stub_dir}{os.pathsep}{env['PATH']}"
    return subprocess.run(
        ["bash", str(GATE)],
        capture_output=True,
        text=True,
        timeout=GATE_TIMEOUT,
        env=env,
        check=False,
    )


def test_gate_passes_when_buildx_answers(tmp_path: Path) -> None:
    """Without this the negative below proves nothing: a gate that failed for an
    unrelated reason — a missing file, a syntax error — would satisfy it."""
    proc = _run_gate(_docker_stub(tmp_path, buildx_exit=0))

    assert proc.returncode == 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"


def test_gate_refuses_when_buildx_is_missing(tmp_path: Path) -> None:
    """The branch that has never run on a developer machine.

    Asserted on the message and not only on the exit code: the whole point of
    this gate is that the failure explains itself, since the condition it
    catches produces no error of its own.
    """
    proc = _run_gate(_docker_stub(tmp_path, buildx_exit=1))

    assert proc.returncode == 1, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    assert "buildx" in proc.stderr
    assert "docker-buildx" in proc.stderr, "the refusal must name the package to install"
