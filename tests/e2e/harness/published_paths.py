"""Read the published-path definition that ``scripts/published-paths.sh`` owns.

The guard suites build their fixture trees from these arrays rather than from a
transcribed literal. A transcribed copy would have to be edited in step with the
definition, which is the duplication that definition exists to retire — and when
it drifted, every test in those modules failed, including the ones asserting that
a clean tree passes.

Sourcing the shell file is what makes it one definition rather than two. There is
no Python parser for it on purpose: a parser would be a second reading of the
same data, and it would disagree with the shell the first time an entry gained a
comment or a line continuation.

A module of its own rather than a fixture in ``conftest``: it takes no fixture
arguments and several modules import it at import time, to build constants before
any test runs.
"""

from __future__ import annotations

import subprocess

from .conftest import REPO_ROOT

PATHS_FILE = REPO_ROOT / "scripts" / "published-paths.sh"


def shared_array(name: str) -> list[str]:
    """Return one array from the shared definition, in the order the file lists it.

    Raises rather than returning empty when the file cannot be sourced. An empty
    list would let a fixture build a tree with nothing in it, and every guard
    that scans that tree would then report success having read nothing.
    """
    out = subprocess.run(
        ["bash", "-c", f'source "$1"; printf "%s\\n" "${{{name}[@]}}"', "_", str(PATHS_FILE)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return [line for line in out.splitlines() if line]
