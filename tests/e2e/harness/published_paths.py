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

    The explicit file check is what makes that sentence true, and it is not
    redundant with ``check=True``. When ``source`` fails, bash reports it on
    stderr and carries on to the next command in the ``-c`` string; ``printf``
    is that next command and it succeeds, so the shell exits 0 and ``check=True``
    is satisfied over an empty result. Measured, not assumed.
    """
    if not PATHS_FILE.is_file():
        raise FileNotFoundError(
            f"{PATHS_FILE} does not exist, so the published-path arrays cannot be read. "
            "The expected cause is the e2e runner container, where scripts/ is neither "
            "copied into the image nor mounted. Every suite that reads these arrays "
            "carries a skip mark for that case, and the mark works only if the read "
            "happens inside a test body — never at module scope."
        )
    out = subprocess.run(
        ["bash", "-c", f'source "$1"; printf "%s\\n" "${{{name}[@]}}"', "_", str(PATHS_FILE)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    ).stdout
    return [line for line in out.splitlines() if line]


def first_entry(name: str) -> str:
    """Return the first entry of one shared array, for a case that needs a sample.

    CALL THIS FROM A TEST BODY, NEVER AT MODULE SCOPE — and the same goes for
    ``shared_array`` and for anything derived from either, including a
    ``@pytest.mark.parametrize`` list, which is evaluated at import.

    Anything raised while a module is imported is a COLLECTION error, and pytest
    answers a collection error by aborting the whole session. It does not skip
    the offending module and continue: it reports ``Interrupted: N errors during
    collection`` and every other module's tests stop running too. Two module-scope
    calls of the form ``shared_array(...)[0]`` once did exactly that to the e2e
    tier — the rest of the package collected cleanly and none of it ran.

    The skip marks the guard suites carry are no defence, because pytest has to
    import a module before it can read ``pytestmark``. Deferring the call into a
    test body is what lets the skip do its job.
    """
    entries = shared_array(name)
    if not entries:
        raise ValueError(
            f"{name} is empty in {PATHS_FILE}, so this case has no sample path to work "
            "with and would assert nothing. Give the array an entry, or drop the case."
        )
    return entries[0]
