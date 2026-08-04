"""Meta-guard — nothing may be interpolated into a workflow's shell.

GitHub substitutes a ``${{ ... }}`` expression into a script as TEXT, before the
interpreter reads it. A value that arrives that way is command text, not an
argument, and a git ref name is allowed to hold ``$``, backticks, parentheses,
``;``, ``&`` and ``|``. git does reject some characters — spaces, backslashes,
control characters, and the revision syntax it needs for itself — but not one of
those omissions closes the hole. The publishing workflow holds a token with
``packages: write`` for all three service images, so a script built this way
turns "can push a tag" into "can run anything". The fix is an ``env:`` entry,
which delivers the value as data.

Two positions count as a script. ``run:`` is the obvious one. ``with: script:``
is the other: ``actions/github-script`` evaluates that value as JavaScript, so an
expression interpolated there is the same defect wearing a different key.

The second rule is about versions. Every published tag comes from the git tag and
nowhere else (ADR-024 D2), so a version written into a script is a second place
that has to be edited at release time, and the last one anybody thinks to check.
Confining the rule to scripts is what makes it exception-free: the pinned
third-party actions carry their version in a comment on the ``uses:`` line, which
is never inside one.

What each case reads, because the two kinds are not interchangeable:

- The cases built on ``_workflow_with`` drive the extraction over SYNTHETIC text.
  They are what proves the checks fire, and that they fire on scripts only — the
  synthetic workflow always carries an expression in an action input and in an
  ``env:`` value, so a check that scanned the whole file instead would fail its
  clean case.
- The cases built on ``_WORKFLOWS`` read the REAL files under
  ``.github/workflows/``. Nothing else in this repository parses them: there is no
  actionlint, no yamllint and no yq.

Pure parsing work: no stack, no Docker, no database. The marks come from
``guard_harness.guard_marks``, whose docstring says why the isolation one is
there.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .conftest import REPO_ROOT
from .guard_harness import guard_marks

# REPO_ROOT rather than a parents[N] walk: inside the runner container the
# harness sits at /runner/harness, which has fewer parents than the host layout,
# and computing the walk here raises at import — killing collection for the whole
# tier rather than this one module.
_WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"

# Both extensions, because GitHub reads both. A file renamed from one to the
# other must stay inside the scan rather than leaving it silently.
_WORKFLOWS = sorted([*_WORKFLOW_DIR.glob("*.yml"), *_WORKFLOW_DIR.glob("*.yaml")])

_EXPRESSION = re.compile(r"\$\{\{")
_VERSION_LITERAL = re.compile(r"\bv?[0-9]+\.[0-9]+\.[0-9]+")

pytestmark = guard_marks(
    skip_when=not _WORKFLOW_DIR.is_dir(),
    reason="the workflow directory is absent from the e2e runner image; this guard runs on the host",
)


def _scripts(text: str) -> list[tuple[str, str]]:
    """Every script in one workflow, each labelled with its owner and its key.

    Two keys carry a script: ``run:``, which bash executes, and ``with: script:``,
    which actions/github-script evaluates as JavaScript. The label is what a
    failure prints, so it names the step and the key rather than an index into a
    list the reader cannot see.

    ``or []`` on the step list rather than a default argument: a job written with
    ``steps:`` and nothing under it parses to None, and a reusable-workflow job
    has no ``steps`` key at all.
    """
    document = yaml.safe_load(text) or {}
    found: list[tuple[str, str]] = []
    for job_id, job in (document.get("jobs") or {}).items():
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict):
                continue
            name = step.get("name") or f"step {index}"
            if "run" in step:
                found.append((f"{job_id} / {name} [run:]", str(step["run"])))
            script = (step.get("with") or {}).get("script")
            if script is not None:
                found.append((f"{job_id} / {name} [script:]", str(script)))
    return found


def _expressions_in_scripts(text: str) -> list[str]:
    return [label for label, body in _scripts(text) if _EXPRESSION.search(body)]


def _versions_in_scripts(text: str) -> list[tuple[str, str]]:
    return [
        (label, hit) for label, body in _scripts(text) for hit in _VERSION_LITERAL.findall(body)
    ]


def _workflow_with(body: str, *, key: str = "run") -> str:
    """A minimal workflow whose only script is ``body``, written under ``key``.

    It always carries an expression in an action input and in an ``env:`` value.
    Those are the two safe positions, so the clean case below fails if either
    check ever widens from the scripts to the whole file.
    """
    if key == "run":
        script_step = (
            "      - name: The script\n"
            "        env:\n"
            "          TRIGGER_REF: ${{ github.ref }}\n"
            "        run: |\n" + _indent(body, 10)
        )
    else:
        script_step = (
            "      - name: The script\n"
            "        uses: actions/github-script"
            "@0000000000000000000000000000000000000000 # v9.9.9\n"
            "        with:\n"
            "          script: |\n" + _indent(body, 12)
        )
    return (
        "name: probe\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  probe:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - name: An action input, which is not a script\n"
        "        uses: some/action@0000000000000000000000000000000000000000 # v9.9.9\n"
        "        with:\n"
        "          ref: ${{ github.ref }}\n" + script_step
    )


def _indent(body: str, width: int) -> str:
    pad = " " * width
    return "\n".join(f"{pad}{line}" for line in body.splitlines()) + "\n"


def test_a_clean_script_is_not_reported() -> None:
    """Without this the cases that follow prove nothing.

    A check that reported every workflow would satisfy all of them. This one also
    pins the boundary: the synthetic workflow puts an expression in an action
    input and in an env: value, and neither is a finding.
    """
    text = _workflow_with('echo "ref is ${TRIGGER_REF}"')

    assert _scripts(text), "the fixture contributed no script, so nothing was examined"
    assert _expressions_in_scripts(text) == []
    assert _versions_in_scripts(text) == []


def test_an_expression_inside_a_run_script_is_reported() -> None:
    """The injection shape: the ref becomes part of the command bash runs."""
    text = _workflow_with('echo "ref is ${{ github.ref }}"')

    assert _expressions_in_scripts(text) == ["probe / The script [run:]"]


def test_an_expression_inside_a_github_script_is_reported() -> None:
    """The same defect under a different key, evaluated as JavaScript.

    A check that looked only at ``run:`` would report nothing here, and the
    module's claim to cover the injection class would be false.
    """
    text = _workflow_with("console.log('ref is ${{ github.ref }}')", key="script")

    assert _expressions_in_scripts(text) == ["probe / The script [script:]"]


def test_a_version_written_into_a_script_is_reported() -> None:
    """A version in a script is a second place a release has to edit."""
    text = _workflow_with('echo "for example v1.0.0"')

    assert _versions_in_scripts(text) == [("probe / The script [run:]", "v1.0.0")]


def test_the_workflows_are_present_and_contribute_scripts() -> None:
    """A PASS on the real-file cases means nothing if nothing was read.

    Each of them iterates the scripts these files contain, so a rename that
    emptied the glob, or a restructure that left no script at all, would turn
    them green having examined nothing.
    """
    assert _WORKFLOWS, f"no workflow file under {_WORKFLOW_DIR}"

    scripts = [body for path in _WORKFLOWS for body in _scripts(path.read_text())]

    assert scripts, "the workflows parse but contribute no script to examine"


def test_no_workflow_interpolates_an_expression_into_a_script() -> None:
    """Read over the real files, which nothing else in this repository parses."""
    found: list[str] = []
    for path in _WORKFLOWS:
        found += [
            f"{_relative(path)}: {label}" for label in _expressions_in_scripts(path.read_text())
        ]

    assert found == [], (
        "these scripts are built by text substitution; pass the value through env: instead:\n"
        + "\n".join(found)
    )


def test_no_workflow_names_a_version_inside_a_script() -> None:
    """Read over the real files. The tag is the only source of a version."""
    found: list[str] = []
    for path in _WORKFLOWS:
        found += [
            f"{_relative(path)}: {label} names {hit}"
            for label, hit in _versions_in_scripts(path.read_text())
        ]

    assert found == [], (
        "a version written into a script is a second place a release has to edit:\n"
        + "\n".join(found)
    )


def _relative(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT))
