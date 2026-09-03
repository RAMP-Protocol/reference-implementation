"""Meta-guard — the Lambda runtime emulator has exactly one invoker.

The emulator serves ONE invocation at a time. A second invocation arriving
while one is in flight makes it abort the in-flight request unanswered and exit
its own process; the container dies, and every test after that one fails on a
service name that no longer resolves. The first failure names a dropped
connection and the rest name DNS, so nothing in the output points at the
collision that caused all of it.

The container healthcheck used to be a real function invocation, run by Docker
on its own schedule for the container's whole life. That made the collision a
matter of timing rather than of correctness: it fired whenever a probe landed
on top of a slow invocation, which is exactly the shape of an intermittent CI
failure. The probe is now a connection check, and this suite is what stops it
going back.

Four properties, because closing only some of them leaves a green suite over a
probe that invokes again:

* the probe script performs no invocation, and pulls in no HTTP client it could
  perform one with;
* both emulator services still run that script as their healthcheck;
* the image still copies that script to the path those healthchecks name — the
  one link the first two assertions do not cover, and repointing it alone is
  enough to restore the defect;
* inside the harness, the invoke path appears in exactly one module, so the
  test client stays the only client.

Pure file reading: no stack, no Docker, no database.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .conftest import REPO_ROOT
from .guard_harness import guard_marks

# The path literal comes from the harness module that owns it rather than being
# restated here. A copy in this file would be a second occurrence of the very
# string the last assertion counts, and the guard would flag itself.
from .lambda_edge import INVOKE_PATH

_LAMBDA_DIR = REPO_ROOT / "tests" / "e2e" / "lambda-edge"
_PROBE = _LAMBDA_DIR / "healthcheck.mjs"
_DOCKERFILE = _LAMBDA_DIR / "Dockerfile"
_COMPOSE = REPO_ROOT / "docker-compose.e2e.yml"

# REPO_ROOT would be wrong here. Inside the e2e runner image the harness is
# copied to /runner/harness, not /runner/tests/e2e/harness, so a path built
# from REPO_ROOT resolves to a directory that does not exist and the scan comes
# up empty — passing for the wrong reason.
_HARNESS_DIR = Path(__file__).resolve().parent

# The two services that run the emulator. Both serve the same image; they
# differ only in which baked bundle their `command` selects.
_EMULATOR_SERVICES = ("lambda-edge", "lambda-edge-no-wba")

# Where the healthchecks look for the probe, and so where the image must put it.
_PROBE_IN_IMAGE = "/opt/healthcheck.mjs"

# An HTTP client is the capability an invocation needs. A probe that imports
# one has either started invoking again or is one edit away from it.
_HTTP_IMPORT = re.compile(r"""["']node:https?["']""")

pytestmark = guard_marks(
    skip_when=not (_PROBE.is_file() and _DOCKERFILE.is_file() and _COMPOSE.is_file()),
    reason="the lambda-edge image sources are absent from the e2e runner image; "
    "this guard runs on the host",
)


def _healthcheck_command(service: str) -> str:
    """The healthcheck command for ``service``, flattened to one string.

    Flattened rather than compared element-wise because compose accepts both a
    list and a bare string, and this guard cares only about which file the
    command names.
    """
    services = yaml.safe_load(_COMPOSE.read_text())["services"]
    svc = services.get(service)
    assert svc is not None, (
        f"no {service!r} service in docker-compose.e2e.yml — the compose file "
        "changed shape and this guard is no longer reading the emulator"
    )
    healthcheck = svc.get("healthcheck") or {}
    test = healthcheck.get("test")
    assert test, f"{service!r} declares no healthcheck test"
    return " ".join(test) if isinstance(test, list) else str(test)


def test_the_container_probe_never_invokes_the_function() -> None:
    probe = _PROBE.read_text()
    assert INVOKE_PATH not in probe, (
        "the lambda-edge container probe posts to the Lambda invoke path again. "
        "Docker runs it on its own schedule for the container's whole life, so "
        "it will eventually land on top of the harness's invocation, and the "
        "emulator answers a second concurrent invocation by exiting — killing "
        "the container mid-suite"
    )
    assert not _HTTP_IMPORT.search(probe), (
        "the lambda-edge container probe imports an HTTP client. The probe must "
        "prove only that the emulator accepts connections; anything that can "
        "speak HTTP to it can invoke it, and an invoking probe destroys the "
        "container when it collides with a test"
    )


def test_both_emulator_services_run_the_audited_probe() -> None:
    for service in _EMULATOR_SERVICES:
        command = _healthcheck_command(service)
        assert _PROBE_IN_IMAGE in command, (
            f"{service!r} no longer healthchecks with {_PROBE_IN_IMAGE} but with "
            f"{command!r} — its probe is outside the file this suite audits, so "
            "nothing stops it invoking the function"
        )


def test_the_image_copies_the_audited_probe_to_the_path_the_healthchecks_name() -> None:
    """The link the two assertions above leave open.

    Repoint this one COPY at some other file and both of them still pass: the
    audited script is still clean and both healthchecks still name
    /opt/healthcheck.mjs. What runs is whatever the COPY put there.
    """
    source = _PROBE.relative_to(REPO_ROOT).as_posix()
    copies = [
        line
        for line in _DOCKERFILE.read_text().splitlines()
        if line.startswith("COPY ") and _PROBE_IN_IMAGE in line
    ]
    assert copies, (
        f"the lambda-edge Dockerfile no longer copies anything to "
        f"{_PROBE_IN_IMAGE}, which is the file both healthchecks run"
    )
    for line in copies:
        assert source in line, (
            f"the lambda-edge Dockerfile fills {_PROBE_IN_IMAGE} from something "
            f"other than {source}: {line!r}. The healthchecks would run a script "
            "this suite never reads"
        )


def test_the_harness_is_the_only_invoker() -> None:
    invokers = sorted(
        path.relative_to(_HARNESS_DIR).as_posix()
        for path in _HARNESS_DIR.rglob("*.py")
        if INVOKE_PATH in path.read_text()
    )
    assert invokers == ["lambda_edge.py"], (
        f"the Lambda invoke path appears in {invokers}, not in lambda_edge.py "
        "alone. One module owns invocation so the harness stays a single "
        "sequential client; a second one is how two invocations end up in "
        "flight at once"
    )
