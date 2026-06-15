"""Compose-derived runtime helpers for the E2E harness.

Resolves project-name-aware values (host ports, volume names) and
materializes named-volume content at fixture time so two compose stacks
brought up under different project names from different cwds (main tree
+ worktree) coexist on a single Docker daemon without compile-time
literal collisions.

Uses the docker-py SDK (``docker``) against the daemon socket rather
than shelling out to the ``docker`` / ``docker compose`` CLI. The SDK
is a hard test-side dependency (tests/e2e/pyproject.toml) and gives
typed exceptions, no argv assembly, and no subprocess overhead.
Compose-CLI semantics we cannot reach via the SDK (project name +
service ports) are reconstructed from container labels: every compose-
managed container carries ``com.docker.compose.project``,
``com.docker.compose.service``, and ``com.docker.compose.config-files``
labels, which together pin the project context exactly.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

import docker

if TYPE_CHECKING:
    from docker import DockerClient


# Compose's own project-name normalization (cli/utils.go::NormalizeProjectName):
# lowercase the cwd basename, then drop characters that aren't [a-z0-9_-].
_PROJECT_NAME_FORBIDDEN = re.compile(r"[^a-z0-9_-]")

_LABEL_PROJECT = "com.docker.compose.project"
_LABEL_SERVICE = "com.docker.compose.service"
_LABEL_CONFIG_FILES = "com.docker.compose.config-files"


def _client() -> DockerClient:
    """Return a docker-py client bound to the daemon socket."""
    return docker.from_env()


def _resolve_project_name(compose_file: Path) -> str:
    """Return the compose project name for ``compose_file``.

    Walks all containers on the daemon, finds one whose
    ``com.docker.compose.config-files`` label lists ``compose_file``,
    and returns its ``com.docker.compose.project`` label. Catches
    ``-p <name>`` and ``COMPOSE_PROJECT_NAME`` overrides because the
    label captures whatever project name the stack was actually brought
    up under.

    Falls back to compose's cwd-basename normalization rule when no
    container matches (stack not running yet).
    """
    target = str(compose_file)
    for container in _client().containers.list(all=True):
        labels = container.labels or {}
        config_files = labels.get(_LABEL_CONFIG_FILES, "") or ""
        if target in config_files.split(","):
            project = labels.get(_LABEL_PROJECT, "")
            if project:
                return project
    return _PROJECT_NAME_FORBIDDEN.sub("", compose_file.parent.name.lower())


def resolve_host_port(compose_file: Path, service: str, container_port: int) -> int:
    """Return the host port Docker assigned to ``service:container_port``.

    Looks up the running container by its compose labels (project +
    service), then reads the host binding for ``container_port/tcp``
    from ``container.ports``. Equivalent to ``docker compose port
    <svc> <container_port>`` but goes straight to the daemon API.
    """
    project = _resolve_project_name(compose_file)
    containers = _client().containers.list(
        filters={
            "label": [f"{_LABEL_PROJECT}={project}", f"{_LABEL_SERVICE}={service}"],
        },
    )
    if not containers:
        msg = (
            f"compose port lookup failed: service={service!r} not running "
            f"in project={project!r} (compose_file={compose_file})"
        )
        raise RuntimeError(msg)
    bindings = (containers[0].ports or {}).get(f"{container_port}/tcp", [])
    if not bindings:
        msg = (
            f"compose port lookup failed: service={service!r} "
            f"port={container_port} not published in {compose_file}"
        )
        raise RuntimeError(msg)
    return int(bindings[0]["HostPort"])


def resolve_fixtures_volume(compose_file: Path) -> str:
    """Return the canonical name of the ``fixtures`` named volume.

    Compose v2 prefixes named volumes with the project name, e.g.
    ``agentic-content-access_fixtures`` (main tree) vs.
    ``agent-a07f5136_fixtures`` (worktree). Tests that mount the
    volume from the host must look up the actual name rather than rely
    on the main-tree literal.
    """
    return f"{_resolve_project_name(compose_file)}_fixtures"
