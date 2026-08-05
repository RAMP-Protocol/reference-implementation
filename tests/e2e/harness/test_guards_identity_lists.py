"""Meta-guard — the three e2e identity lists must agree.

An e2e identity exists in three places no tool connects: the ``IDENTITIES``
list in ``scripts/gen-e2e-keys.sh`` (mints the private fixture), a per-kid
jwks service in ``docker-compose.e2e.yml`` (mounts the fixture, aliases the
kid), and that service's entry in a ``depends_on`` block so the stack waits
for it. One direction of a mismatch fails quietly: a fixture minted with no
jwks host resolves nowhere, which is exactly the shape of the deliberate
ghost-agent negative control — so an accidental omission reads as the
intended case and no test goes red.

This suite is the tool that connects the lists. It parses ``IDENTITIES`` out
of the real script (failing loudly if the extraction breaks) and the real
compose file with a YAML parser, then asserts:

* every minted identity is served by a service that mounts ITS fixture and
  aliases ITS kid — except the two documented exceptions (the ghost agent,
  served nowhere by design; the broker relay key, published by the Broker's
  own directory);
* the ghost agent stays hostless — no alias, no mount, anywhere;
* every jwks service is named in some service's ``depends_on``, so the stack
  actually waits for the directory hosts it relies on.

Pure file reading: no stack, no Docker, no database.
"""

from __future__ import annotations

import re

import yaml

from .conftest import REPO_ROOT
from .guard_harness import guard_marks

_KEYGEN = REPO_ROOT / "scripts" / "gen-e2e-keys.sh"
_COMPOSE = REPO_ROOT / "docker-compose.e2e.yml"

pytestmark = guard_marks(skip_when=not (_KEYGEN.is_file() and _COMPOSE.is_file()))

# Served nowhere by design — the negative control every resolution route must
# come up empty for.
_GHOST_KID = "ghost-agent-e2e"
# Published by the Broker's OWN WBA directory (the broker service mounts the
# fixture); it has no standalone jwks host on purpose.
_BROKER_RELAY_KID = "broker.broker-local.v1"


def _identities() -> list[tuple[str, str]]:
    """(kid, fixture filename) pairs lifted from the real IDENTITIES list.

    Extraction failing is itself a finding: the list moved or changed shape,
    and this guard is no longer reading the code that mints the fixtures.
    """
    text = _KEYGEN.read_text()
    block = re.search(r"^IDENTITIES = \[\n(.*?)^\]\n", text, re.DOTALL | re.MULTILINE)
    assert block, (
        "could not find the IDENTITIES list in scripts/gen-e2e-keys.sh — "
        "the list moved; fix this guard's extraction so it keeps reading the "
        "real one"
    )
    pairs = re.findall(r'\("([^"]+)", "([^"]+)"\)', block.group(1))
    assert pairs, "IDENTITIES block matched but no (kid, filename) tuples parsed"
    return pairs


def _compose_services() -> dict:
    return yaml.safe_load(_COMPOSE.read_text())["services"]


def _service_aliases(svc: dict) -> set[str]:
    networks = svc.get("networks") or {}
    if not isinstance(networks, dict):
        return set()
    out: set[str] = set()
    for net in networks.values():
        if isinstance(net, dict):
            out.update(net.get("aliases") or [])
    return out


def _mounted_fixtures(svc: dict) -> set[str]:
    """Basenames of host paths this service bind-mounts."""
    out: set[str] = set()
    for vol in svc.get("volumes") or []:
        if isinstance(vol, str):
            host = vol.split(":", 1)[0]
            out.add(host.rsplit("/", 1)[-1])
    return out


def test_every_minted_identity_is_served_and_depended_on() -> None:
    services = _compose_services()
    for kid, filename in _identities():
        if kid in (_GHOST_KID, _BROKER_RELAY_KID):
            continue
        serving = [
            name
            for name, svc in services.items()
            if kid in _service_aliases(svc) and filename in _mounted_fixtures(svc)
        ]
        assert serving, (
            f"identity {kid!r} is minted by gen-e2e-keys.sh but no compose "
            f"service both aliases it and mounts {filename!r} — its key would "
            "resolve nowhere, which is indistinguishable from the ghost-agent "
            "negative control"
        )


def test_broker_relay_fixture_is_mounted_into_the_broker() -> None:
    services = _compose_services()
    relay_file = dict(_identities())[_BROKER_RELAY_KID]
    broker = services.get("broker")
    assert broker is not None, "no broker service in docker-compose.e2e.yml"
    assert relay_file in _mounted_fixtures(broker), (
        f"the broker service no longer mounts {relay_file!r} — the relay key "
        "would be published nowhere (the Broker's own directory is its only "
        "publication path)"
    )


def test_ghost_agent_stays_hostless() -> None:
    services = _compose_services()
    ghost_file = dict(_identities())[_GHOST_KID]
    offenders = [
        name
        for name, svc in services.items()
        if _GHOST_KID in _service_aliases(svc) or ghost_file in _mounted_fixtures(svc)
    ]
    assert not offenders, (
        f"services {offenders} serve the ghost agent's identity — the negative "
        "control depends on that key being served NOWHERE"
    )


def test_every_jwks_service_is_depended_on() -> None:
    services = _compose_services()
    jwks = {name for name in services if name.endswith("-jwks") or name == "publisher-jwks"}
    assert jwks, "no jwks services found — the compose file changed shape"
    depended: set[str] = set()
    for svc in services.values():
        deps = svc.get("depends_on") or {}
        depended.update(deps.keys() if isinstance(deps, dict) else deps)
    orphans = sorted(jwks - depended)
    assert not orphans, (
        f"jwks services {orphans} appear in nobody's depends_on — the stack "
        "does not wait for them, so their identities resolve only by luck of "
        "startup order"
    )
