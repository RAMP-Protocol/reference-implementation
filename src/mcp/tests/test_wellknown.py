"""Tests for the agent ``/.well-known/ramp.json`` producer.

Two surfaces are exercised:

* the manifest builder directly, with a :class:`DeterministicClock` so the
  key-validity window is asserted exactly (ADR-008 D1 — no wall clock); and
* the live ``GET /.well-known/ramp.json`` route through FastMCP's real HTTP
  app (the same app ``mcp.run(transport="http")`` serves), driven in-process
  via an ASGI transport. Only env + key file are arranged; the route, the
  manifest builder, and JSON serialisation all run for real.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from ramp_mcp_shim.clock import DeterministicClock
from ramp_mcp_shim.httpsig import AgentKey
from ramp_mcp_shim.server import WELL_KNOWN_PATH, mcp
from ramp_mcp_shim.wellknown import JsonWebKey, build_agent_manifest, load_agent_manifest

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

_DOMAIN = "agent.example"
_KID = "agent.v1"
_PUBKEY_BYTES = 32
_AWARE = datetime(2026, 1, 1, tzinfo=UTC)
_NAIVE = datetime(2026, 1, 1)  # intentionally tz-naive — drives the reject test


def _agent_key() -> tuple[AgentKey, bytes]:
    """Return a fresh AgentKey plus its raw 32-byte public key."""
    priv = Ed25519PrivateKey.generate()
    seed_b64 = base64.urlsafe_b64encode(priv.private_bytes_raw()).rstrip(b"=").decode()
    pub_raw = priv.public_key().public_bytes_raw()
    return AgentKey(kid=_KID, private_seed_b64=seed_b64), pub_raw


def _write_key_file(tmp_path: Path, key: AgentKey) -> Path:
    """Persist ``key`` in the JSON shape the loader reads."""
    path = tmp_path / "agent-key.json"
    path.write_text(
        json.dumps({"kid": key.kid, "private_key": key.private_seed_b64, "public_key": "x"}),
    )
    return path


def _write_corrupt_key_file(tmp_path: Path) -> Path:
    """Persist a key file whose seed decodes to the wrong length (not 32 bytes)."""
    path = tmp_path / "corrupt-key.json"
    short_seed = base64.urlsafe_b64encode(b"too-short").rstrip(b"=").decode()
    path.write_text(json.dumps({"kid": _KID, "private_key": short_seed, "public_key": "x"}))
    return path


def test_build_manifest_shape_and_key_window() -> None:
    """The builder emits the AGENT wire shape with a clock-derived key window."""
    key, pub_raw = _agent_key()
    start = datetime(2026, 6, 3, 12, 0, 0, tzinfo=UTC)
    clock = DeterministicClock(start)

    manifest = build_agent_manifest(_DOMAIN, key, clock=clock)

    assert manifest.ver == "1.0"
    assert manifest.role == "ROLE_AGENT"
    assert manifest.domain == _DOMAIN
    assert len(manifest.public_keys) == 1

    jwk = manifest.public_keys[0]
    assert jwk.kid == _KID
    assert (jwk.kty, jwk.crv, jwk.use, jwk.alg) == ("OKP", "Ed25519", "sig", "EdDSA")
    # x is base64url(no pad) of the raw 32-byte public key.
    decoded = base64.urlsafe_b64decode(jwk.x + "=" * (-len(jwk.x) % 4))
    assert len(decoded) == _PUBKEY_BYTES
    assert decoded == pub_raw
    # not_before/not_after are real datetimes on the model; window is
    # [now - 1h, now + ~10y).
    assert jwk.not_before == start - timedelta(hours=1)
    assert jwk.not_after == start + timedelta(days=3650)
    # The JSON wire form is RFC 3339 with a Z suffix.
    wire = manifest.model_dump(mode="json")["public_keys"][0]
    assert wire["not_before"] == "2026-06-03T11:00:00Z"
    assert wire["not_after"] == (start + timedelta(days=3650)).isoformat().replace("+00:00", "Z")


def test_load_manifest_returns_none_without_domain() -> None:
    """No RAMP_AGENT_ID → no publishable identity → None (route answers 404)."""
    assert load_agent_manifest(None) is None
    assert load_agent_manifest("") is None


def test_load_manifest_returns_none_without_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A domain but no agent key anywhere → None (keyless dev run)."""
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(tmp_path / "absent.json"))
    monkeypatch.chdir(tmp_path)  # no ./deploy/mcp/agent-key.json fallback here
    assert load_agent_manifest(_DOMAIN) is None


def test_load_manifest_returns_none_with_corrupt_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present but malformed key file is treated as absent → None, not a raise."""
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(_write_corrupt_key_file(tmp_path)))
    monkeypatch.chdir(tmp_path)
    assert load_agent_manifest(_DOMAIN) is None


@pytest.fixture
async def http_client() -> AsyncIterator[httpx.AsyncClient]:
    """Drive the real FastMCP HTTP app (custom routes included) in-process.

    The lifespan (which starts the MCP streamable-session manager) is not
    entered: the ``/.well-known/ramp.json`` route is a plain Starlette route
    that does not depend on the session manager, and entering that lifespan
    inside an async fixture trips an anyio cross-task cancel-scope error.
    """
    app = mcp.http_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://shim.test") as client:
        yield client


@pytest.mark.asyncio
async def test_route_serves_agent_manifest(
    http_client: httpx.AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GET /.well-known/ramp.json returns the AGENT manifest as JSON."""
    key, pub_raw = _agent_key()
    monkeypatch.setenv("RAMP_AGENT_ID", _DOMAIN)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(_write_key_file(tmp_path, key)))

    resp = await http_client.get(WELL_KNOWN_PATH)

    assert resp.status_code == 200
    body = resp.json()
    assert body["ver"] == "1.0"
    assert body["role"] == "ROLE_AGENT"
    assert body["domain"] == _DOMAIN
    assert body["public_keys"][0]["kid"] == _KID
    decoded = base64.urlsafe_b64decode(body["public_keys"][0]["x"] + "==")
    assert len(decoded) == _PUBKEY_BYTES
    assert decoded == pub_raw


@pytest.mark.asyncio
async def test_route_404_when_unconfigured(
    http_client: httpx.AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without RAMP_AGENT_ID the route answers a bare 404, not a 500/crash."""
    monkeypatch.delenv("RAMP_AGENT_ID", raising=False)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(tmp_path / "absent.json"))
    monkeypatch.chdir(tmp_path)

    resp = await http_client.get(WELL_KNOWN_PATH)

    assert resp.status_code == 404
    assert resp.content == b""  # body-less; the status is the contract


@pytest.mark.asyncio
async def test_route_404_when_key_corrupt(
    http_client: httpx.AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-corrupt agent key yields a graceful 404, never a 500/crash."""
    monkeypatch.setenv("RAMP_AGENT_ID", _DOMAIN)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(_write_corrupt_key_file(tmp_path)))
    monkeypatch.chdir(tmp_path)

    resp = await http_client.get(WELL_KNOWN_PATH)

    assert resp.status_code == 404


def _assert_minted_uuid(value: str) -> None:
    """A minted id is a canonical dashed UUIDv4 (``str(uuid.uuid4())``), not the
    32-char undashed hex form — matching the Go/TS producers. ``str(uuid.UUID(v))``
    re-emits the canonical dashed form, so equality holds only for that form.
    """
    assert str(uuid.UUID(value)) == value


@pytest.mark.asyncio
async def test_route_request_id_echo_and_mint_on_200(
    http_client: httpx.AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """200 branch carries the correlation id: an inbound X-Request-ID is echoed
    verbatim; an absent one is minted as a dashed UUIDv4.
    """
    key, _ = _agent_key()
    monkeypatch.setenv("RAMP_AGENT_ID", _DOMAIN)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(_write_key_file(tmp_path, key)))

    echoed = await http_client.get(WELL_KNOWN_PATH, headers={"X-Request-ID": "corr-200"})
    assert echoed.status_code == 200
    assert echoed.headers["X-Request-ID"] == "corr-200"

    minted = await http_client.get(WELL_KNOWN_PATH)
    assert minted.status_code == 200
    _assert_minted_uuid(minted.headers["X-Request-ID"])


@pytest.mark.asyncio
async def test_route_request_id_echo_and_mint_on_404(
    http_client: httpx.AsyncClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """404 branch carries the same correlation contract as the 200 branch."""
    monkeypatch.delenv("RAMP_AGENT_ID", raising=False)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(tmp_path / "absent.json"))
    monkeypatch.chdir(tmp_path)

    echoed = await http_client.get(WELL_KNOWN_PATH, headers={"X-Request-ID": "corr-404"})
    assert echoed.status_code == 404
    assert echoed.headers["X-Request-ID"] == "corr-404"

    minted = await http_client.get(WELL_KNOWN_PATH)
    assert minted.status_code == 404
    _assert_minted_uuid(minted.headers["X-Request-ID"])


def test_jwk_rejects_naive_not_before() -> None:
    """A tz-naive not_before is rejected: the RFC 3339 serializer (astimezone)
    would misread a naive instant as local time and corrupt the wire value.
    """
    with pytest.raises(ValidationError):
        JsonWebKey(kid=_KID, x="AA", not_before=_NAIVE, not_after=_AWARE)


def test_jwk_rejects_naive_not_after() -> None:
    """The same guard applies to not_after, independently of not_before."""
    with pytest.raises(ValidationError):
        JsonWebKey(kid=_KID, x="AA", not_before=_AWARE, not_after=_NAIVE)
