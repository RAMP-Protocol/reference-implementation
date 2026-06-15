"""Key-resolution behavior of the outbound-signing client factory (LT2).

The discovery-manifest path tolerates a missing/corrupt key (it degrades to a
keyless 404 — see ``test_wellknown.py``). The outbound-signing path must instead
fail closed when an operator explicitly points ``RAMP_AGENT_KEY_FILE`` at a file
that does not load, rather than silently returning an unsigned client.
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_mcp_shim.signing_client import (
    AgentKeyConfigError,
    load_agent_key,
    make_signing_async_client,
)

if TYPE_CHECKING:
    from pathlib import Path

_KID = "agent.v1"


def _valid_seed_b64() -> str:
    """Return a base64url(no-pad) raw 32-byte Ed25519 seed."""
    priv = Ed25519PrivateKey.generate()
    return base64.urlsafe_b64encode(priv.private_bytes_raw()).rstrip(b"=").decode()


def _write_key(path: Path, seed_b64: str) -> Path:
    path.write_text(json.dumps({"kid": _KID, "private_key": seed_b64, "public_key": "x"}))
    return path


def test_explicit_malformed_key_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present-but-unusable explicit RAMP_AGENT_KEY_FILE raises, not unsigned."""
    short_seed = base64.urlsafe_b64encode(b"too-short").rstrip(b"=").decode()
    key_file = _write_key(tmp_path / "bad.json", short_seed)
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(key_file))
    monkeypatch.chdir(tmp_path)  # no ./deploy/mcp/agent-key.json fallback here

    with pytest.raises(AgentKeyConfigError):
        load_agent_key(require_valid_explicit=True)
    with pytest.raises(AgentKeyConfigError):
        make_signing_async_client()


def test_explicit_valid_key_loads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A well-formed explicit key loads (the signing path gets a real identity)."""
    key_file = _write_key(tmp_path / "ok.json", _valid_seed_b64())
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(key_file))
    key = load_agent_key(require_valid_explicit=True)
    assert key is not None
    assert key.kid == _KID


def test_absent_explicit_key_degrades_to_unsigned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An explicit path that does not exist still degrades gracefully to None."""
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(tmp_path / "absent.json"))
    monkeypatch.chdir(tmp_path)
    assert load_agent_key(require_valid_explicit=True) is None


def test_tolerant_loader_never_raises_on_corrupt_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default (discovery) path stays tolerant: corrupt explicit key → None."""
    short_seed = base64.urlsafe_b64encode(b"too-short").rstrip(b"=").decode()
    monkeypatch.setenv("RAMP_AGENT_KEY_FILE", str(_write_key(tmp_path / "bad.json", short_seed)))
    monkeypatch.chdir(tmp_path)
    assert load_agent_key() is None
