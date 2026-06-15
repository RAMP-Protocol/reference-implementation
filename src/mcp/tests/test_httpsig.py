"""Round-trip test: Python signer produces a signature that verifies in Go.

This module only checks canonicalisation invariants; the Go-side integration
test (see tests/e2e) covers the cross-language round-trip.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_mcp_shim.httpsig import AgentKey, Signer, SigningTransport, pop_signature_base

_POP_BASE_VECTORS = (
    Path(__file__).resolve().parents[3] / "testdata" / "pop-signature-base-vectors.json"
)


def _make_agent_key() -> tuple[AgentKey, Ed25519PrivateKey]:
    """Return a fresh AgentKey plus the underlying private-key object for verify."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    seed_b64 = base64.urlsafe_b64encode(seed).rstrip(b"=").decode()
    key = AgentKey(kid="test.v1", private_seed_b64=seed_b64)
    return key, priv


def test_sign_emits_required_headers() -> None:
    """Signer must emit every RFC 9421 header the verifier requires."""
    key, _ = _make_agent_key()
    signer = Signer(key)

    headers = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/ramp.v1.ExchangeService/DiscoverResources"),
        body=b'{"q":"x"}',
        authorization="Bearer test-jwt",
    )
    assert "Signature-Input" in headers
    assert "Signature" in headers
    assert "Content-Digest" in headers
    assert headers["Authorization"] == "Bearer test-jwt"
    # Canonical Content-Digest is sha-256=:<base64>:.
    digest_b64 = base64.b64encode(hashlib.sha256(b'{"q":"x"}').digest()).decode()
    assert headers["Content-Digest"] == f"sha-256=:{digest_b64}:"


def test_sign_binds_all_covered_components() -> None:
    """Signature-Input must list the four required components in order."""
    key, _ = _make_agent_key()
    signer = Signer(key)
    headers = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/rpc"),
        body=b"",
        authorization="",
    )
    expected = '("@method" "@target-uri" "content-digest" "authorization")'
    assert expected in headers["Signature-Input"]


@pytest.mark.asyncio
async def test_signing_transport_injects_headers_on_outbound() -> None:
    """The async transport must sign every request it forwards."""
    key, _ = _make_agent_key()
    captured: dict[str, str] = {}

    class SpyTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            for k, v in request.headers.items():
                captured[k.lower()] = v
            return httpx.Response(200, content=b"ok")

    client = httpx.AsyncClient(transport=SigningTransport(SpyTransport(), Signer(key)))
    resp = await client.post(
        "https://broker.example/rpc",
        content=b'{"q":"x"}',
        headers={"Authorization": "Bearer abc"},
    )
    assert resp.status_code == 200
    assert "signature" in captured
    assert "signature-input" in captured
    assert captured["authorization"] == "Bearer abc"
    await client.aclose()


def test_pop_signature_base_matches_shared_vectors() -> None:
    """The PoP signature base reproduces the shared cross-language fixture.

    Pins ramp_mcp_shim.httpsig.pop_signature_base byte-for-byte against the same
    testdata/pop-signature-base-vectors.json the edge verifier checks, so the two
    @target-uri base builders cannot drift apart (ADR-013 D2/D4).
    """
    vectors = json.loads(_POP_BASE_VECTORS.read_text())["vectors"]
    assert vectors
    for vec in vectors:
        assert pop_signature_base(vec["url"], vec["params"]) == vec["expected_base"]


def test_agent_key_from_file(tmp_path: Path) -> None:
    """AgentKey.from_file reads the JSON shape written by the bootstrap script."""
    priv = Ed25519PrivateKey.generate()
    seed_b64 = base64.urlsafe_b64encode(priv.private_bytes_raw()).rstrip(b"=").decode()
    path = tmp_path / "agent-key.json"
    path.write_text(json.dumps({"kid": "f.v1", "private_key": seed_b64, "public_key": "x"}))
    got = AgentKey.from_file(path)
    assert got.kid == "f.v1"
    assert got.private_seed_b64 == seed_b64
