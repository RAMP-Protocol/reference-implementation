"""RFC 7638 thumbprint parity + bound-fetch proof-of-possession signing.

The thumbprint test pins the Python implementation to the SAME shared vectors
the Go and TS implementations use (testdata/thumbprint-vectors.json, ADR-013
D4), so a byte-level divergence between any of the three rejects every bound
fetch and fails here.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_mcp_shim._b64 import b64url_decode, b64url_nopad
from ramp_mcp_shim.httpsig import AGENT_KEY_HEADER, AgentKey, Signer
from ramp_mcp_shim.thumbprint import ed25519_thumbprint

_VECTORS_PATH = Path(__file__).resolve().parents[3] / "testdata" / "thumbprint-vectors.json"


def test_thumbprint_matches_shared_vectors() -> None:
    """Every shared vector's thumbprint reproduces under the Python impl."""
    vectors = json.loads(_VECTORS_PATH.read_text())["vectors"]
    assert vectors
    for vec in vectors:
        pub = b64url_decode(vec["public_key_b64url"])
        assert ed25519_thumbprint(pub) == vec["thumbprint"]


def test_fixture_thumbprints_match_independent_construction() -> None:
    """Independent oracle for the shared fixture.

    Build the canonical JWK with ``json.dumps(sort_keys=True)`` — entirely
    different code from the hand-built string the three production impls share —
    and recompute the RFC 7638 thumbprint. A member-order, whitespace, or
    encoding regression that slipped into all three impls (and a regenerated
    fixture) would still diverge from this independent computation, converting
    the parity suite from "the impls agree with each other" to "the impls agree
    with an independent reading of the standard".
    """
    vectors = json.loads(_VECTORS_PATH.read_text())["vectors"]
    assert vectors
    for vec in vectors:
        pub = b64url_decode(vec["public_key_b64url"])
        x = b64url_nopad(pub)
        canonical = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": x},
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(canonical.encode()).digest()
        assert b64url_nopad(digest) == vec["thumbprint"]


def _make_agent_key() -> tuple[AgentKey, Ed25519PrivateKey]:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    return AgentKey(kid="agent.v1", private_seed_b64=b64url_nopad(seed)), priv


def test_sign_get_keyid_is_thumbprint() -> None:
    """The PoP keyid and presented key are the agent's thumbprint / raw key."""
    key, _ = _make_agent_key()
    headers = Signer(key).sign_get("https://pub.example/r?agent_id=x&sig=y")

    thumb = key.thumbprint()
    assert AGENT_KEY_HEADER in headers
    assert headers["Signature-Input"].startswith('sig1=("@method" "@target-uri")')
    assert f'keyid="{thumb}"' in headers["Signature-Input"]
    # Presented raw key thumbprints back to the same value (3-way self-consistency).
    presented = b64url_decode(headers[AGENT_KEY_HEADER])
    assert ed25519_thumbprint(presented) == thumb


def test_sign_get_signature_verifies_over_canonical_base() -> None:
    """The signature verifies against the edge's reconstructed base."""
    key, priv = _make_agent_key()
    url = "https://pub.example/r?exp=4102444800&sig=z&agent_id=" + key.thumbprint()
    headers = Signer(key).sign_get(url)

    raw_params = headers["Signature-Input"].split("=", 1)[1]
    base = "\n".join(
        ['"@method": GET', f'"@target-uri": {url}', f'"@signature-params": {raw_params}']
    )
    sig_b64 = headers["Signature"].split(":", 1)[1].rstrip(":")
    priv.public_key().verify(base64.b64decode(sig_b64), base.encode())
