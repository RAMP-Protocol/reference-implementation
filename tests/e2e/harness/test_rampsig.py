"""Cross-language byte-exactness gate for the harness RFC 7638/9421 primitives.

The harness reproduces two wire forms that a DIFFERENT implementation in a
different language checks: the RFC 7638 Ed25519 thumbprint (the ``agent_id`` /
``keyid`` the Go verifier and the TS edge resolve) and the RFC 9421 signature
base for a bound-retrieval GET (what the edge rebuilds in ``pop.ts``). A byte
that differs here does not fail loudly — it fails as an invalid signature, i.e.
a wall of unexplained rejections across the whole e2e suite.

These assertions were ported from the retired ``src/mcp`` shim's
``test_thumbprint.py`` / ``test_httpsig.py``; the Go (``internal/rampthumbprint``)
and TypeScript (``src/edge/tests``) suites still read the SAME vector files, so
pinning the Python rendering to them is what keeps all three renderings identical.
"""

from __future__ import annotations

import json

import pytest

from ramp_sdk.b64 import b64url_decode
from .conftest import REPO_ROOT
from .rampsig import ed25519_thumbprint, pop_signature_base

# Pure crypto-primitive tests — no compose stack, no DB. Declare `isolated` so the
# autouse per-test cleanup chain (which needs a live Postgres DSN) is a no-op here,
# matching harness/test_acceptance.py.
pytestmark = pytest.mark.stack_isolation("isolated")

# Shared cross-language oracles, resolved via the harness REPO_ROOT idiom so the
# paths hold both in the host checkout and in the runner container where testdata/
# is COPYed in — the same resolution test_acceptance.py uses.
_THUMBPRINT_VECTORS = REPO_ROOT / "testdata" / "thumbprint-vectors.json"
_POP_BASE_VECTORS = REPO_ROOT / "testdata" / "pop-signature-base-vectors.json"


def test_thumbprints_match_shared_vectors() -> None:
    """ed25519_thumbprint reproduces the shared RFC 7638 vectors byte for byte.

    Each vector pairs a base64url-no-pad raw 32-byte public key with the
    base64url-no-pad thumbprint the Go and TS implementations produce for it.
    """
    vectors = json.loads(_THUMBPRINT_VECTORS.read_text())["vectors"]
    assert vectors
    for vec in vectors:
        public_key = b64url_decode(vec["public_key_b64url"])
        assert ed25519_thumbprint(public_key) == vec["thumbprint"], vec["public_key_b64url"]


def test_pop_signature_base_matches_shared_vectors() -> None:
    """pop_signature_base reproduces the shared bound-retrieval base byte for byte.

    A divergence in line order, quoting, or the params string rejects every bound
    fetch, so the base is pinned to exactly what the edge verifier reconstructs.
    """
    vectors = json.loads(_POP_BASE_VECTORS.read_text())["vectors"]
    assert vectors
    for vec in vectors:
        got = pop_signature_base(vec["url"], vec["params"])
        assert got == vec["expected_base"], vec["url"]
