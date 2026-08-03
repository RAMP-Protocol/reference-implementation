"""Cross-language byte-exactness gate for the harness offer-acceptance signer.

The e2e harness's JCS canonicalization of ``AgentAcceptancePayload``
(now ``ramp_sdk.core``, ``JCS(protojson(payload))`` via the vetted
``rfc8785`` library) MUST reproduce the bytes the REAL Go SDK produces
(``helpers.SignOfferAcceptance``), and the hex Ed25519 signature MUST
equal the Go signature for the same fixed seed. The shared oracle is
``testdata/acceptance-vectors.json``, generated from the Go SDK at the pinned
protocol revision. The vectors MUST be regenerated from the Go oracle at every
protocol re-pin: a stale vector file pins a stale byte layout and lets signer
drift ride silently (that is exactly how the JCS switch was missed).

A divergence here means the relay-driven happy path would present an acceptance
the Exchange rejects, which makes this the highest-risk surface in the signing
chain. It is unit-tested because it is a cryptographic primitive and a parser,
two of the categories the testing doctrine admits unit tests for.
"""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ramp_sdk.core import (
    ACCEPTANCE_SIGNATURE_ALGORITHM,
)
from ramp_sdk.core import (
    jcs_acceptance_payload as canonical_acceptance_payload,
)
from ramp_sdk.core import (
    sign_offer_acceptance_jcs,
)
from .conftest import REPO_ROOT

# Pure crypto-primitive test — no compose stack, no DB. Declare `isolated` so the
# autouse `_stack_isolation_dispatch` per-test cleanup chain (which needs a live
# Postgres DSN) is a no-op for this module.
pytestmark = pytest.mark.stack_isolation("isolated")

# The shared cross-language oracle. Resolved via the harness's REPO_ROOT idiom
# (conftest.REPO_ROOT == the compose-file's dir) so the path holds in BOTH the
# host checkout (repo-root/testdata) AND the runner container, where REPO_ROOT is
# the bind-mounted /runner and testdata/ is COPYed in (tests/e2e/Dockerfile).
# parents[3] would IndexError inside the container's /runner/harness layout.
_VECTORS_PATH = REPO_ROOT / "testdata" / "acceptance-vectors.json"


def _vectors() -> list[dict[str, str]]:
    doc = json.loads(_VECTORS_PATH.read_text())
    # The vector file self-describes its canonicalization; refuse to run the
    # JCS assertions against a stale (pre-JCS) vector file.
    assert doc.get("canonicalization") == "jcs"
    vectors: list[dict[str, str]] = doc["vectors"]
    assert vectors
    return vectors


def test_canonical_bytes_match_go_oracle() -> None:
    """The rendered payload reproduces the Go ``canonicalSignPayload`` bytes exactly.

    Pins the JCS(protojson) layout: lexicographically sorted keys, minimal
    separators, empty ``requester_domain`` omitted (the ``empty_domain`` vector
    drops the key entirely — proto-JSON default-skip).
    """
    for vec in _vectors():
        got = canonical_acceptance_payload(
            offer_sig=vec["offer_sig"],
            requester_id=vec["requester_id"],
            requester_domain=vec["requester_domain"],
            idempotency_key=vec["idempotency_key"],
        )
        assert got == vec["canonical_jcs"].encode("utf-8"), vec["name"]


def test_signature_matches_go_oracle_for_fixed_seed() -> None:
    """Signing the canonical bytes with the vector seed reproduces the Go signature.

    Ed25519 is deterministic, so a fixed seed yields one signature; the hex MUST
    equal the value the Go ``ed25519.Sign`` produced, proving the whole chain
    (canonicalization + sign + hex) is byte-identical across languages.
    """
    for vec in _vectors():
        seed = bytes.fromhex(vec["seed_hex"])
        signature_hex, algorithm = sign_offer_acceptance_jcs(
            seed=seed,
            offer_sig=vec["offer_sig"],
            requester_id=vec["requester_id"],
            requester_domain=vec["requester_domain"],
            idempotency_key=vec["idempotency_key"],
        )
        assert signature_hex == vec["signature_hex"], vec["name"]
        assert algorithm == ACCEPTANCE_SIGNATURE_ALGORITHM


def test_signature_verifies_under_vector_pubkey() -> None:
    """The harness signature verifies under the vector's published public key.

    Independent of the byte-equality leg: even if both sides shared a
    canonicalization regression, a signature that verifies under the
    Go-published pubkey over the harness-built canonical bytes proves the agent
    and Exchange agree on the signed bytes.
    """
    for vec in _vectors():
        payload = canonical_acceptance_payload(
            offer_sig=vec["offer_sig"],
            requester_id=vec["requester_id"],
            requester_domain=vec["requester_domain"],
            idempotency_key=vec["idempotency_key"],
        )
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(vec["pubkey_b64"]))
        pub.verify(bytes.fromhex(vec["signature_hex"]), payload)


def test_reject_empty_offer_sig() -> None:
    """An empty offer signature is fail-closed (mirror Go ``acceptance.go``).

    An empty anchor would let the acceptance float free of any concrete offer,
    so signing over it must raise rather than produce a floating signature.
    """
    with pytest.raises(ValueError, match="offer"):
        canonical_acceptance_payload(
            offer_sig="",
            requester_id="agent-1",
            requester_domain="agent.example.com",
            idempotency_key="idem-1",
        )
    priv = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="offer"):
        sign_offer_acceptance_jcs(
            seed=priv.private_bytes_raw(),
            offer_sig="",
            requester_id="agent-1",
            requester_domain="agent.example.com",
            idempotency_key="idem-1",
        )
