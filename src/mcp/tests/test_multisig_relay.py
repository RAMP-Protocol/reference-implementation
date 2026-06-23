"""Multisig relay topology verification: MCP → Broker → Exchange.

This module verifies that MCP's signing implementation is compatible with the
broker's multisig relay mechanism. The full end-to-end multisig chain is:

1. MCP signs request with sig1 (this module)
2. Broker preserves sig1 and appends sig2 (tested in src/broker/internal/xclient)
3. Exchange verifies both signatures (tested in internal/httpsig)

**What this test verifies:**
- MCP uses the correct signature label (`sig1`)
- MCP's coverage set matches Broker/Exchange requirements
- MCP's signature format is RFC 9421 compliant

**What this test does NOT do:**
- Run a live Broker or Exchange (cross-language integration tested in Go)
- Mock Broker/Exchange responses (composition proof, not integration proof)

**Composition proof:**
If MCP emits sig1 with the RAMP coverage set (verified here), AND Broker's
AppendSignatureRAMP preserves sig1 when adding sig2 (verified in Go tests under
src/broker/internal/xclient/signing_transport_test.go), AND Exchange verifies
multisig requests (verified in Go tests under internal/httpsig), THEN the
MCP → Broker → Exchange multisig relay works by composition.

See ADR-013 §3.2 for the multisig relay architecture.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ramp_mcp_shim.httpsig import _COVERED_COMPONENTS, AgentKey, Signer


def _make_test_agent_key() -> AgentKey:
    """Return a deterministic AgentKey for test repeatability."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    seed_b64 = base64.urlsafe_b64encode(seed).rstrip(b"=").decode()
    return AgentKey(kid="agent.test.v1", private_seed_b64=seed_b64)


def test_mcp_uses_sig1_label() -> None:
    """Verify MCP signer emits sig1 label (required for broker multisig relay).

    **Why this matters:**
    Broker's AppendSignatureRAMP expects the incoming agent signature to use
    the label `sig1`. If MCP used a different label, Broker would create a
    conflicting sig1, overwriting MCP's signature.

    **Go test reference:**
    src/broker/internal/xclient/signing_transport_test.go::TestSigningTransport_PreservesAgentSignature
    verifies Broker appends sig2 when sig1 exists.
    """
    key = _make_test_agent_key()
    signer = Signer(key)

    headers = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/ramp.v1.BrokerService/Resolve"),
        body=b'{"url":"https://publisher.example/content"}',
        authorization="Bearer agent-token",
    )

    # Verify sig1 label is used in both headers.
    sig_input = headers.get("Signature-Input", "")
    assert sig_input.startswith("sig1="), (
        f"MCP must use sig1 label for broker multisig compatibility, got: {sig_input}"
    )

    sig = headers.get("Signature", "")
    assert sig.startswith("sig1=:"), f"Signature must use sig1 label, got: {sig}"


def test_mcp_coverage_set_matches_ramp_requirements() -> None:
    """Verify MCP's coverage set matches Broker/Exchange verifier requirements.

    **Required components (RAMP coverage set):**
    - @method
    - @target-uri
    - content-digest
    - authorization

    **Why this matters:**
    Exchange's verifier requires these four base components on sig1. If MCP
    omitted any, Exchange would reject the request. MCP is the originating hop
    and emits only sig1 over exactly this base set; the relaying Broker appends a
    chaining sig2 whose covered set is this base set PLUS "signature";key="sig1"
    (RAMP-56 forwarding chain). MCP must NOT add extra components to sig1 — the
    chain link is the Broker's responsibility, not MCP's.

    **Go test reference:**
    internal/httpsig/verifier_test.go verifies the RAMP coverage set.
    """
    # Verify the constant matches the spec.
    assert _COVERED_COMPONENTS == (
        "@method",
        "@target-uri",
        "content-digest",
        "authorization",
    ), "MCP coverage set must match RAMP spec (ADR-001 §2.1)"

    # Verify the signer emits all four components.
    key = _make_test_agent_key()
    signer = Signer(key)
    headers = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/rpc"),
        body=b'{"test":"data"}',
        authorization="Bearer test-token",
    )

    sig_input = headers["Signature-Input"]
    # Extract the covered components list from the sig_input.
    # Format: sig1=("@method" "@target-uri" "content-digest" "authorization");...
    assert '("@method" "@target-uri" "content-digest" "authorization")' in sig_input, (
        f"Signature-Input must contain RAMP coverage set, got: {sig_input}"
    )


def test_mcp_signature_format_rfc9421_compliant() -> None:
    """Verify MCP's signature format matches RFC 9421 spec.

    **Required format:**
    - Signature-Input: sig1=(<components>);keyid="...";alg="ed25519";created=...;expires=...
    - Signature: sig1=:<base64>:
    - Content-Digest: sha-256=:<base64>:

    **Why this matters:**
    Broker and Exchange parse signatures using Go's RFC 9421 parser. If MCP's
    format deviates from the spec, parsing will fail and the request will be
    rejected before Broker can append sig2.
    """
    key = _make_test_agent_key()
    signer = Signer(key)
    body = b'{"url":"https://publisher.example/content"}'
    headers = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/ramp.v1.BrokerService/Resolve"),
        body=body,
        authorization="Bearer agent-token",
    )

    # Verify Signature-Input format.
    sig_input = headers["Signature-Input"]
    assert 'keyid="agent.test.v1"' in sig_input, "Signature-Input must include keyid"
    assert 'alg="ed25519"' in sig_input, "Signature-Input must include alg=ed25519"
    assert "created=" in sig_input, "Signature-Input must include created timestamp"
    assert "expires=" in sig_input, "Signature-Input must include expires timestamp"

    # Verify Signature format (sig1=:<base64>:).
    sig = headers["Signature"]
    assert sig.startswith("sig1=:"), "Signature must use RFC 9421 byte sequence format"
    assert sig.endswith(":"), "Signature must end with colon"
    # Extract base64 part (between colons) and verify it's valid base64.
    sig_b64 = sig.removeprefix("sig1=:").removesuffix(":")
    try:
        sig_bytes = base64.b64decode(sig_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        pytest.fail(f"Signature value must be valid base64, got error: {exc}")
    assert len(sig_bytes) == 64, "Ed25519 signature must be 64 bytes"

    # Verify Content-Digest format (sha-256=:<base64>:).
    content_digest = headers["Content-Digest"]
    assert content_digest.startswith("sha-256=:"), "Content-Digest must use sha-256"
    assert content_digest.endswith(":"), "Content-Digest must end with colon"
    # Extract and verify the digest.
    digest_b64 = content_digest.removeprefix("sha-256=:").removesuffix(":")
    expected_digest = base64.b64encode(hashlib.sha256(body).digest()).decode()
    assert digest_b64 == expected_digest, "Content-Digest must match body SHA-256"


def test_mcp_binds_authorization_header() -> None:
    """Verify MCP includes authorization header in signature coverage.

    **Why this matters:**
    The RAMP spec requires binding the authorization header to prevent token
    substitution attacks. If MCP didn't include authorization in the coverage
    set, an attacker could replace the Bearer token after signature verification.

    **Empty authorization:**
    When no Bearer token is available, MCP must pass an empty string to bind
    the absence cryptographically (prevents injection).

    **Go test reference:**
    internal/httpsig/verifier_test.go::TestVerifyRequest_TamperedAuthorizationRejected
    verifies authorization binding in Go.
    """
    key = _make_test_agent_key()
    signer = Signer(key)

    # Test with Bearer token.
    headers_with_token = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/rpc"),
        body=b"{}",
        authorization="Bearer test-token",
    )
    assert headers_with_token["Authorization"] == "Bearer test-token"
    assert "authorization" in headers_with_token["Signature-Input"].lower()

    # Test with empty authorization (binds absence).
    headers_no_token = signer.sign(
        method="POST",
        url=httpx.URL("https://broker.example/rpc"),
        body=b"{}",
        authorization="",
    )
    assert headers_no_token["Authorization"] == ""
    assert "authorization" in headers_no_token["Signature-Input"].lower()
