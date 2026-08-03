"""RFC 9421 signing-base construction and RFC 7638 thumbprints for the harness.

These are the wire primitives the harness has to reproduce byte-for-byte, because
the party checking them is a different implementation in a different language: the
Go verifier (``internal/httpsig/verifier.go``) rebuilds the RAMP signing base, and
the TypeScript edge (``src/edge/src/pop.ts``) rebuilds the bound-retrieval one. A
byte that differs here does not fail loudly — it fails as an invalid signature,
which reads like a broken service rather than a broken test.

Both forms are pinned to shared vectors under ``testdata/`` — the thumbprint by
``thumbprint-vectors.json`` and the bound-retrieval base by
``pop-signature-base-vectors.json`` — by ``test_rampsig.py``, so the Go,
TypeScript, and Python renderings cannot drift apart silently.
"""

from __future__ import annotations

import base64
import hashlib

from ramp_sdk.pop import signature_base as _sdk_pop_signature_base
from ramp_sdk.thumbprint import thumbprint as _sdk_thumbprint

# The RAMP covered-component set (ADR-001 §2.1) for an originating sig1. It MUST
# match the verifiers' required set (verifier.go requiredCoveredComponents).
# After the WBA split it includes signature-agent — the signer's
# directory origin — because the verifier resolves the RFC 7638 thumbprint keyid
# against that directory. A relaying Broker appends a chaining sig2 covering this
# set plus "signature";key="sig1"; an agent only ever emits sig1.
COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
    "signature-agent",
)

# Header carrying the signer's directory origin (Web Bot Auth). Covered by every
# RAMP signature after the WBA split; the verifier keys the authenticated
# principal on it. MUST match the Go constant httpsig.SignatureAgentHeader.
SIGNATURE_AGENT_HEADER = "Signature-Agent"

_ED25519_PUBLIC_KEY_BYTES = 32


def ed25519_thumbprint(public_key: bytes) -> str:
    """Return the base64url-no-pad RFC 7638 thumbprint of a raw Ed25519 key.

    Delegates to ``ramp_sdk.thumbprint`` rather than re-deriving it. That is what
    makes ``test_rampsig.py`` a real gate: the vectors under ``testdata/`` are
    generated from the Go oracle, so pinning them against the SDK is what catches
    drift at an SDK re-pin. A local copy would pin only itself — the copy and the
    vectors could agree while the code every signer actually calls had moved.
    """
    if len(public_key) != _ED25519_PUBLIC_KEY_BYTES:
        msg = f"thumbprint: public key must be {_ED25519_PUBLIC_KEY_BYTES} bytes"
        raise ValueError(msg)
    return _sdk_thumbprint(public_key)


def content_digest(body: bytes) -> str:
    """Return the RFC 9421 ``Content-Digest`` header value for ``body``."""
    sha = hashlib.sha256(body).digest()
    return "sha-256=:" + base64.b64encode(sha).decode() + ":"


def build_sig_params(*, keyid: str, created: int, expires: int) -> str:
    """Return the ``@signature-params`` value for the RAMP covered set."""
    covered_list = " ".join(f'"{c}"' for c in COVERED_COMPONENTS)
    return f'({covered_list});keyid="{keyid}";alg="ed25519";created={created};expires={expires}'


def build_signing_base(
    *,
    method: str,
    target_uri: str,
    digest_header: str,
    authorization: str,
    signature_agent: str,
    sig_params: str,
) -> str:
    """Return the RFC 9421 signing base over the RAMP covered set.

    Byte-identical to the Go verifier's reconstruction: every covered component in
    ``COVERED_COMPONENTS`` order, terminated by ``@signature-params``.
    """
    return "\n".join(
        [
            f'"@method": {method.upper()}',
            f'"@target-uri": {target_uri}',
            f'"content-digest": {digest_header}',
            f'"authorization": {authorization}',
            f'"signature-agent": {signature_agent}',
            f'"@signature-params": {sig_params}',
        ]
    )


def build_rfc9421_headers(
    *,
    digest_header: str,
    authorization: str,
    signature_agent: str,
    sig_params: str,
    sig_b64: str,
) -> dict[str, str]:
    """Assemble the RFC 9421 header set a signer stamps onto an outbound request."""
    return {
        "Content-Digest": digest_header,
        "Authorization": authorization,
        SIGNATURE_AGENT_HEADER: signature_agent,
        "Signature-Input": f"sig1={sig_params}",
        "Signature": f"sig1=:{sig_b64}:",
    }


def title_case_signed_headers(
    *,
    content_digest: str,
    authorization: str,
    signature_agent: str,
    signature_input: str,
    signature: str,
) -> dict[str, str]:
    """Lift an SDK sign result into the canonical Title-Case header set.

    The sibling of :func:`build_rfc9421_headers` for callers that already hold
    fully-assembled ``Signature-Input`` / ``Signature`` values (the SDK signer
    returns them that way) rather than the raw params + signature bytes. Both
    live here so the key casing, key set, and order cannot drift between the two
    producers.
    """
    return {
        "Content-Digest": content_digest,
        "Authorization": authorization,
        SIGNATURE_AGENT_HEADER: signature_agent,
        "Signature-Input": signature_input,
        "Signature": signature,
    }


def pop_signature_base(url: str, sig_params: str) -> str:
    """RFC 9421 signature base for a bound-retrieval GET (ADR-013 D2).

    Delegates to ``ramp_sdk.pop.signature_base`` for the same reason as
    :func:`ed25519_thumbprint`: the shared vectors must pin the code the edge
    verifier is mirrored against, not a second copy of it. The method is fixed to
    GET on this path.
    """
    return _sdk_pop_signature_base("GET", url, sig_params)
