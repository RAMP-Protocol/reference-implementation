"""RFC 9421 Ed25519 signer for outbound MCP-shim requests.

Layer 1 of the three-layer auth model (see docs/architecture/adr-001-three-layer-auth.md).
Wraps an existing httpx transport so every Broker call carries

    Signature-Input: sig1=("@method" "@target-uri" "content-digest" "authorization");\\
        keyid="...";alg="ed25519";created=...;expires=...
    Signature: sig1=:<base64>:
    Content-Digest: sha-256=:<base64>:

The coverage set matches the Broker / Exchange verifier's required components.

**Multisig forwarding-chain compatibility (ADR-013 D5, RAMP-56):**
This signer always emits the originating signature `sig1` over the RAMP base
coverage set. When the Broker relays the request it preserves sig1 and appends a
chaining sig2 whose covered set is the base set PLUS ``"signature";key="sig1"``,
so sig2 cryptographically commits to sig1 (RFC 9421 §2.4). The Exchange verifies
the whole chain and bounds its depth. MCP is always the originating hop and never
appends to or verifies a chain, so it needs no parameterized-component logic —
keep it strictly sig1-only. See tests/test_multisig_relay.py for the composition
proof and cross-references to Go integration tests.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import BaseModel, ConfigDict, Field

from ._b64 import b64url_decode, b64url_nopad
from .clock import Clock, SystemClock
from .thumbprint import ed25519_thumbprint

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_SIGNATURE_TTL_SECONDS = 30

# RAMP coverage set (ADR-001 §2.1) for the originating sig1. MUST match the
# Broker/Exchange verifiers' required base components. The relaying Broker appends
# a chaining sig2 whose covered set is this base set PLUS "signature";key="sig1"
# (RAMP-56 forwarding chain); MCP only ever emits sig1 over this base set.
_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
)

# Covered set for the proof-of-possession GET signature (ADR-013 D2): no body
# (drop content-digest), the signed URL is the credential (drop authorization).
_GET_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
)

# Header carrying the agent's raw Ed25519 public key on a bound retrieval GET
# (ADR-013 D1). MUST match the edge verifier (src/edge/src/pop.ts).
AGENT_KEY_HEADER = "X-RAMP-Agent-Key"


class AgentKey(BaseModel):
    """Ed25519 keypair for outbound RFC 9421 signing.

    The key file is written by ``scripts/gen-demo-agent-key.sh`` in the
    JSON shape ``{"kid": "...", "private_key": "<b64url seed>", "public_key": "<b64url>"}``.
    """

    model_config = ConfigDict(frozen=True)

    kid: str = Field(description="Key identifier (matches JWKS `kid`)")
    private_seed_b64: str = Field(description="Base64url Ed25519 seed (32 bytes raw)")

    @classmethod
    def from_file(cls, path: str | Path) -> Self:
        """Load the agent key from a JSON file written by the bootstrap script."""
        doc = json.loads(Path(path).read_text())
        return cls(kid=doc["kid"], private_seed_b64=doc["private_key"])

    def private_key(self) -> Ed25519PrivateKey:
        """Decode the seed and return the cryptography private-key object."""
        seed = b64url_decode(self.private_seed_b64)
        return Ed25519PrivateKey.from_private_bytes(seed)

    def public_key_bytes(self) -> bytes:
        """Return the raw 32-byte Ed25519 public key derived from the seed."""
        return self.private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def public_key_b64url(self) -> str:
        """Return the raw public key as base64url-no-pad (X-RAMP-Agent-Key form)."""
        return b64url_nopad(self.public_key_bytes())

    def thumbprint(self) -> str:
        """Return the RFC 7638 thumbprint of the key (the WBA keyid / agent_id)."""
        return ed25519_thumbprint(self.public_key_bytes())


class Signer:
    """Builds RFC 9421 Signature + Signature-Input headers for an outbound request."""

    def __init__(
        self,
        key: AgentKey,
        *,
        ttl_seconds: int = _SIGNATURE_TTL_SECONDS,
        clock: Clock | None = None,
    ) -> None:
        """Store the key, signature lifetime (seconds), and time source."""
        self._key = key
        self._priv = key.private_key()
        self._ttl = ttl_seconds
        self._clock: Clock = clock if clock is not None else SystemClock()

    def sign(self, method: str, url: httpx.URL, body: bytes, authorization: str) -> dict[str, str]:
        """Return headers (Content-Digest, Signature-Input, Signature, Authorization).

        The caller must apply these headers before the request leaves the
        transport. Authorization is always bound — when the caller has no
        Bearer JWT, pass an empty string so the absence is cryptographically
        pinned.
        """
        digest_header = _content_digest(body)
        created = int((self._clock.now() - _EPOCH).total_seconds())
        expires = created + self._ttl
        covered_list = " ".join(f'"{c}"' for c in _COVERED_COMPONENTS)
        sig_params = (
            f'({covered_list});keyid="{self._key.kid}";'
            f'alg="ed25519";created={created};expires={expires}'
        )
        base_lines = [
            f'"@method": {method.upper()}',
            f'"@target-uri": {url!s}',
            f'"content-digest": {digest_header}',
            f'"authorization": {authorization}',
            f'"@signature-params": {sig_params}',
        ]
        base = "\n".join(base_lines)
        sig = self._priv.sign(base.encode())
        sig_b64 = base64.b64encode(sig).decode()
        return {
            "Content-Digest": digest_header,
            "Authorization": authorization,
            "Signature-Input": f"sig1={sig_params}",
            "Signature": f"sig1=:{sig_b64}:",
        }

    def sign_get(self, url: httpx.URL | str) -> dict[str, str]:
        """Return proof-of-possession headers for a bound retrieval GET (ADR-013).

        Presents the agent's raw public key (``X-RAMP-Agent-Key``) and an RFC 9421
        signature over ``@method`` + ``@target-uri`` whose ``keyid`` is the key's
        RFC 7638 thumbprint (Web Bot Auth). The edge verifies the signature
        against the presented key and enforces the 3-way identity offline. The
        signature base and the standard-base64 ``Signature`` value MUST match the
        edge verifier (src/edge/src/pop.ts).
        """
        created = int((self._clock.now() - _EPOCH).total_seconds())
        expires = created + self._ttl
        keyid = self._key.thumbprint()
        covered_list = " ".join(f'"{c}"' for c in _GET_COVERED_COMPONENTS)
        sig_params = (
            f'({covered_list});keyid="{keyid}";alg="ed25519";created={created};expires={expires}'
        )
        sig = self._priv.sign(pop_signature_base(str(url), sig_params).encode())
        sig_b64 = base64.b64encode(sig).decode()
        return {
            AGENT_KEY_HEADER: self._key.public_key_b64url(),
            "Signature-Input": f"sig1={sig_params}",
            "Signature": f"sig1=:{sig_b64}:",
        }


class SigningTransport(httpx.AsyncBaseTransport):
    """httpx transport that signs every outbound request with RFC 9421 + Ed25519."""

    def __init__(self, inner: httpx.AsyncBaseTransport, signer: Signer) -> None:
        """Store the inner transport and the signer."""
        self._inner = inner
        self._signer = signer

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Stamp the RFC 9421 headers onto request and forward it."""
        body = request.content or b""
        authz = request.headers.get("authorization", "")
        headers = self._signer.sign(
            method=request.method,
            url=request.url,
            body=body,
            authorization=authz,
        )
        for name, value in headers.items():
            request.headers[name] = value
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        """Close the inner transport (no-op when not a concrete transport)."""
        if hasattr(self._inner, "aclose"):
            await self._inner.aclose()


def pop_signature_base(url: str, sig_params: str) -> str:
    """RFC 9421 signature base for a bound-retrieval GET (ADR-013 D2).

    The covered set is fixed to ``@method`` + ``@target-uri`` (the method is
    always GET on this path). This MUST stay byte-identical to the edge verifier
    (``src/edge/src/pop.ts`` ``signatureBase``) and the TS test signer; the three
    are pinned by ``testdata/pop-signature-base-vectors.json``.
    """
    return "\n".join(
        [
            '"@method": GET',
            f'"@target-uri": {url}',
            f'"@signature-params": {sig_params}',
        ]
    )


def _content_digest(body: bytes) -> str:
    sha = hashlib.sha256(body).digest()
    return "sha-256=:" + base64.b64encode(sha).decode() + ":"
