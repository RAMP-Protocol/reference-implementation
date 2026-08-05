"""Test-harness RFC 9421 Ed25519 signer for v1 obligation 05 tests.

Mirrors the ``_sign_request`` helper in ``catalog_push.py`` so that obligation-05's
"happy" (correctly refused) and "failure" (defect-guard) scenarios can
construct deliberately-bad signatures against the canonical RPC surface
(``DiscoverResources`` / ``ExecuteTransaction`` / ``ReportUsage``).

The signing base, covered-component set, and crypto are the SDK's
(``ramp_sdk.httpsig.sign_request``), and the 5-key Title-Case header lift is
``rampsig.title_case_signed_headers`` — the sibling of the same module's
``build_rfc9421_headers``, so the harness's two header producers cannot drift in
casing, key set, or order. Both stay aligned with the production verifier. What
stays local here are the TEST-ONLY knobs — caller-supplied ``created`` /
``expires`` / ``signature_agent`` overrides — that let the obligation tests forge
expired, future-dated, or mis-attributed signatures against the canonical RPC
surface (the SDK signer takes injected timestamps by design, which is exactly
what those knobs need).

The module exposes two pieces:

- :class:`SignedRequest` — a frozen Pydantic-shaped dataclass holding
  the four headers (``Content-Digest``, ``Signature-Input``,
  ``Signature``, ``Authorization``) plus the canonical signing-base
  string. Tests assert refusal reasons against the header values; the
  signing-base string is exposed for the "tampered body" / "tampered
  headers" scenarios that need to know what the signer committed to.
- :func:`sign_request` — the function that builds a SignedRequest from
  method, target URI, body bytes, and a keypair. The function accepts
  knobs for the timestamps so tests can construct expired or future-
  dated signatures without monkey-patching the clock.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from ramp_sdk.b64 import b64url_decode
from ramp_sdk.httpsig import sign_request as _sdk_sign_request
from ramp_sdk.thumbprint import thumbprint as ed25519_thumbprint

from .rampsig import title_case_signed_headers

_DEFAULT_TTL_SECONDS = 30


@dataclass(frozen=True)
class SignedRequest:
    """Bundle of headers + signing-base produced by :func:`sign_request`.

    The ``headers`` mapping is what the test stamps onto the outgoing
    httpx request. The ``signing_base`` field is exposed so the
    "tampered body" scenario can assert on which body bytes the
    signature committed to (a sanity check, not a refusal observable).
    """

    headers: dict[str, str]
    signing_base: str
    keyid: str


def sign_request(
    *,
    method: str,
    target_uri: str,
    body: bytes,
    kid: str,
    priv: Ed25519PrivateKey,
    created: int | None = None,
    expires: int | None = None,
    authorization: str = "",
    signature_agent: str | None = None,
) -> SignedRequest:
    """Build the RFC 9421 signing base, sign with ``priv``, return headers.

    After the WBA split the RFC 9421 ``keyid`` is the key's RFC 7638 thumbprint;
    the ``kid`` argument names the signer's directory origin, carried in the
    covered ``Signature-Agent`` header (defaulting to ``kid`` — in the demo/tests
    an agent's kid == its directory == caller identity). Pass ``signature_agent``
    explicitly to decouple them.

    ``created`` and ``expires`` default to ``now`` and ``now + 30s``
    respectively. Tests that want an expired signature pass
    ``created=now - 600, expires=now - 300``; tests that want a future-
    dated signature pass ``created=now + 600, expires=now + 1200``.
    """
    now = int(time.time())
    actual_created = created if created is not None else now
    actual_expires = expires if expires is not None else actual_created + _DEFAULT_TTL_SECONDS

    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keyid = ed25519_thumbprint(pub_bytes)
    agent = signature_agent if signature_agent is not None else kid
    signed = _sdk_sign_request(
        method=method,
        url=target_uri,
        body=body,
        authorization=authorization,
        signer_seed=priv.private_bytes_raw(),
        keyid=keyid,
        created=actual_created,
        expires=actual_expires,
        signature_agent=agent,
    )
    headers = title_case_signed_headers(
        content_digest=signed.content_digest,
        authorization=authorization,
        signature_agent=agent,
        signature_input=signed.signature_input,
        signature=signed.signature,
    )
    return SignedRequest(headers=headers, signing_base=signed.signature_base, keyid=keyid)


def load_keypair(key_path: Path) -> tuple[str, Ed25519PrivateKey]:
    """Read a contributor-style keyfile and return ``(kid, Ed25519PrivateKey)``.

    The key file format is the one written by ``scripts/gen-e2e-keys.sh``:
    ``{"kid": "...", "private_key": "<b64url seed>", "public_key": "..."}``.
    """
    doc = json.loads(key_path.read_text())
    seed = b64url_decode(doc["private_key"])
    return doc["kid"], Ed25519PrivateKey.from_private_bytes(seed)


def generate_random_keypair(kid: str) -> tuple[str, Ed25519PrivateKey]:
    """Build an in-memory Ed25519 keypair tagged with ``kid``.

    Used by the "unknown signer" scenario — a freshly-generated key
    cannot be registered in any agent's hosted ``ramp.json``, so the
    verifier's resolver returns :go:`ErrUnknownKey` when it tries to
    resolve the ``kid``.
    """
    return kid, Ed25519PrivateKey.generate()


__all__ = [
    "SignedRequest",
    "key_thumbprint",
    "generate_random_keypair",
    "load_keypair",
    "sign_request",
]


def key_thumbprint(key_path: Path) -> str:
    """Return the RFC 7638 thumbprint of the key stored at ``key_path``.

    The thumbprint is the identity a WBA directory and a revocation list name a
    key by, so a test that has only the keyfile can still ask "which key is this?"
    without reconstructing the JWK by hand.
    """
    _, priv = load_keypair(key_path)
    return ed25519_thumbprint(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
