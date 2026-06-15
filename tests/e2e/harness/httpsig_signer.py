"""Test-harness RFC 9421 Ed25519 signer for v1 obligation 05 tests.

Mirrors ``src/mcp/src/ramp_mcp_shim/httpsig.py::Signer.sign`` and the
``_sign_request`` helper in ``catalog_push.py`` so that obligation-05's
"happy" (correctly refused) and "failure" (defect-guard) scenarios can
construct deliberately-bad signatures against the canonical RPC surface
(``DiscoverResources`` / ``ExecuteTransaction`` / ``ReportUsage``).

The duplication of the signing base is deliberate (and intentionally
small) so the obligation tests stay self-contained and do not pull
``ramp_mcp_shim`` into the e2e harness's dependency tree. The covered-
components list, parameter ordering, and canonicalization rules MUST
stay aligned with the production verifier at ``internal/httpsig/``.

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

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .b64 import b64url_decode

_COVERED_COMPONENTS: tuple[str, ...] = (
    "@method",
    "@target-uri",
    "content-digest",
    "authorization",
)
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
) -> SignedRequest:
    """Build the RFC 9421 signing base, sign with ``priv``, return headers.

    ``created`` and ``expires`` default to ``now`` and ``now + 30s``
    respectively. Tests that want an expired signature pass
    ``created=now - 600, expires=now - 300``; tests that want a future-
    dated signature pass ``created=now + 600, expires=now + 1200``.
    """
    now = int(time.time())
    actual_created = created if created is not None else now
    actual_expires = expires if expires is not None else actual_created + _DEFAULT_TTL_SECONDS

    digest_header = "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"
    covered_list = " ".join(f'"{c}"' for c in _COVERED_COMPONENTS)
    sig_params = (
        f'({covered_list});keyid="{kid}";alg="ed25519";'
        f"created={actual_created};expires={actual_expires}"
    )
    base_lines = [
        f'"@method": {method.upper()}',
        f'"@target-uri": {target_uri}',
        f'"content-digest": {digest_header}',
        f'"authorization": {authorization}',
        f'"@signature-params": {sig_params}',
    ]
    base = "\n".join(base_lines)
    sig = priv.sign(base.encode())
    sig_b64 = base64.b64encode(sig).decode()
    headers = {
        "Content-Digest": digest_header,
        "Authorization": authorization,
        "Signature-Input": f"sig1={sig_params}",
        "Signature": f"sig1=:{sig_b64}:",
    }
    return SignedRequest(headers=headers, signing_base=base, keyid=kid)


def load_keypair(key_path: Path) -> tuple[str, Ed25519PrivateKey]:
    """Read a contributor-style keyfile and return ``(kid, Ed25519PrivateKey)``.

    The key file format is the one written by
    ``scripts/gen-demo-agent-key.sh`` and by
    ``catalog_push.generate_contributor_key``:
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
    "generate_random_keypair",
    "load_keypair",
    "sign_request",
]
