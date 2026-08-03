"""Shared Ed25519 key-materialization core for the repo's key-gen scripts.

Both ``scripts/gen-e2e-keys.sh`` and ``scripts/gen-examplenews-publisher-key.sh``
embed a ``python3`` heredoc that mints an Ed25519 seed (and, for e2e, its public
half) and b64url-encodes raw bytes. That core used to live in two byte-identical
copies; it lives here once. Each script keeps its own JSON shape, file layout,
and side effects (chmod, registry publish, env-file emission).

The heredocs consume this module by inserting ``scripts/lib`` onto ``sys.path``
(passed as the first heredoc argv) and importing the two helpers below.

Runnable as a CLI for ad-hoc use / verification::

    python3 scripts/lib/ed25519_keys.py
    {"seed": "<b64url>", "public_key": "<b64url>"}
"""

from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def b64u(b: bytes) -> str:
    """Return the URL-safe, unpadded base64 encoding of raw bytes."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def generate_seed_pub_b64() -> tuple[str, str]:
    """Generate an Ed25519 keypair; return ``(seed_b64url, public_key_b64url)``.

    The seed is the 32-byte raw private key (``PrivateFormat.Raw``); the public
    half is the 32-byte raw public key. Both are b64url-encoded without padding,
    matching the on-disk fixture shape both scripts already write.
    """
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64u(seed), b64u(pub)


def _main() -> None:
    seed_b64, pub_b64 = generate_seed_pub_b64()
    print(json.dumps({"seed": seed_b64, "public_key": pub_b64}))


if __name__ == "__main__":
    _main()
