"""Shared Ed25519 key material helpers for the repo's key-gen scripts.

The key-gen scripts (``scripts/gen-e2e-keys.sh``,
``scripts/gen-examplenews-publisher-key.sh``,
``scripts/gen-buyer-delegation-key.sh``, and
``deploy/terraform/scripts/gen-staging-keys.sh``) embed ``python3`` heredocs
that mint Ed25519 keypairs and, for the identity scripts, emit public Web Bot
Auth directory entries. The keypair mint and the WBA entry shape each used to
live in several byte-identical copies; they live here once. Each script keeps
its own JSON file shape, file layout, and side effects (chmod, env-file
emission).

``deploy/publisher-jwks/entrypoint.sh`` consumes this module too: its image is
built from the repo root so the Dockerfile copies this file to
``/opt/ramp/lib``, and the entrypoint heredoc imports the same window and
entry helpers the scripts use — no shell-side copy to keep in sync.

The heredocs consume this module by inserting its directory onto ``sys.path``
(passed as a heredoc argv) and importing the helpers below.

Runnable as a CLI for ad-hoc use / verification::

    python3 scripts/lib/ed25519_keys.py
    {"seed": "<b64url>", "public_key": "<b64url>"}
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def wba_validity_window(lifetime_days: int, skew_hours: int = 1) -> tuple[str, str]:
    """Return ``(not_before, not_after)`` RFC 3339 strings for a WBA entry.

    ``not_before`` is backdated by ``skew_hours`` so a verifier whose clock
    runs slightly behind the generating machine never rejects a
    freshly-published key; ``not_after`` is ``lifetime_days`` ahead. The
    caller chooses the lifetime — it is a policy decision, not a default.
    """
    now = datetime.now(timezone.utc)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (
        (now - timedelta(hours=skew_hours)).strftime(fmt),
        (now + timedelta(days=lifetime_days)).strftime(fmt),
    )


def wba_directory_key(pub_b64: str, not_before: str, not_after: str) -> dict:
    """Return one WBA directory ``keys[]`` entry for an Ed25519 public key.

    The seven members are all required by the canonical directory schema
    (``internal/rampwellknown/schema/ramp-wba-directory.json``); a document
    missing one serves fine and then fails every signed request with an error
    that points at the signature, so the entry is built here once instead of
    hand-written per script. Entries carry no ``kid`` — verifiers name a key
    by its RFC 7638 thumbprint.
    """
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "x": pub_b64,
        "not_before": not_before,
        "not_after": not_after,
    }


def materialize_keypair(path, kid: str, mode: int = 0o600) -> str:
    """Idempotently ensure an Ed25519 keypair fixture at ``path``; return its
    public key (b64url).

    An existing file is REUSED, never rotated — re-running a key-gen script
    must not swap a live identity's key out from under the containers or
    documents derived from it. On reuse the ``issuer`` member is backfilled
    in place when absent: the jwks entrypoint requires it for the manifest
    domain and refuses to guess from the kid (whose first dot would truncate
    a dotted identity). New files carry
    ``{kid, issuer, kty, crv, alg, private_key, public_key}`` with
    ``issuer == kid``.

    ``mode`` is applied on both paths. The default 0o600 suits operator-held
    keys; the e2e script passes 0o644 because its fixtures are mounted
    read-only into distroless/nonroot containers across a UID boundary.
    """
    fixture = Path(path)
    if fixture.exists():
        spec = json.loads(fixture.read_text())
        pub_b64 = spec["public_key"]
        if "issuer" not in spec:
            spec["issuer"] = kid
            fixture.write_text(json.dumps(spec, indent=2) + "\n")
    else:
        seed_b64, pub_b64 = generate_seed_pub_b64()
        fixture.write_text(
            json.dumps(
                {
                    "kid": kid,
                    "issuer": kid,
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "private_key": seed_b64,
                    "public_key": pub_b64,
                },
                indent=2,
            )
            + "\n"
        )
    os.chmod(fixture, mode)
    return pub_b64


def _main() -> None:
    seed_b64, pub_b64 = generate_seed_pub_b64()
    print(json.dumps({"seed": seed_b64, "public_key": pub_b64}))


if __name__ == "__main__":
    _main()
