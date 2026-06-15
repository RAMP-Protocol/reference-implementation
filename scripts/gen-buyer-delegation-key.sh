#!/usr/bin/env bash
# Generate a buyer's two Ed25519 keypairs — primary delegation signing key
# (use=verify) and dedicated revocation-list signing key (use=revoke) — and
# publish both pubkeys as a JWKS at the buyer's keys URL. Tracks ye6f-21 /
# agentic-content-access-g32u; see ADR-003 §5c.
#
# Buyer JWKS hosting is intentionally flexible per ADR-003 §1 (opaque-URL
# rule). Two layouts are supported via BUYER_HOSTING:
#
#   convention   — {BUYER_DOMAIN}/.well-known/ramp.json
#                  (e.g. acme.com/.well-known/ramp.json)
#   custom-path  — agent-platform-style per-customer path
#                  (e.g. agent-platform.local/buyers/${BUYER_NAME}/keys)
#
# Usage:
#   scripts/gen-buyer-delegation-key.sh                       # acme @ acme.local convention
#   BUYER_NAME=alice BUYER_DOMAIN=agent-platform.local \
#       BUYER_HOSTING=custom-path scripts/gen-buyer-delegation-key.sh
#
# Outputs:
#   deploy/buyers/${BUYER_DOMAIN}/.well-known/ramp.json             (convention)
#       OR  deploy/buyers/${BUYER_DOMAIN}/buyers/${BUYER_NAME}/keys (custom-path)
#   deploy/publisher-keys/${BUYER_NAME}-delegation-key.json
#       (gitignored; primary delegation private key — buyer-side biscuit
#       attenuation signer)
#   deploy/publisher-keys/${BUYER_NAME}-revocation-key.json
#       (gitignored; revocation-list signing private key — separate from the
#       delegation key so a delegation-key compromise does not also yield
#       the revocation path)
#
# Idempotent: regenerates both private keys and overwrites the JWKS entries
# for both kids, leaving any unrelated entries alone.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUYER_NAME="${BUYER_NAME:-acme}"
BUYER_DOMAIN="${BUYER_DOMAIN:-${BUYER_NAME}.local}"
BUYER_HOSTING="${BUYER_HOSTING:-convention}"
BUYER_VERIFY_KID="${BUYER_VERIFY_KID:-${BUYER_NAME}.delegate.2026}"
BUYER_REVOKE_KID="${BUYER_REVOKE_KID:-${BUYER_NAME}.revoke.2026}"

KEYS_DIR="${REPO_ROOT}/deploy/publisher-keys"
case "$BUYER_HOSTING" in
    convention)
        JWKS_DIR="${REPO_ROOT}/deploy/buyers/${BUYER_DOMAIN}/.well-known"
        JWKS_FILE="${JWKS_DIR}/ramp.json"
        ;;
    custom-path)
        JWKS_DIR="${REPO_ROOT}/deploy/buyers/${BUYER_DOMAIN}/buyers/${BUYER_NAME}"
        JWKS_FILE="${JWKS_DIR}/keys"
        ;;
    *)
        echo "BUYER_HOSTING must be 'convention' or 'custom-path' (got: $BUYER_HOSTING)" >&2
        exit 2
        ;;
esac

mkdir -p "$KEYS_DIR" "$JWKS_DIR"

VERIFY_PRIV_FILE="${KEYS_DIR}/${BUYER_NAME}-delegation-key.json"
REVOKE_PRIV_FILE="${KEYS_DIR}/${BUYER_NAME}-revocation-key.json"

python3 - \
    "$VERIFY_PRIV_FILE" "$REVOKE_PRIV_FILE" "$JWKS_FILE" \
    "$BUYER_VERIFY_KID" "$BUYER_REVOKE_KID" <<'PY'
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)

verify_priv_path, revoke_priv_path, jwks_path, verify_kid, revoke_kid = sys.argv[1:6]


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_keypair() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, pub


def jwk_entry(kid: str, pub: bytes, use: str) -> dict:
    return {
        "kid": kid,
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "use": use,
        "x": b64u(pub),
    }


verify_seed, verify_pub = make_keypair()
revoke_seed, revoke_pub = make_keypair()

Path(verify_priv_path).write_text(json.dumps({
    "kid": verify_kid,
    "alg": "EdDSA",
    "use": "verify",
    "seed": b64u(verify_seed),
    "public": b64u(verify_pub),
}, indent=2) + "\n")
os.chmod(verify_priv_path, 0o600)

Path(revoke_priv_path).write_text(json.dumps({
    "kid": revoke_kid,
    "alg": "EdDSA",
    "use": "revoke",
    "seed": b64u(revoke_seed),
    "public": b64u(revoke_pub),
}, indent=2) + "\n")
os.chmod(revoke_priv_path, 0o600)

existing: dict = {"keys": []}
jwks = Path(jwks_path)
if jwks.exists():
    try:
        existing = json.loads(jwks.read_text())
    except json.JSONDecodeError:
        existing = {"keys": []}
existing.setdefault("keys", [])
keep = [k for k in existing["keys"] if k.get("kid") not in {verify_kid, revoke_kid}]
existing["keys"] = keep + [
    jwk_entry(verify_kid, verify_pub, "verify"),
    jwk_entry(revoke_kid, revoke_pub, "revoke"),
]
jwks.write_text(json.dumps(existing, indent=2, sort_keys=True) + "\n")

print(f"  wrote {verify_priv_path}  (use=verify, kid={verify_kid})")
print(f"  wrote {revoke_priv_path}  (use=revoke, kid={revoke_kid})")
print(f"  wrote {jwks_path}  (both pubkeys published)")
PY
