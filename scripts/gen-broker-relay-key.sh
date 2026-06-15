#!/usr/bin/env bash
# Generate the Broker's outbound-relay Ed25519 keypair and publish the pubkey
# to the unified Broker keys file. Idempotent: the kid is overwritten on each
# run, and the private-key file is written 0600.
#
# Usage:
#   scripts/gen-broker-relay-key.sh                          # default kid=broker.broker-local.v1
#   BROKER_RELAY_KID=broker.broker-us-1.v2 scripts/gen-broker-relay-key.sh
#
# Outputs:
#   deploy/broker/keys.json         (checked in — pubkeys only; merges with existing entries)
#   deploy/broker/broker-key.json   (gitignored — private key; mounted into the Broker container)

set -euo pipefail

BROKER_RELAY_KID="${BROKER_RELAY_KID:-broker.broker-local.v1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS_FILE="${REPO_ROOT}/deploy/broker/keys.json"
BROKER_PRIV_FILE="${REPO_ROOT}/deploy/broker/broker-key.json"

mkdir -p "$(dirname "$KEYS_FILE")" "$(dirname "$BROKER_PRIV_FILE")"

python3 - "$BROKER_RELAY_KID" "$KEYS_FILE" "$BROKER_PRIV_FILE" <<'PY'
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat,
)

kid, keys_path, broker_priv_path = sys.argv[1:4]

priv = Ed25519PrivateKey.generate()
pub = priv.public_key()

priv_seed = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


entry = {
    "kid": kid,
    "kty": "OKP",
    "crv": "Ed25519",
    "use": "sig",
    "alg": "EdDSA",
    "x": b64u(pub_raw),
}

keys = Path(keys_path)
doc = {"keys": []}
if keys.exists():
    try:
        doc = json.loads(keys.read_text())
    except json.JSONDecodeError:
        doc = {"keys": []}
doc.setdefault("keys", [])
doc["keys"] = [k for k in doc["keys"] if k.get("kid") != kid] + [entry]
keys.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")

priv_file = Path(broker_priv_path)
priv_file.write_text(json.dumps({
    "kid": kid,
    "kty": "OKP",
    "crv": "Ed25519",
    "alg": "EdDSA",
    "private_key": b64u(priv_seed),
    "public_key": b64u(pub_raw),
}, indent=2, sort_keys=True) + "\n")
os.chmod(broker_priv_path, 0o600)

print(f"wrote {keys_path} and {broker_priv_path} (kid={kid})")
PY
