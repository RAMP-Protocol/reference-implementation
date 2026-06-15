#!/usr/bin/env bash
# Generate a demo Ed25519 keypair for the MCP shim and publish the pubkey to
# the unified Broker keys registry file. Idempotent: the kid is overwritten on
# each run, and the private-key file is written 0600.
#
# Usage:
#   scripts/gen-demo-agent-key.sh               # default kid=agent-demo.v1
#   AGENT_KID=agent-foo.v2 scripts/gen-demo-agent-key.sh
#
# Outputs:
#   deploy/broker/keys.json         (checked in — pubkeys only; shared with broker-relay)
#   deploy/mcp/agent-key.json       (gitignored — private key; mounted into the MCP shim container)

set -euo pipefail

AGENT_KID="${AGENT_KID:-agent-demo.v1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_FILE="${REPO_ROOT}/deploy/broker/keys.json"
MCP_FILE="${REPO_ROOT}/deploy/mcp/agent-key.json"

mkdir -p "$(dirname "$BROKER_FILE")" "$(dirname "$MCP_FILE")"

python3 - "$AGENT_KID" "$BROKER_FILE" "$MCP_FILE" <<'PY'
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat,
)

kid, broker_path, mcp_path = sys.argv[1:4]

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

# Read-modify-write the broker registry so other kids are preserved.
broker = Path(broker_path)
doc = {"keys": []}
if broker.exists():
    try:
        doc = json.loads(broker.read_text())
    except json.JSONDecodeError:
        doc = {"keys": []}
doc.setdefault("keys", [])
doc["keys"] = [k for k in doc["keys"] if k.get("kid") != kid] + [entry]
broker.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")

# Overwrite the MCP private-key file outright; only one active demo agent.
mcp = Path(mcp_path)
mcp.write_text(json.dumps({
    "kid": kid,
    "kty": "OKP",
    "crv": "Ed25519",
    "alg": "EdDSA",
    "private_key": b64u(priv_seed),
    "public_key": b64u(pub_raw),
}, indent=2, sort_keys=True) + "\n")
os.chmod(mcp_path, 0o600)

print(f"wrote {broker_path} and {mcp_path} (kid={kid})")
PY
