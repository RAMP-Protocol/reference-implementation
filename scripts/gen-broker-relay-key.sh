#!/usr/bin/env bash
# Generate the Broker's outbound-relay Ed25519 keypair. Idempotent the way the
# sibling key-gen scripts are: an EXISTING file is reused, never overwritten —
# the Broker's own WBA directory is this key's only publication path, so a
# silent overwrite would rotate the live relay identity and the first symptom
# would be relayed requests failing 401 once verifiers refresh their cached
# directory. The private-key file is written 0600.
#
# Rotation is EXPLICIT (see src/broker/RUNBOOK.md "Rotate the relay key"):
#   BROKER_RELAY_ROTATE=1 BROKER_RELAY_KID=broker.example.v2 scripts/gen-broker-relay-key.sh
#
# There is no shared key registry file to publish the pubkey into: the Broker
# reads this private key (BROKER_RELAY_KEY_FILE) and publishes the public half
# in its OWN WBA directory at boot, which is where the Exchange's broker
# well-known resolver learns it.
#
# Usage:
#   scripts/gen-broker-relay-key.sh                          # default kid=broker.broker-local.v1
#   BROKER_RELAY_KID=broker.broker-us-1.v2 scripts/gen-broker-relay-key.sh
#
# Outputs:
#   deploy/broker/broker-key.json   (gitignored — private key; mounted into the Broker container)

set -euo pipefail

BROKER_RELAY_KID="${BROKER_RELAY_KID:-broker.broker-local.v1}"
BROKER_RELAY_ROTATE="${BROKER_RELAY_ROTATE:-0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BROKER_PRIV_FILE="${REPO_ROOT}/deploy/broker/broker-key.json"

mkdir -p "$(dirname "$BROKER_PRIV_FILE")"

# Interpreter selection (PYTHON array) shared by every key-gen script.
. "$REPO_ROOT/scripts/lib/select-python.sh"

"${PYTHON[@]}" - "$REPO_ROOT/scripts/lib" "$BROKER_RELAY_KID" "$BROKER_PRIV_FILE" "$BROKER_RELAY_ROTATE" <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from ed25519_keys import materialize_keypair

kid, broker_priv_path, rotate = sys.argv[2:5]
priv_file = Path(broker_priv_path)

if priv_file.is_file():
    if rotate != "1":
        old_kid = json.loads(priv_file.read_text()).get("kid")
        print(
            f"kept existing {priv_file} (kid={old_kid}) — a re-run never "
            "rotates the live relay identity; set BROKER_RELAY_ROTATE=1 to "
            "mint a fresh keypair"
        )
        sys.exit(0)
    priv_file.unlink()
    print(f"BROKER_RELAY_ROTATE=1: replacing {priv_file}")

materialize_keypair(priv_file, kid, mode=0o600)
print(f"wrote {priv_file} (kid={kid})")
PY
