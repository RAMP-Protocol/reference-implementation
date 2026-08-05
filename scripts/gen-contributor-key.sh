#!/usr/bin/env bash
# Mint a catalog-contributor Ed25519 keypair file — the key an operator passes
# to ramp-ingest's --key flag to sign catalog pushes. Parameterized on the
# contributor id, unlike gen-e2e-keys.sh, whose identity list is fixed to the
# e2e stack's fixtures.
#
# The contributor id IS the hostname of the contributor's Web Bot Auth
# directory: the Exchange verifies a push by fetching
# https://<id>/.well-known/http-message-signatures-directory, so the public
# half of this key must be published there (the jwks host image, or the
# stack's static directory hosting, both consume this file's shape). There is
# no shared key registry file to update.
#
# Output shape matches the e2e fixtures byte-for-byte in structure —
# {kid, issuer, kty, crv, alg, private_key, public_key} — because the jwks
# host entrypoint requires `issuer` for the manifest domain and AgentKey-style
# loaders read `private_key`/`public_key` as unpadded base64url raw bytes.
# Written 0644: the file is mounted read-only into nonroot containers, and a
# 0600 file owned by the generating user is unreadable across that UID
# boundary. The no-private-key-in-git invariant is enforced by .gitignore,
# not by the on-disk mode — keep the file out of the repository.
#
# Idempotent: an existing file is reused (re-running never rotates a key that
# a live directory already publishes). Delete the file to mint a fresh key.
#
# Usage:
#   scripts/gen-contributor-key.sh <contributor-id> [out-file]
#   scripts/gen-contributor-key.sh catalog-contributor.publisher.example
#       # → deploy/publisher-keys/catalog-contributor.publisher.example-key.json

set -euo pipefail

if [ $# -lt 1 ] || [ -z "$1" ]; then
    echo "usage: $0 <contributor-id> [out-file]" >&2
    echo "  <contributor-id> is the hostname the contributor's key directory is served at" >&2
    exit 2
fi

CONTRIBUTOR_ID="$1"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="${2:-${REPO_ROOT}/deploy/publisher-keys/${CONTRIBUTOR_ID}-key.json}"

mkdir -p "$(dirname "$OUT_FILE")"

# Interpreter selection (PYTHON array) shared by every key-gen script.
. "$REPO_ROOT/scripts/lib/select-python.sh"

"${PYTHON[@]}" - "$REPO_ROOT/scripts/lib" "$CONTRIBUTOR_ID" "$OUT_FILE" <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from ed25519_keys import materialize_keypair

contributor_id, out_file = sys.argv[2:4]
path = Path(out_file)

# The shared materializer owns the envelope (kid, issuer, kty, crv, alg,
# private_key, public_key), the reuse-never-rotate rule, and the issuer
# backfill; 0644 because the file is mounted into nonroot containers.
existed = path.is_file()
materialize_keypair(path, contributor_id, mode=0o644)
if existed:
    kid = json.loads(path.read_text())["kid"]
    print(f"kept existing {path} (kid={kid}) — delete the file to mint a fresh key")
else:
    print(f"wrote {path} (kid={contributor_id})")
PY
