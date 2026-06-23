#!/bin/sh
# publisher-jwks entrypoint — render the resource-owner's
# /.well-known/ramp.json from the Ed25519 private key mounted at
# $SIGNING_KEY_FILE, then exec nginx.
#
# The unified WellKnownManifest the CatalogSignatureMiddleware self-signup
# path consumes (role=ROLE_PUBLISHER):
#       {"ver": "1.0", "role": "ROLE_PUBLISHER", "domain": <issuer>,
#        "public_keys": [{"kid", "kty": "OKP", "crv": "Ed25519",
#                         "use": "sig", "alg": "EdDSA",
#                         "x": <base64url raw 32-byte pubkey>,
#                         "not_before": <RFC3339>,
#                         "not_after": <RFC3339>}],
#        "catalog_contributors": [...]}
#
# not_before/not_after are wide-open (now-1h .. now+10y) so the
# fixture is never the reason a self-signup fails in the e2e stack.

set -eu

KEY_FILE="${SIGNING_KEY_FILE:-/keys/examplenews-subscription-key.json}"
KID="${SIGNING_KID_OVERRIDE:-}"
# MANIFEST_ROLE selects the manifest's role; default ROLE_PUBLISHER preserves the
# catalog-contributor host behaviour. ROLE_AGENT serves an agent identity's
# manifest (no catalog_contributors) for the lazy-registration e2e.
ROLE="${MANIFEST_ROLE:-ROLE_PUBLISHER}"
WEB_ROOT=/var/www/ramp

mkdir -p "$WEB_ROOT/.well-known"

if [ ! -s "$KEY_FILE" ]; then
    echo "publisher-jwks: signing key not readable at $KEY_FILE" >&2
    exit 1
fi

python3 - "$KEY_FILE" "$WEB_ROOT/.well-known/ramp.json" "$KID" "$ROLE" <<'PY'
import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

key_path, manifest_path, kid_override, role = sys.argv[1:5]

with Path(key_path).open() as fh:
    spec = json.load(fh)

# The key fixture stores the Ed25519 seed (32 bytes) base64url-encoded under
# "private"; some fixtures use "seed", and the agent fixtures (shared with the
# pytest signer) use "private_key". Accept any.
priv_b64 = spec.get("private") or spec.get("seed") or spec.get("private_key")
if not priv_b64:
    sys.exit(f"publisher-jwks: no 'private'/'seed'/'private_key' in {key_path}")
raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
if len(raw) == 64:
    # Ed25519 stdlib-format key: seed (32) || pubkey (32). Use the seed.
    seed = raw[:32]
elif len(raw) == 32:
    seed = raw
else:
    sys.exit(f"publisher-jwks: key length {len(raw)} not 32/64 in {key_path}")
priv = Ed25519PrivateKey.from_private_bytes(seed)
pub_obj = priv.public_key()
# Unified RAMP JWK `x`: base64url (no padding) of the raw 32-byte Ed25519 key.
pub_raw = pub_obj.public_bytes(Encoding.Raw, PublicFormat.Raw)
pub_x = base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")

now = datetime.now(timezone.utc)
valid_from = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
valid_until = (now + timedelta(days=3650)).strftime("%Y-%m-%dT%H:%M:%SZ")

kid = kid_override or spec.get("kid") or "publisher-key"

manifest = {
    "ver": "1.0",
    "role": role,
    "domain": spec.get("issuer", kid.split(".", 1)[0]),
    "public_keys": [
        {
            "kid": kid,
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "x": pub_x,
            "not_before": valid_from,
            "not_after": valid_until,
        },
    ],
}
# catalog_contributors is a publisher-only field (the self-signup Gate-1 list);
# an agent manifest omits it.
if role == "ROLE_PUBLISHER":
    manifest["catalog_contributors"] = [
        {"domain": "catalog-contributor-e2e", "relationship": "harness"},
    ]

Path(manifest_path).write_text(json.dumps(manifest, indent=2) + "\n")
print(
    f"publisher-jwks: wrote {manifest_path} "
    f"(kid={kid}, valid_from={valid_from}, valid_until={valid_until})"
)
PY

echo "publisher-jwks: seeding complete; exec-ing $*"
exec "$@"
