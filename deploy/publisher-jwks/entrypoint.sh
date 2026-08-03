#!/bin/sh
# publisher-jwks entrypoint — render the resource-owner's discovery documents
# from the Ed25519 private key mounted at $SIGNING_KEY_FILE, then exec nginx.
#
# After the WBA split there are TWO files:
#   * /.well-known/ramp.json — the KEYLESS commercial overlay manifest
#     (role=ROLE_PUBLISHER, no identity keys):
#       {"ver": "1.0", "role": "ROLE_PUBLISHER", "domain": <issuer>,
#        "catalog_contributors": [...], "exchanges": [...]}
#   * /.well-known/http-message-signatures-directory — the Web Bot Auth
#     directory (a JWK Set; the key carries NO kid, named by RFC 7638 thumbprint):
#       {"keys": [{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
#                  "x": <base64url raw 32-byte pubkey>,
#                  "not_before": <RFC3339>, "not_after": <RFC3339>}]}
# The CatalogSignatureMiddleware self-signup path fetches the WBA directory to
# learn the writer key (matched by caller_id == manifest domain).
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

EXCHANGES_JSON="${EXCHANGES_JSON:-}" \
CATALOG_CONTRIBUTORS_JSON="${CATALOG_CONTRIBUTORS_JSON:-}" \
MANIFEST_DOMAIN_OVERRIDE="${MANIFEST_DOMAIN_OVERRIDE:-}" \
python3 - "$KEY_FILE" "$WEB_ROOT/.well-known/ramp.json" "$KID" "$ROLE" <<'PY'
import base64
import json
import os
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

# The resource-owner key fixture stores the Ed25519 seed (32 bytes) base64url-
# encoded under "private". Some fixtures use "seed"; the e2e harness contributor
# fixture (catalog_push.generate_contributor_key / gen-e2e-keys.sh) and the agent
# fixtures (shared with the pytest signer) use "private_key". Accept any of the three.
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

# Optional exchanges[] (Phase-2 demo): the Broker's publisher-probe reads this
# to route a resolve to the owning Exchange. Each EXCHANGES_JSON entry carries
# {domain, endpoint, supported_profiles?}; per-entry supported_profiles are
# hoisted to a top-level supported_profiles set (the unified AuthorizedExchange
# has no per-entry slot, matching the edge's publisher-manifest.mjs emitter).
exchanges_env = os.environ.get("EXCHANGES_JSON", "").strip()
exchanges_in = json.loads(exchanges_env) if exchanges_env else []
exchanges = [
    {
        "domain": e["domain"],
        "endpoint": e["endpoint"],
        "relationship": "PROVIDER_RELATIONSHIP_DIRECT",
    }
    for e in exchanges_in
]
profiles = sorted({p for e in exchanges_in for p in e.get("supported_profiles", [])})

# A self-hosting contributor needs its manifest domain to EQUAL its
# fetched agent_id (registry.go rejects m.GetDomain() != agentID). Allow an
# explicit override; default to the issuer / kid-prefix derivation otherwise.
domain = os.environ.get("MANIFEST_DOMAIN_OVERRIDE", "").strip() or spec.get(
    "issuer", kid.split(".", 1)[0]
)

# catalog_contributors defaults to the demo harness contributor (the examplenews
# subscription publisher authorizes it); a self-hosting contributor host serves
# only its own key and passes CATALOG_CONTRIBUTORS_JSON='[]' to suppress it.
contributors_env = os.environ.get("CATALOG_CONTRIBUTORS_JSON", "").strip()
contributors = (
    json.loads(contributors_env)
    if contributors_env
    else [{"domain": "catalog-contributor-e2e", "relationship": "harness"}]
)

# Keyless commercial overlay — identity keys moved to the WBA directory below.
manifest = {
    "ver": "1.0",
    # role generalized (v1.1): ROLE_PUBLISHER (default) or ROLE_AGENT for the
    # lazy-registration e2e. domain keeps the env-override-aware derivation.
    "role": role,
    "domain": domain,
}
# catalog_contributors / exchanges / supported_profiles are publisher-only fields
# (the self-signup Gate-1 list + the publisher-probe routing); an agent manifest
# (lazy-registration e2e) omits them. Publisher fields stay env-driven (ours), so
# the multi-publisher demo can vary contributors/exchanges/profiles per host.
if role == "ROLE_PUBLISHER":
    if contributors:
        manifest["catalog_contributors"] = contributors
    if exchanges:
        manifest["exchanges"] = exchanges
    if profiles:
        manifest["supported_profiles"] = profiles

# Web Bot Auth directory — the signing key as a JWK Set, NO kid (named by
# thumbprint). kid is retained only for the log line below.
wba = {
    "keys": [
        {
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

Path(manifest_path).write_text(json.dumps(manifest, indent=2) + "\n")
wba_path = Path(manifest_path).parent / "http-message-signatures-directory"
wba_path.write_text(json.dumps(wba, indent=2) + "\n")
print(
    f"publisher-jwks: wrote {manifest_path} + {wba_path} "
    f"(kid={kid}, valid_from={valid_from}, valid_until={valid_until})"
)
PY

echo "publisher-jwks: seeding complete; exec-ing $*"
exec "$@"
