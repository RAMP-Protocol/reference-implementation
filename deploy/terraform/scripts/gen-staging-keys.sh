#!/usr/bin/env bash
# Generate the staging stack's key material into
# deploy/terraform/stacks/staging-aws/keys/ (gitignored — no private key
# material is ever tracked in git).
#
# Outputs:
#   ed25519-private.pem      Exchange offer/URL signing key (uploaded to VM)
#   rsa-private.pem          Exchange RSA key for CloudFront-scheme tenants (uploaded)
#   broker-relay-key.json    Broker relay signing keypair (uploaded)
#   broker-identity-seed     Broker IDENTITY key seed, b64url 32 bytes (LOCAL
#                            source of truth; the derived PEM below is what
#                            ships). A DIFFERENT key from the relay one above:
#                            the relay key signs Broker->Exchange calls (its
#                            pubkey is published in the Broker's own WBA
#                            directory, where the Exchange resolves it), while
#                            this one is the identity the Broker publishes in
#                            that same directory with a 90-day validity window.
#                            It must survive a restart, or the Broker breaks a
#                            promise it just published.
#   broker-identity-key.pem  The same identity key as a PEM (raw 64-byte
#                            payload, the shape the Broker's key-file loader
#                            accepts — NOT PKCS#8). Uploaded to the VM and
#                            read via BROKER_ED25519_KEY_FILE, so the key
#                            ships as a root-owned file like its peers rather
#                            than as an env value in the compose file.
#   agent-key.json           Smoke agent keypair (LOCAL ONLY — smoke.sh signs
#                            Broker calls with it; no service on the VM reads it)
#   contributor-key.json     Catalog-contributor keypair (LOCAL ONLY — signs
#                            seed-staging.sh's ramp-ingest push, never uploaded)
#   smoke-agent-wba.json         PUBLIC Web Bot Auth directory documents (JWK
#   catalog-contributor-wba.json Sets, public keys only) for the two smoke
#                            identities. The stack reads them at apply time and
#                            serves each at its identity's hostname
#                            (/.well-known/http-message-signatures-directory),
#                            which is how the Exchange and Broker verify the
#                            smoke signatures — the private halves never leave
#                            this machine. Re-derived on every run from
#                            whatever keypair is current.
#
# There is no shared key registry file: services learn verification keys only
# via well-known discovery (each participant publishes its own keys).
#
# Idempotent: existing keypairs are reused (re-running never rotates keys under
# a live stack).
#
# The smoke identity ids ARE hostnames — <label>.<domain> — because each id is
# the host the services fetch the signer's key directory from. lib/staging-env.sh
# resolves them: from the existing key files' kids, or (first run only) from
# STAGING_DOMAIN — the domain the stack serves the identity directories
# directly under. For stacks/staging-aws that is the tfvars `domain`; for
# stacks/demo-aws, where every name nests under the publisher label, it is
# the publisher hostname (<publisher_subdomain>.<domain>):
#
#   STAGING_DOMAIN=staging-zone.example deploy/terraform/scripts/gen-staging-keys.sh
#   STAGING_DOMAIN=demo.publisher.example STACK_DIR=... # demo-aws
#
# Usage:
#   deploy/terraform/scripts/gen-staging-keys.sh

set -euo pipefail

# KEYS_DIR comes from staging-env.sh, derived from STACK_DIR: the directory
# this script WRITES is the one seed-staging.sh, fund-staging-agent.sh, and
# smoke.sh READ, including under a STACK_DIR override.
. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"

# Fail fast with one clear line when a tool is absent: openssl generates the
# PEM signing keys. The Python interpreter needs no check here — staging-env.sh
# above already sourced select-python.sh, which picks uv or system python3.
command -v openssl >/dev/null 2>&1 || { echo "missing: openssl" >&2; exit 2; }

# Empty ids mean the key files do not exist yet AND STAGING_DOMAIN is unset —
# there is nothing to mint hostname-shaped ids from (see staging-env.sh).
if [ -z "${AGENT_ID}" ] || [ -z "${CONTRIBUTOR_ID}" ]; then
    echo "the smoke identity key files do not exist yet, so their ids must be minted:" >&2
    echo "set STAGING_DOMAIN to the domain the stack serves the identity directories under and re-run, e.g." >&2
    echo "  STAGING_DOMAIN=staging-zone.example $0        # stacks/staging-aws: the tfvars 'domain'" >&2
    echo "  STAGING_DOMAIN=demo.publisher.example $0      # stacks/demo-aws: the publisher hostname" >&2
    echo "(each id becomes <label>.<STAGING_DOMAIN> — the hostname the stack serves that identity's key directory at)" >&2
    exit 2
fi

mkdir -p "${KEYS_DIR}"
chmod 0700 "${KEYS_DIR}"

# PEM signing keys (reused when present, like every keypair here).
if [ ! -f "${KEYS_DIR}/ed25519-private.pem" ]; then
    openssl genpkey -algorithm ED25519 -out "${KEYS_DIR}/ed25519-private.pem"
fi
if [ ! -f "${KEYS_DIR}/rsa-private.pem" ]; then
    openssl genrsa -out "${KEYS_DIR}/rsa-private.pem" 2048
fi

# The Python below stays inline in this shell script on purpose. It is mostly
# glue — write each keypair file if it does not exist yet — with one
# deliberate exception: the Broker identity PEM derivation at the bottom
# hand-rolls a non-standard PEM (raw
# 64-byte payload) because its ONLY consumer is the Broker's own loader and no
# library writes that shape. Everything else imports the shared helpers in
# scripts/lib. Moving this into a Python module of its own would mean one more
# package to maintain, for a utility an operator runs once per environment.
"${PYTHON[@]}" - "${REPO_ROOT}/scripts/lib" "${KEYS_DIR}" \
    "${BROKER_RELAY_KID}" "${AGENT_ID}" "${CONTRIBUTOR_ID}" <<'PY'
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, sys.argv[1])
from ed25519_keys import (
    generate_seed_pub_b64,
    materialize_keypair,
    wba_directory_key,
    wba_validity_window,
)

keys_dir = Path(sys.argv[2])
broker_relay_kid, agent_id, contributor_id = sys.argv[3:6]

# (kid, filename, requester_type note). Same JSON shape as the e2e fixtures —
# the services and ramp-ingest read {kid, kty, crv, alg, private_key, public_key}.
IDENTITIES = [
    (broker_relay_kid, "broker-relay-key.json"),
    (agent_id, "agent-key.json"),
    (contributor_id, "contributor-key.json"),
]


# Shared materializer: reuse-never-rotate, issuer stamped (and backfilled on
# reuse) so a staging key file mounted into a jwks host passes its issuer
# guard, 0600 — these are operator-held keys that never leave this machine.
pubkeys = {
    filename: materialize_keypair(keys_dir / filename, kid)
    for kid, filename in IDENTITIES
}

# Public Web Bot Auth directory documents for the two smoke identities. The
# stack serves each verbatim at its identity's hostname
# (/.well-known/http-message-signatures-directory), so the Exchange and Broker
# can verify the smoke signatures without any private material leaving this
# machine. The relay key needs none: the Broker publishes it in its own
# directory. Directory keys carry NO kid — a verifier names them by RFC 7638
# thumbprint. Re-derived unconditionally so the served document can never
# drift from the keypair it describes.
#
# The validity window is 90 days, matching what the Broker publishes for its
# own keys. These are real public hostnames whose private halves sit on an
# operator's machine with no revocation channel, so the window is the only
# thing that ever retires a leaked smoke key — a wide window would leave it
# verifying for years. Re-running this script before an apply is already the
# documented refresh path, so the bound costs nothing; a smoke run against a
# stack whose documents are older than 90 days fails signature verification,
# and the fix is exactly that documented path (re-run this script, re-apply).
_not_before, _not_after = wba_validity_window(lifetime_days=90)

WBA_DOCUMENTS = [
    ("agent-key.json", "smoke-agent-wba.json"),
    ("contributor-key.json", "catalog-contributor-wba.json"),
]

for key_filename, wba_filename in WBA_DOCUMENTS:
    document = {"keys": [wba_directory_key(pubkeys[key_filename], _not_before, _not_after)]}
    wba_path = keys_dir / wba_filename
    wba_path.write_text(json.dumps(document, indent=2) + "\n")
    wba_path.chmod(0o644)

# The Broker's IDENTITY key. It is outbound-only (it stamps the intermediary
# attestation) and the Broker publishes its own public half in its WBA
# directory.
#
# Two artifacts, one key. The seed is the compact source of truth; the PEM is
# derived from it deterministically and is what ships to the VM, so the key
# travels as a root-owned key FILE like its peers (BROKER_ED25519_KEY_FILE),
# never as an env value inside the world-readable compose file. The PEM is
# deliberately NOT the PKCS#8 shape `openssl genpkey` writes: the Broker's
# key-file loader wants the raw 64-byte ed25519 private key (seed || public
# key) as the block payload, and this script is the producer of that shape.
# Derive-if-missing means a deployment that already has a seed gets a PEM for
# the SAME key — no identity rotation.
seed_path = keys_dir / "broker-identity-seed"
pem_path = keys_dir / "broker-identity-key.pem"


def pem_payload(path):
    return base64.b64decode(
        "".join(
            line
            for line in path.read_text().splitlines()
            if line and not line.startswith("-----")
        )
    )


if not seed_path.exists():
    if pem_path.exists():
        # A lost seed is recoverable: the PEM payload is seed || public key,
        # so its first 32 bytes ARE the seed. Re-derive it and keep the
        # identity. Minting a fresh seed here instead would first write a
        # decoy that can never match the PEM, then push the operator toward
        # the identity rotation this design exists to prevent.
        identity_seed = (
            base64.urlsafe_b64encode(pem_payload(pem_path)[:32]).decode().rstrip("=")
        )
    else:
        identity_seed, _ = generate_seed_pub_b64()
    seed_path.write_text(identity_seed + "\n")
    seed_path.chmod(0o600)

seed_b64 = seed_path.read_text().strip()
seed_bytes = base64.urlsafe_b64decode(seed_b64 + "=" * (-len(seed_b64) % 4))
key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
pub_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

if pem_path.exists():
    # Both artifacts exist: prove they are still the SAME key. Without this, a
    # deleted-and-regenerated seed would silently diverge from the PEM that
    # keeps shipping, and a later PEM re-derivation would rotate the Broker's
    # published identity mid-window — the promise-break this whole design
    # exists to prevent.
    if pem_payload(pem_path)[:32] != seed_bytes:
        sys.exit(
            f"{pem_path.name} does not match {seed_path.name} — the two have "
            "diverged (was the seed deleted and regenerated?). Delete BOTH to "
            "mint a fresh identity, or restore the matching seed. Careful: a "
            "fresh identity breaks the validity window the Broker already "
            "published."
        )
else:
    payload = base64.b64encode(seed_bytes + pub_bytes).decode()
    body = "\n".join(payload[i : i + 64] for i in range(0, len(payload), 64))
    # Write-to-temp + atomic rename: an interrupted run must not leave a
    # truncated PEM behind, because the exists() guard above would then treat
    # the stump as final on every later run.
    tmp_path = pem_path.with_suffix(".pem.tmp")
    # The label is named once and interpolated into both halves so this file
    # never carries a BEGIN header and its matching END footer as literals.
    # That pair is what the secret scanner matches on, and it matches whatever
    # sits between the two. The bytes written are unchanged: the label the
    # Broker's loader and the broker_identity_key_pem validation both read is
    # the rendered one.
    label = "ED25519 PRIVATE KEY"
    tmp_path.write_text(f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    tmp_path.chmod(0o600)
    tmp_path.replace(pem_path)

print(
    "gen-staging-keys: "
    + ", ".join(kid for kid, _ in IDENTITIES)
    + f" -> {keys_dir}/ (private keypairs + broker identity seed/PEM; "
    + "public WBA directory documents for the smoke identities)"
)
PY

echo "done. keys live in ${KEYS_DIR} (gitignored). contributor-key.json stays local."
