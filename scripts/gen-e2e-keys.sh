#!/usr/bin/env bash
# Generate the Ed25519 identities the docker-compose E2E stack needs and
# publish their public halves into the checked-in Broker key registry
# (deploy/broker/keys.json). The private halves are written under
# tests/e2e/harness/fixtures/ (gitignored — no private key material is
# tracked in git) where the runner image and the broker/relay volume mount read
# them.
#
# Identities (kid → fixture file):
#   catalog-contributor-e2e          catalog_contributor_key.json
#   agent-e2e                        agent_e2e_key.json
#   agent-nobilling-e2e              agent_nobilling_e2e_key.json
#   broker.broker-local.v1           broker_relay_key.json   (also mounted into broker)
#   test-signer-e2e.v1               test_signer_key.json
#   agent-demo-eur                   agent_demo_eur_key.json
#   lazy-agent-e2e                   agent_lazy_e2e_key.json      (NOT registry-seeded)
#   ghost-agent-e2e                  agent_ghost_e2e_key.json     (NOT registry-seeded)
#   demo.ramp-protocol.org           selfpub_philosophy_key.json  (self-publish, kid=domain)
#   music.demo.ramp-protocol.org     selfpub_music_key.json       (self-publish, kid=domain)
#   sfx.demo.ramp-protocol.org       selfpub_sfx_key.json         (self-publish, kid=domain)
#
# NOTE: the kid values above (agent-e2e, agent-demo.v1, broker.broker-local.v1,
# etc.) are E2E/demo FIXTURES, not real public DNS domains. In the demo they act
# as the agent identity (the Signature-Agent value) and are reachable only on the
# local docker-compose network, via RAMP_MANIFEST_FETCH_{SCHEME,PORT}. Do not read
# them as real registered domains. (The self-publish entries where kid=domain are
# the exception — those are domain-shaped on purpose.)
#
# Well-known key distribution: after the WBA split each domain's edge
# SERVES its self key in its Web Bot Auth directory
# (/.well-known/http-message-signatures-directory) keys[] — with NO kid (the key
# is named by its RFC 7638 thumbprint) — so the Exchange learns it via the cached
# well-known fetch (Gate-1 self-signup, matched by caller_id == publisher domain)
# — never a DB pre-seed. This script emits a per-edge env_file under
# deploy/edge-keys/<service>.env carrying WBA_KEYS_JSON=<canonical ramp.v1
# JsonWebKey[] for that domain's self key>; docker-compose.e2e.yml injects it via
# `env_file:`. The key distribution is thus derived from the same generated
# private material the signer uses — the served JWK and the signing key can never
# drift.
#
# Idempotent: a kid's keypair is generated ONLY when its private fixture is
# absent (fresh checkout, or after `e2e-down -v` clears them). An existing
# fixture is reused and its public half (re)published to the registry — so a
# repeat run (e.g. a second `e2e-up` against an already-booted stack) does NOT
# rotate keys, which would mismatch the containers' mounted keys.
#
# Private fixtures are written 0644 (world-readable). The broker mounts
# broker_relay_key.json read-only into a distroless `USER nonroot:nonroot`
# container (uid 65532); a 0600 file owned by the generating user (root in CI)
# is unreadable across that UID boundary, so the broker exits(1) at boot with
# "permission denied". 0644 is how a read-only key is normally provisioned into
# a container. This does NOT weaken the no-private-key-in-git invariant, which
# is enforced by .gitignore (tests/e2e/**/*key*.json), not by the on-disk mode.
# The mode is (re)applied on the reuse path too, to correct any pre-existing
# 0600 fixture from before this change.
#
# Outputs:
#   deploy/broker/keys.json                              (checked in — pubkeys only)
#   tests/e2e/harness/fixtures/<identity>_key.json       (gitignored — private keys)
#
# Run once before `docker compose -f docker-compose.e2e.yml up` (wired into
# `make e2e-keys` / `make e2e-up`).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEYS_FILE="${REPO_ROOT}/deploy/broker/keys.json"
FIXTURES_DIR="${REPO_ROOT}/tests/e2e/harness/fixtures"
EDGE_KEYS_DIR="${REPO_ROOT}/deploy/edge-keys"

mkdir -p "$(dirname "$KEYS_FILE")" "$FIXTURES_DIR" "$EDGE_KEYS_DIR"

python3 - "$REPO_ROOT/scripts/lib" "$KEYS_FILE" "$FIXTURES_DIR" "$EDGE_KEYS_DIR" <<'PY'
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from ed25519_keys import generate_seed_pub_b64

keys_path, fixtures_dir, edge_keys_dir = sys.argv[2:5]

# (kid, private-fixture filename). One Ed25519 keypair per identity.
IDENTITIES = [
    ("catalog-contributor-e2e", "catalog_contributor_key.json"),
    ("agent-e2e", "agent_e2e_key.json"),
    ("agent-nobilling-e2e", "agent_nobilling_e2e_key.json"),
    ("broker.broker-local.v1", "broker_relay_key.json"),
    ("test-signer-e2e.v1", "test_signer_key.json"),
    # Throwaway, non-relay identity the cross-container revocation e2e revokes
    # (test_revocation_channel). Published in the Broker WBA directory so the
    # Exchange resolves it via the broker channel; used by no other scenario.
    ("revocation-throwaway-e2e", "revocation_throwaway_key.json"),
    # Phase-2 demo buyer funded in EUR (the demo catalog denominates most terms
    # in EUR/GBP; the baseline agent-e2e is USD-only and the in-memory billing
    # adapter authorizes every term — incl. FREE — on a currency match).
    ("agent-demo-eur", "agent_demo_eur_key.json"),
]

# Identities that get a keypair but are deliberately absent from the Broker
# registry. Pre-seeding one here would satisfy resolution from the registry and
# so retire the very code path its test exists to drive — a green run proving
# nothing. Both fixtures are consumed by the lazy-registration e2e.
UNSEEDED_IDENTITIES = [
    # Resolvable, but only the slow way: the agent-jwks service serves this key's
    # ROLE_AGENT well-known on the lazy-agent-e2e alias, and the Broker and
    # Exchange must fetch it there. This is the only test that fires the
    # well-known fetch on the relay path, because every other signing agent is
    # pre-registered.
    ("lazy-agent-e2e", "agent_lazy_e2e_key.json"),
    # Resolvable nowhere at all — the negative control. Valid signature, no
    # registry entry and no well-known host, so every resolution route must come
    # up empty.
    ("ghost-agent-e2e", "agent_ghost_e2e_key.json"),
]

# Self-publish identities: kid == publisher domain. Each domain's edge
# SERVES this key in its Web Bot Auth directory (see the emission below) so the
# Exchange learns it via the cached well-known fetch (Gate-1 self-signup); the
# ramp.json overlay carries no keys at all. The demo
# ingest signs that publisher's feed with caller_id == kid == domain (Gate-2
# caller==domain). The pubkey is emitted to a per-edge env_file below.
#
# (kid==domain, private-fixture filename, edge env_file basename)
# The philosophy publisher is the BARE APEX demo domain (demo.ramp-protocol.org)
# BY DESIGN, while music/sfx are subdomained (music./sfx.demo...). Its fixture
# selfpub_philosophy_key.json carries no 'philosophy' token in its kid because
# kid == domain == the apex — grep-by-domain on the apex, not on 'philosophy'.
SELF_PUBLISH_IDENTITIES = [
    ("demo.ramp-protocol.org", "selfpub_philosophy_key.json", "edge"),
    ("music.demo.ramp-protocol.org", "selfpub_music_key.json", "fastly-edge"),
    ("sfx.demo.ramp-protocol.org", "selfpub_sfx_key.json", "aws-edge"),
]


keys = Path(keys_path)
doc = {"keys": []}
if keys.exists():
    try:
        doc = json.loads(keys.read_text())
    except json.JSONDecodeError:
        doc = {"keys": []}
doc.setdefault("keys", [])

fixtures = Path(fixtures_dir)


def materialize(kid: str, filename: str) -> str:
    """Idempotently ensure an Ed25519 keypair fixture; return its pubkey b64url.

    Reuse the existing keypair when present. Re-running (e.g. a second `e2e-up`
    while the stack is booted) must NOT rotate keys — that would mismatch the
    containers' mounted keys and re-churn anything derived from them.
    """
    fixture = fixtures / filename
    if fixture.exists():
        pub_b64 = json.loads(fixture.read_text())["public_key"]
    else:
        seed_b64, pub_b64 = generate_seed_pub_b64()
        # Private fixture (gitignored) consumed by the runner image / mounts.
        fixture.write_text(
            json.dumps(
                {
                    "kid": kid,
                    # The JWKS entrypoint derives a manifest domain from
                    # `issuer`, falling back to the kid up to its first dot.
                    # Emitting it explicitly means a kid that later grows a
                    # dotted prefix cannot silently change that domain.
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
    # 0644 (world-readable): the broker / nginx hosts mount these keys into
    # distroless / nonroot containers; a 0600 file owned by the generating user
    # (root in CI dind) is unreadable across the UID boundary. Applied on the
    # reuse path too, to correct any pre-existing 0600 fixture.
    os.chmod(fixture, 0o644)
    return pub_b64


def publish_registry_entry(kid: str, pub_b64: str) -> None:
    """(Re)publish a verify-side JWK to the shared Broker registry (pubkey only)."""
    entry = {
        "kid": kid,
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "x": pub_b64,
    }
    doc["keys"] = [k for k in doc["keys"] if k.get("kid") != kid] + [entry]


for kid, filename in IDENTITIES:
    pub_b64 = materialize(kid, filename)
    publish_registry_entry(kid, pub_b64)

for kid, filename in UNSEEDED_IDENTITIES:
    materialize(kid, filename)

# ── Self-publish keys (caller_id == domain) + per-edge WBA_KEYS_JSON ──
# Each edge serves exactly ONE active key (its own self key); selectValidKey in
# the Exchange picks ActiveKeys[0] in doc order, so the served list carries only
# the catalog-signing key. The validity window is wide-open (now-1h .. now+10y)
# so the fixture is never the reason a self-signup fails in the e2e stack. These
# keys are NOT published to deploy/broker/keys.json: the well-known fetch is the
# ONLY path by which the Exchange may learn a catalog-writer key (Core Invariant).
_now = datetime.now(UTC)
_not_before = (_now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
_not_after = (_now + timedelta(days=3650)).strftime("%Y-%m-%dT%H:%M:%SZ")

for domain, filename, edge_service in SELF_PUBLISH_IDENTITIES:
    pub_b64 = materialize(domain, filename)
    # WBA directory keys[] item: a pure JWK with NO kid (named by thumbprint),
    # matching the canonical ramp-wba-directory.json schema the edge serves.
    wba_keys = [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "x": pub_b64,
            "not_before": _not_before,
            "not_after": _not_after,
        },
    ]
    env_path = Path(edge_keys_dir) / f"{edge_service}.env"
    env_path.write_text(
        "WBA_KEYS_JSON=" + json.dumps(wba_keys, separators=(",", ":")) + "\n"
    )
    os.chmod(env_path, 0o644)

doc["keys"].sort(key=lambda k: k.get("kid", ""))
keys.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")

print(
    "gen-e2e-keys: wrote "
    + ", ".join(kid for kid, _ in IDENTITIES)
    + f" → {keys_path} (pubkeys) + {fixtures_dir}/ (private); "
    + "not registry-seeded "
    + ", ".join(kid for kid, _ in UNSEEDED_IDENTITIES)
    + f" → {fixtures_dir}/ only; "
    + "self-publish keys "
    + ", ".join(d for d, _, _ in SELF_PUBLISH_IDENTITIES)
    + f" → {edge_keys_dir}/*.env (WBA_KEYS_JSON)"
)
PY
