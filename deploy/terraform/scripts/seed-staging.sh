#!/usr/bin/env bash
# One-time staging seed: registers the demo tenant, the signing identities,
# and the Broker's exchange row, then ingests the demo philosophy feed through
# the production ingest binary (cmd/ramp-ingest) over public HTTPS.
#
# No admin RPC exists yet for tenant/agent/exchange registration (the RAMP-51
# admin plane covers fee-rate + reporting-policy only), so registration is a
# DOCUMENTED one-time SQL step executed over SSH — printed in full before it
# runs, never hidden. When registration RPCs land, this script should switch
# to them.
#
# Prerequisites: stack applied (terraform outputs readable), keys generated
# (gen-staging-keys.sh), images pushed, DNS live, Caddy certs issued.
#
# Env (all optional):
#   STACK_DIR        default deploy/terraform/stacks/staging-aws
#   TENANT_ID        default tenant-staging
#   PUBLISHER_DOMAIN publisher hostname to seed the tenant and catalog for.
#                    Default: the stack's own edge-fronted hostname
#                    (publisher_hostname output). Set it — together with a
#                    fresh TENANT_ID — to onboard a client publisher fronted
#                    by a separately applied stacks/edge (the deploy_edge =
#                    false mode), e.g.:
#                      TENANT_ID=tenant-client \
#                      PUBLISHER_DOMAIN=client-news.example.com \
#                      deploy/terraform/scripts/seed-staging.sh
#   FEED             default deploy/fixtures/demo/philosophy.jsonl
#   AGENT_ID / CONTRIBUTOR_ID / BROKER_RELAY_KID — identity ids come from
#   lib/staging-env.sh, which reads the smoke ids from the generated key
#   files' kids (shared with gen-staging-keys.sh and smoke.sh so the ids can
#   never drift apart). This script additionally proves the ids equal the
#   hostnames the stack serves the key directories at, before seeding rows
#   under them.
#
# Usage:
#   deploy/terraform/scripts/seed-staging.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"
TENANT_ID="${TENANT_ID:-tenant-staging}"
FEED="${FEED:-${REPO_ROOT}/deploy/fixtures/demo/philosophy.jsonl}"

# Fail fast with one clear line when a tool is absent: terraform reads the
# stack outputs (tf_out), go runs the ramp-ingest catalog push, python3
# converts the public keys into the hex form the SQL needs, uv runs the signed
# Register call that mints the smoke agent's billing account.
command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo "missing: go" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "missing: python3" >&2; exit 2; }
command -v uv >/dev/null 2>&1 || { echo "missing: uv" >&2; exit 2; }

# Builds SSH_CMD from the stack.s vm_public_ip output. The identity comes from
# RAMP_SSH_IDENTITY_FILE, not from Terraform - see lib/staging-env.sh.
load_ssh_cmd

# The rows seeded below are keyed by the smoke ids, and the services verify
# those identities' signatures by fetching https://<id>/.well-known/... — so
# an id that is not the hostname the stack serves is a guaranteed 401 later.
# Refuse to seed it.
require_ids_match_stack
# The tenant domain and the Exchange's EXCHANGE_DEFAULT_TENANT must be the
# same string, and the stack is the one place that derives it (its
# default_tenant_domain output). Reading it back here keeps the two tools
# from drifting: with an independent derivation, a deploy_edge = false stack
# seeded the tenant under the client hostname while the Exchange kept looking
# under demo.<domain>, and every agent Register failed. PUBLISHER_DOMAIN
# stays only as a fallback for a stack applied before the output existed.
PUBLISHER="$(tf_out default_tenant_domain 2>/dev/null || true)"
if [ -n "${PUBLISHER_DOMAIN:-}" ] && [ -n "${PUBLISHER}" ] && [ "${PUBLISHER_DOMAIN}" != "${PUBLISHER}" ]; then
    echo "PUBLISHER_DOMAIN (${PUBLISHER_DOMAIN}) does not match the stack's default_tenant_domain (${PUBLISHER})." >&2
    echo "Register looks the tenant up under default_tenant_domain, so seeding a different domain leaves every agent Register failing." >&2
    echo "Set default_tenant_domain in the stack tfvars, apply, then re-run without PUBLISHER_DOMAIN." >&2
    exit 2
fi
PUBLISHER="${PUBLISHER:-${PUBLISHER_DOMAIN:-}}"
if [ -z "${PUBLISHER}" ]; then
    echo "could not read default_tenant_domain from the stack — re-apply it, or pass PUBLISHER_DOMAIN=<publisher hostname>" >&2
    exit 2
fi
EXCHANGE_URL="$(tf_out exchange_url)"
EXCHANGE_DOMAIN="${EXCHANGE_URL#https://}"

# Public keys as hex for bytea literals (ramp.agents.public_key stores raw bytes).
pub_hex() {
    python3 - "$1" <<'PY'
import base64
import json
import sys

with open(sys.argv[1]) as f:
    pub = json.load(f)["public_key"]
print(base64.urlsafe_b64decode(pub + "=" * (-len(pub) % 4)).hex())
PY
}

CONTRIBUTOR_PUB_HEX="$(pub_hex "${KEYS_DIR}/contributor-key.json")"
AGENT_PUB_HEX="$(pub_hex "${KEYS_DIR}/agent-key.json")"
RELAY_PUB_HEX="$(pub_hex "${KEYS_DIR}/broker-relay-key.json")"

SQL_FILE="$(mktemp)"
TMP_FEED="$(mktemp)"
trap 'rm -f "${SQL_FILE}" "${TMP_FEED}"' EXIT

# The SQL references every operator-supplied value as a psql variable
# (:'name') — psql quotes those as SQL literals server-side, so no value is
# ever spliced into the SQL text and no quote in a value can change the
# statement. The heredoc is quoted on purpose: nothing interpolates here.
cat > "${SQL_FILE}" <<'EOSQL'
-- RAMP staging one-time seed (idempotent; re-runs are no-ops).
-- Tenant for the demo publisher domain; ed25519_key_ref matches the ref the
-- Exchange registers its loaded PEM under (RAMP_DEMO_ED25519_KEY_REF default).
INSERT INTO ramp.tenants (
    tenant_id, domain, ed25519_key_ref,
    reporting_policy, signing_scheme
) VALUES (:'tenant_id', :'publisher', 'exchange-primary', '{}', 'ED25519')
ON CONFLICT (tenant_id) DO NOTHING;

-- Broker-relayed ExecuteTransaction is opt-in per tenant.
UPDATE ramp.tenants SET allow_broker_relay = TRUE WHERE domain = :'publisher';

-- Signing identities: catalog contributor (ingest), smoke agent, and the
-- Broker outbound-relay key (must classify as BROKER for resolveCaller).
INSERT INTO ramp.agents (agent_id, public_key, requester_type)
VALUES (:'contributor_id', decode(:'contributor_pub_hex', 'hex'), 'AGENT')
ON CONFLICT (agent_id) DO UPDATE SET public_key = EXCLUDED.public_key;

INSERT INTO ramp.agents (agent_id, public_key, requester_type)
VALUES (:'agent_id', decode(:'agent_pub_hex', 'hex'), 'AGENT')
ON CONFLICT (agent_id) DO UPDATE SET public_key = EXCLUDED.public_key;

INSERT INTO ramp.agents (agent_id, public_key, requester_type)
VALUES (:'broker_relay_kid', decode(:'relay_pub_hex', 'hex'), 'BROKER')
ON CONFLICT (agent_id) DO UPDATE SET
    public_key = EXCLUDED.public_key,
    requester_type = EXCLUDED.requester_type;

-- Exchange row the Broker routes resolves through.
INSERT INTO broker.exchanges (
    exchange_id, domain, endpoint, trust_level,
    supported_profiles, priority, healthy
)
SELECT 'ex-staging', :'exchange_domain', :'exchange_url',
       'VERIFIED', '["ramp-news-v1"]'::jsonb, 10, TRUE
WHERE NOT EXISTS (
    SELECT 1 FROM broker.exchanges WHERE domain = :'exchange_domain'
);
EOSQL

PSQL_VARS=(
    -v "tenant_id=${TENANT_ID}"
    -v "publisher=${PUBLISHER}"
    -v "contributor_id=${CONTRIBUTOR_ID}"
    -v "agent_id=${AGENT_ID}"
    -v "broker_relay_kid=${BROKER_RELAY_KID}"
    -v "contributor_pub_hex=${CONTRIBUTOR_PUB_HEX}"
    -v "agent_pub_hex=${AGENT_PUB_HEX}"
    -v "relay_pub_hex=${RELAY_PUB_HEX}"
    -v "exchange_domain=${EXCHANGE_DOMAIN}"
    -v "exchange_url=${EXCHANGE_URL}"
)

echo "== one-time registration SQL (via ${SSH_CMD[*]}) =="
cat "${SQL_FILE}"
echo "-- with:"
for entry in "${PSQL_VARS[@]}"; do
    [ "${entry}" = "-v" ] || echo "--   ${entry}"
done
echo "=========================================================="

# printf %q shell-quotes every element for the remote command line, so the
# values are as safe in transit over ssh as they are inside the SQL.
"${SSH_CMD[@]}" \
    "sudo docker compose -f ${VM_COMPOSE_FILE} exec -T postgres psql -v ON_ERROR_STOP=1 $(printf '%q ' "${PSQL_VARS[@]}") -U ramp -d ramp" \
    < "${SQL_FILE}"

# The Exchange starts before this one-time SQL creates the default tenant, so
# its boot-time EXCHANGE_DEFAULT_AGENT_CREDIT write initially has no row to
# update. Restart after seeding and wait for health before Register; this keeps
# the boot path as the setting's sole owner and prevents a zero-credit race.
echo "== restart Exchange to apply boot-time tenant settings =="
"${SSH_CMD[@]}" \
    "sudo docker compose -f ${VM_COMPOSE_FILE} restart exchange >/dev/null && \
     sudo docker compose -f ${VM_COMPOSE_FILE} up -d --wait --wait-timeout 120 exchange"

echo "== ingest demo feed as ${CONTRIBUTOR_ID} (domain rewritten to ${PUBLISHER}) =="
sed "s|demo\.ramp-protocol\.org|${PUBLISHER}|g" "${FEED}" > "${TMP_FEED}"

# The exit status is the whole verdict: the Exchange stores or refuses a
# submission whole and the binary exits non-zero on any refusal, so there is
# no second signal to read off its report.
cd "${REPO_ROOT}"
if ! go run ./src/exchange/cmd/ramp-ingest \
    --exchange-url "${EXCHANGE_URL}" \
    --tenant "${TENANT_ID}" \
    --key "${KEYS_DIR}/contributor-key.json" \
    "${TMP_FEED}"; then
    echo "ingest failed — seed is NOT complete" >&2
    exit 1
fi

# The SQL above gives the smoke agent an identity, not a billing account. The
# billing_ref every ledger account id is derived from is minted only by the
# Register RPC, which also creates the agent's TigerBeetle account. Skip this
# and the paid leg is denied at authorize with "billing ref required", before a
# balance is ever consulted — so funding would credit an account the Exchange
# never touches. Idempotent: an already-registered agent gets its stored ref
# back and nothing changes.
echo "== register the smoke agent's billing account as ${AGENT_ID} =="
BILLING_REF="$(
    RAMP_STAGING_EXCHANGE_URL="${EXCHANGE_URL}" \
    RAMP_STAGING_AGENT_KEY="${KEYS_DIR}/agent-key.json" \
        uv run --project "${REPO_ROOT}/tests/e2e" \
        python "${REPO_ROOT}/tests/e2e/register_staging_agent.py"
)"
if [ -z "${BILLING_REF}" ]; then
    echo "register returned no billing_ref — seed is NOT complete" >&2
    exit 1
fi

echo "seed complete: tenant ${TENANT_ID} (${PUBLISHER}) + demo feed on ${EXCHANGE_URL}"
echo "  smoke agent billing_ref: ${BILLING_REF}"
echo "next: agent-balances.sh — verify the configured welcome credit; fund manually if the balance is zero"
