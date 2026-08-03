#!/usr/bin/env bash
# Staging smoke check: service health over public HTTPS, then the full
# discover -> execute -> signed-URL -> edge -> origin proof
# (tests/e2e/smoke_staging.py), including a no-proof-of-possession fetch
# that must be refused. The proof covers licensing, delivery, and edge
# enforcement; it does not assert billing behavior (the stack merely runs
# with the tigerbeetle adapter configured).
#
# The Identity Service is checked for liveness and for its MCP endpoint being
# gated, but no leg drives a tool call THROUGH that endpoint: doing so needs an
# OAuth bearer, which means completing developer sign-up. The end-to-end proof
# below signs Broker calls directly with the local agent key instead.
#
# Env (optional):
#   STACK_DIR         default deploy/terraform/stacks/staging-aws
#   AGENT_ID          default from lib/staging-env.sh (shared with key
#                     generation and seeding so the id can never drift apart)
#   PUBLISHER_DOMAIN  publisher hostname to smoke against. Default: the
#                     stack's own edge-fronted hostname (publisher_hostname
#                     output). Set it to smoke a client publisher fronted by
#                     a separately applied stacks/edge (deploy_edge = false
#                     mode) — the hostname must be seeded first, see
#                     seed-staging.sh.
#   RAMP_STAGING_ENFORCE_BINDING
#                     "true"/"false" override for the bare-fetch expectation.
#                     Default: read back from the stack's ramp_enforce_binding
#                     output, so the expectation follows the deployment —
#                     "true" expects the bare fetch refused (403), "false"
#                     expects it delivered (200). Set it only when smoking a
#                     separately applied stacks/edge (deploy_edge = false),
#                     where the stack has no edge posture to read; unset
#                     there, the smoke assumes "true" (the module default).
#
# Usage:
#   deploy/terraform/scripts/smoke.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "missing: curl" >&2; exit 2; }
command -v uv >/dev/null 2>&1 || { echo "missing: uv" >&2; exit 2; }

EXCHANGE_URL="$(tf_out exchange_url)"
BROKER_URL="$(tf_out broker_url)"
IDENTITY_URL="$(tf_out identity_url)"
# With deploy_edge = false the publisher_hostname output is null and tf_out
# fails — in that mode the hostname to smoke MUST come from PUBLISHER_DOMAIN.
PUBLISHER="${PUBLISHER_DOMAIN:-$(tf_out publisher_hostname 2>/dev/null || true)}"
if [ -z "${PUBLISHER}" ]; then
    echo "the stack has no edge-fronted hostname (deploy_edge = false) — pass PUBLISHER_DOMAIN=<client hostname>" >&2
    exit 2
fi
# The bare-fetch expectation follows the deployment: read the deployed edge's
# posture back from the stack. With deploy_edge = false the output is null and
# tf_out fails — fall back to "true" (the module default posture), overridable
# via RAMP_STAGING_ENFORCE_BINDING for a stacks/edge applied with "false".
ENFORCE_BINDING="$(tf_out ramp_enforce_binding 2>/dev/null || echo "true")"

# Every leg captures the status and fails loudly on mismatch. A bare
# `curl -fsS url && echo ok` would NOT stop the script: under `set -e` a
# failure on the left side of && is exempt, so a downed service would be
# silently skipped and the smoke would keep going.
check_http() { # check_http <label> <url> <accepted codes...>
    local label="$1" url="$2" code want
    shift 2
    code="$(curl -s -o /dev/null -w '%{http_code}' "${url}")"
    for want in "$@"; do
        if [ "${code}" = "${want}" ]; then
            echo "${label}: ok (${code})"
            return 0
        fi
    done
    echo "${label}: unhealthy — ${url} returned ${code}, wanted $*" >&2
    exit 1
}

echo "== healthz =="
check_http "exchange" "${EXCHANGE_URL}/healthz" 200
check_http "broker" "${BROKER_URL}/healthz" 200
# A 503 here is the Identity Service reporting its database is unreachable; a
# connection failure usually means it never started, which on a fresh stack
# means bootstrap-identity.sh has not run yet.
check_http "identity" "${IDENTITY_URL}/healthz" 200

echo "== identity MCP endpoint =="
# 401 is the PASSING result: the endpoint is mounted and its bearer gate is
# active. Asserting it (rather than accepting any answer) makes this a
# negative-path check — a 200 would mean the MCP tools, which sign RAMP calls
# with a developer's custodied key, are reachable by anyone.
check_http "mcp bearer gate" "${IDENTITY_URL}/mcp" 401
# Served outside the gate on purpose: it is how an MCP client that met that
# 401 discovers which authorization server to sign in against.
check_http "mcp discovery" "${IDENTITY_URL}/.well-known/oauth-protected-resource" 200

echo "== edge manifest =="
check_http "edge ramp.json" "https://${PUBLISHER}/.well-known/ramp.json" 200

echo "== end-to-end proof =="
RAMP_STAGING_EXCHANGE_URL="${EXCHANGE_URL}" \
RAMP_STAGING_BROKER_URL="${BROKER_URL}" \
RAMP_STAGING_PUBLISHER="${PUBLISHER}" \
RAMP_STAGING_AGENT_ID="${AGENT_ID}" \
RAMP_STAGING_AGENT_KEY="${KEYS_DIR}/agent-key.json" \
RAMP_STAGING_ENFORCE_BINDING="${RAMP_STAGING_ENFORCE_BINDING:-${ENFORCE_BINDING}}" \
    uv run --project "${REPO_ROOT}/tests/e2e" python "${REPO_ROOT}/tests/e2e/smoke_staging.py"
