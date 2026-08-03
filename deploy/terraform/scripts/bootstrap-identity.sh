#!/usr/bin/env bash
# One-time identity bootstrap: provisions the OIDC client the Identity Service
# signs developers in with, and starts the service on it.
#
# The Identity Service reads its upstream OIDC client id and secret from files
# in a volume it shares with Zitadel. Nothing creates those files at apply
# time — Zitadel has to be running first — so the service crash-loops until
# this script runs. That is expected on a fresh stack, not a failure.
#
# Why this is an SSH step rather than a container in the bundle:
#
#   * The provisioning script it runs (scripts/zitadel-bootstrap.sh) is ~18 KB.
#     Cloud-init user data is capped at 16 KB gzipped for the WHOLE bundle, so
#     shipping it in the VM's user data is not an option.
#   * Zitadel returns a client secret only when it creates or regenerates one,
#     never on read. A one-shot container that re-ran on every reboot would mint
#     a new secret each time and leave the running Identity Service holding a
#     stale one — an authentication failure with no obvious cause. Running the
#     step by hand, guarded, keeps the secret stable.
#
# Re-running is safe: the script stops before provisioning when the client
# already exists. FORCE=1 overrides that, which DOES rotate the secret — the
# Identity Service is restarted here to pick it up, so use it when the secret
# is believed lost, not routinely.
#
# Prerequisites: stack applied, images pushed, DNS live, and Caddy holding a
# certificate for the Zitadel hostname (this script waits for that).
#
# Env (all optional):
#   STACK_DIR         default deploy/terraform/stacks/staging-aws
#   FORCE             1 to re-provision even when the client exists (rotates
#                     the secret)
#   ALICE_PASSWORD    password for the local sign-in user the provisioning
#                     creates. Generated and printed when unset. Only applies
#                     on the run that creates the user.
#   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
#                     enable Google as a federated identity provider; omitted
#                     leaves local sign-in as the only option
#   WAIT_SECONDS      how long to wait for Zitadel and then for the Identity
#                     Service to come up (default 300 each)
#
# Usage:
#   deploy/terraform/scripts/bootstrap-identity.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"

BOOTSTRAP_SRC="${REPO_ROOT}/scripts/zitadel-bootstrap.sh"
VM_BOOTSTRAP="/opt/ramp/zitadel-bootstrap.sh"
BOOTSTRAP_VOLUME="${VM_COMPOSE_PROJECT}_zitadelbootstrap"
COMPOSE_NETWORK="${VM_COMPOSE_PROJECT}_default"
CURL_IMAGE="curlimages/curl:8.11.1"
WAIT_SECONDS="${WAIT_SECONDS:-300}"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "missing: curl" >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo "missing: openssl" >&2; exit 2; }
[ -f "${BOOTSTRAP_SRC}" ] || { echo "missing: ${BOOTSTRAP_SRC}" >&2; exit 2; }

# The image ships an entrypoint and a non-root default user. Both have to go:
# the entrypoint would swallow the command, and the bootstrap volume is owned
# by root, so a non-root process could not write the client credentials into
# it. Kept in one place so the two docker run calls below cannot disagree.
CURL_RUN=(--entrypoint sh --user 0)

# The stack's ssh_command output is the one place that knows how to reach the
# VM — it carries -i <key> when ssh_private_key_path is set in tfvars.
read -r -a SSH_CMD <<< "$(tf_out ssh_command)"
IDENTITY_URL="$(tf_out identity_url)"
ZITADEL_URL="$(tf_out zitadel_url)"
ZITADEL_HOST="${ZITADEL_URL#https://}"

# Wait for a status code, not for connectivity: while Caddy is still issuing
# the certificate curl fails outright, and a bare `curl -f` loop would report
# that as an indistinguishable failure at the end.
wait_for_http() { # wait_for_http <label> <url> <accepted code>
    local label="$1" url="$2" want="$3" waited=0 code
    echo "== waiting for ${label} (${url}) =="
    while [ "${waited}" -lt "${WAIT_SECONDS}" ]; do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "${url}" || true)"
        if [ "${code}" = "${want}" ]; then
            echo "   ${label}: ready (${code}) after ${waited}s"
            return 0
        fi
        sleep 10
        waited=$((waited + 10))
    done
    echo "${label} did not answer ${want} within ${WAIT_SECONDS}s (last: ${code:-no response})" >&2
    echo "check DNS, the Caddy certificate for ${label}, and 'docker compose logs' on the VM" >&2
    exit 1
}

# Already provisioned? The client id file only exists once the provisioning
# below has succeeded, so it is the honest marker. Read it through a throwaway
# container: the volume belongs to Docker, and no service in the bundle has a
# shell to inspect it with.
client_exists() {
    "${SSH_CMD[@]}" \
        "sudo docker run --rm ${CURL_RUN[*]} -v ${BOOTSTRAP_VOLUME}:/bootstrap ${CURL_IMAGE} -c 'test -f /bootstrap/identity_client_id'" \
        >/dev/null 2>&1
}

if [ "${FORCE:-0}" != "1" ] && client_exists; then
    echo "OIDC client already provisioned — nothing to do."
    echo "The Identity Service reads it from the ${BOOTSTRAP_VOLUME} volume on every start."
    echo "To mint a NEW client secret (and restart the service onto it): FORCE=1 $0"
    exit 0
fi

# The OIDC discovery document rather than a Zitadel-specific health path: it
# is the thing the Identity Service itself will fetch, so a 200 here proves
# what the next steps actually depend on — Zitadel serving, DNS resolving, and
# Caddy holding a certificate for the hostname.
wait_for_http "zitadel" "${ZITADEL_URL}/.well-known/openid-configuration" 200

# Zitadel's password policy wants all four character classes; the suffix
# guarantees them whatever the random part happens to contain.
ALICE_PASSWORD="${ALICE_PASSWORD:-$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9')Aa1!}"

echo "== upload provisioning script =="
# Piped over the existing ssh connection rather than scp'd: ssh_command is a
# whole command line, and rewriting it into scp's argument shape is a parsing
# job with no upside.
"${SSH_CMD[@]}" "sudo tee ${VM_BOOTSTRAP} >/dev/null && sudo chmod 0600 ${VM_BOOTSTRAP}" < "${BOOTSTRAP_SRC}"

# Provisioning runs INSIDE the compose network, dialling Zitadel directly at
# http://zitadel:8080. It sends the public hostname as the Host header because
# Zitadel routes instances by that, not by the address dialled — the two differ
# here on purpose, and it means bootstrapping does not depend on the public
# certificate being valid, only on Zitadel being up.
BOOTSTRAP_ENV=(
    -e "ZITADEL_BASE_URL=http://zitadel:8080"
    -e "ZITADEL_INSTANCE_HOST=${ZITADEL_HOST}"
    -e "ZITADEL_ISSUER=${ZITADEL_URL}"
    -e "IDENTITY_AUTH_ISSUER=${IDENTITY_URL}"
    -e "OUT_DIR=/bootstrap"
    -e "ALICE_PASSWORD=${ALICE_PASSWORD}"
)
if [ -n "${GOOGLE_CLIENT_ID:-}" ] && [ -n "${GOOGLE_CLIENT_SECRET:-}" ]; then
    echo "   (Google federation enabled)"
    BOOTSTRAP_ENV+=(
        -e "GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}"
        -e "GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}"
    )
fi

echo "== provision the OIDC client (redirect URI ${IDENTITY_URL}/callback) =="
# printf %q shell-quotes every element for the remote command line, so a
# password or secret cannot break out of it.
"${SSH_CMD[@]}" \
    "sudo docker run --rm ${CURL_RUN[*]} --network ${COMPOSE_NETWORK} \
        -v ${BOOTSTRAP_VOLUME}:/bootstrap \
        -v ${VM_BOOTSTRAP}:/bootstrap.sh:ro \
        $(printf '%q ' "${BOOTSTRAP_ENV[@]}") \
        ${CURL_IMAGE} /bootstrap.sh" >/dev/null

client_exists || {
    echo "provisioning finished but /bootstrap/identity_client_id is absent — the Identity Service cannot start" >&2
    exit 1
}

echo "== restart the Identity Service onto the new client =="
# force-recreate rather than restart: the credentials are read once at startup,
# and a recreate is the unambiguous way to get a process that has read them.
"${SSH_CMD[@]}" "sudo docker compose -f ${VM_COMPOSE_FILE} up -d --force-recreate identity" >/dev/null

wait_for_http "identity" "${IDENTITY_URL}/healthz" 200

echo
echo "identity bootstrap complete."
echo "  MCP endpoint:     ${IDENTITY_URL}/mcp"
echo "  developer sign-up: ${IDENTITY_URL}"
echo "  Zitadel console:  ${ZITADEL_URL} (user zadmin — 'terraform -chdir=${STACK_DIR} output -raw zitadel_admin_password')"
echo "  local sign-in user: alice@acme.local / ${ALICE_PASSWORD}"
echo
echo "The sign-in password above is set only on the run that creates the user;"
echo "record it now, or reset it later from the Zitadel console."
