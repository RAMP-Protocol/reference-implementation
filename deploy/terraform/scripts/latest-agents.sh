#!/usr/bin/env bash
# Lists developer-created agent identities, newest first.
# READ-ONLY: this runs one SELECT through the stack's existing SSH path.
#
# Env (optional):
#   STACK_DIR    default deploy/terraform/stacks/staging-aws
#
# Usage:
#   deploy/terraform/scripts/latest-agents.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }

load_ssh_cmd

LIST_SQL="SELECT email, subdomain, created_at FROM identity.developer_account ORDER BY created_at DESC;"

echo "== list developer-created agents (read-only, via ${SSH_CMD[*]}) =="
echo "${LIST_SQL}"
"${SSH_CMD[@]}" \
    "sudo docker compose -f ${VM_COMPOSE_FILE} exec -T postgres \
        psql -P pager=off -v ON_ERROR_STOP=1 -U ramp -d identity -c $(printf '%q' "${LIST_SQL}")"
