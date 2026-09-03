#!/usr/bin/env bash
# Lists the article URLs currently stored in the deployed Exchange catalog.
# READ-ONLY: this runs one SELECT through the stack's existing SSH path.
#
# Env (optional):
#   STACK_DIR    default deploy/terraform/stacks/staging-aws
#
# Usage:
#   deploy/terraform/scripts/catalog-articles.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }

load_ssh_cmd

LIST_SQL="SELECT tenant_id AS tenant, uri AS article, jsonb_array_length(terms) AS terms, updated_at FROM ramp.catalog ORDER BY updated_at DESC, tenant_id, uri LIMIT 100;"

echo "== list catalog articles (read-only, via ${SSH_CMD[*]}) =="
echo "${LIST_SQL}"
"${SSH_CMD[@]}" \
    "sudo docker compose -f ${VM_COMPOSE_FILE} exec -T postgres \
        psql -P pager=off -v ON_ERROR_STOP=1 -U ramp -d ramp -c $(printf '%q' "${LIST_SQL}")"
