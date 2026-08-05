#!/usr/bin/env bash
# Adds prepaid test money to EVERY registered agent's account — the sweep
# variant of fund-staging-agent.sh, for demo sessions where people sign up
# through the Identity Service and their fresh agents need a balance without
# a per-agent command.
#
# Per the operator-only balance policy this stays operator tooling: the
# operator runs it, the commands are printed before they run, and no service
# ever credits an account on its own. It is safe to re-run at any moment —
# during a demo, on a loop — because each credit's transfer id is derived
# from (billing_ref, amount, label), exactly as in fund-staging-agent.sh:
# agents already funded under this label are no-ops, newly signed-up agents
# get their money. To top everyone up a second time, change FUND_LABEL.
#
# How it works: reads every non-null billing_ref from the Exchange's
# ramp.agents table over SSH (the same documented operator-SQL path the seed
# step uses, read-only here), then runs fund-staging-agent.sh once per agent
# with BILLING_REF set — all ledger mechanics, validation, and the balance
# check live there, in one place.
#
# Env (all optional):
#   STACK_DIR    default deploy/terraform/stacks/staging-aws
#   AMOUNT       euros to add per agent, default 100
#   FUND_LABEL   names this sweep, default "welcome" — change it to top up again
#   LEDGER       passed through to fund-staging-agent.sh (default there: 978)
#
# Usage:
#   deploy/terraform/scripts/fund-all-agents.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"
FUND_LABEL="${FUND_LABEL:-welcome}"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }

read -r -a SSH_CMD <<< "$(tf_out ssh_command)"

LIST_SQL="SELECT DISTINCT billing_ref FROM ramp.agents WHERE billing_ref IS NOT NULL ORDER BY billing_ref;"
echo "== list registered agents (read-only, via ${SSH_CMD[*]}) =="
echo "${LIST_SQL}"
REFS="$("${SSH_CMD[@]}" \
    "sudo docker compose -f ${VM_COMPOSE_FILE} exec -T postgres \
        psql -tA -v ON_ERROR_STOP=1 -U ramp -d ramp -c '${LIST_SQL}'")"

if [ -z "${REFS}" ]; then
    echo "no agent has a billing_ref yet — nothing to fund (agents get one at Register)"
    exit 0
fi

# Into an array FIRST, then loop over the array: the child runs ssh, and
# ssh forwards its stdin to the remote command — a loop feeding refs through
# its own stdin would have the remaining refs eaten by the first child,
# ending the sweep after one agent while still reporting success. This
# read-loop is safe because it runs no child; it only fills the array.
# (Built without mapfile on purpose — macOS ships bash 3.2.)
AGENT_REFS=()
while IFS= read -r ref; do
    AGENT_REFS+=("${ref}")
done <<< "${REFS}"
COUNT="${#AGENT_REFS[@]}"
echo "found ${COUNT} agent account(s); funding each with label '${FUND_LABEL}'"

FAILED=0
for ref in "${AGENT_REFS[@]}"; do
    echo
    echo "──── agent ${ref} ────"
    # fund-staging-agent.sh validates the ref shape, prints the ledger
    # commands, posts the idempotent transfer, and verifies the balance.
    # stdin is closed explicitly so the child's ssh cannot read the
    # operator's terminal.
    if ! BILLING_REF="${ref}" FUND_LABEL="${FUND_LABEL}" \
        "$(dirname "${BASH_SOURCE[0]}")/fund-staging-agent.sh" < /dev/null; then
        echo "FAILED for ${ref} — continuing with the rest" >&2
        FAILED=$((FAILED + 1))
    fi
done

echo
if [ "${FAILED}" -gt 0 ]; then
    echo "sweep finished: ${FAILED} of ${COUNT} account(s) FAILED — see above" >&2
    exit 1
fi
echo "sweep finished: all ${COUNT} account(s) funded (label '${FUND_LABEL}')"
