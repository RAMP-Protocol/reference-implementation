#!/usr/bin/env bash
# Reports every registered agent's prepaid balance. READ-ONLY: it lists agents
# and looks their ledger accounts up, and posts no transfer.
#
# WHY A SCRIPT AND NOT A REQUEST. Nothing serves this number over HTTP. The MCP
# ramp_status tool reports the account handle and whether the account is active,
# and no more. The Exchange has no balance RPC, and no production code path reads
# a balance at all — the billing adapter's GetBalance port exists but the service
# never calls it. So TigerBeetle is the only place the figure lives, and this
# reads it the same way fund-staging-agent.sh verifies its own work.
#
# That is a consequence of the operator-mediated balance policy, not an oversight
# (per ADR-009 D2 and its 2026-08-13 amendment): an operator adds money out of
# band, and the only service-side credit is the tenant-configured default the
# Register flow grants. An agent that wants to see its own balance has nowhere to
# ask, which is worth knowing before a demo where someone asks.
#
# How it works: reads every non-null billing_ref from the Exchange's ramp.agents
# table over SSH — the same read-only operator-SQL path the funding sweep uses —
# then derives each ledger account id and asks TigerBeetle for it. The derivation
# matches the Exchange adapter and the funding script exactly: the little-endian
# low 16 bytes of sha256("agent:" || billing_ref). Amounts are stored at asset
# scale 8, so 10^8 minor units make one euro.
#
# Env (all optional):
#   STACK_DIR    default deploy/terraform/stacks/staging-aws
#
# Usage:
#   deploy/terraform/scripts/agent-balances.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "missing: python3" >&2; exit 2; }

load_ssh_cmd

LIST_SQL="SELECT DISTINCT billing_ref FROM ramp.agents WHERE billing_ref IS NOT NULL ORDER BY billing_ref;"
echo "== list registered agents (read-only, via ${SSH_CMD[*]}) =="
echo "${LIST_SQL}"
REFS="$("${SSH_CMD[@]}" \
    "sudo docker compose -f ${VM_COMPOSE_FILE} exec -T postgres \
        psql -tA -v ON_ERROR_STOP=1 -U ramp -d ramp -c '${LIST_SQL}'")"

if [ -z "${REFS}" ]; then
    echo "no agent has a billing_ref yet — agents get one at Register"
    exit 0
fi

# Into arrays FIRST, then loop over them: the loop below runs ssh, and ssh
# forwards its stdin to the remote command, so a loop feeding refs through its
# own stdin would have the remaining refs eaten by the first child. This
# read-loop is safe because it runs no child that reads stdin. (Built without
# mapfile on purpose — macOS ships bash 3.2.)
REFS_LIST=()
ACCS=()
while IFS= read -r ref; do
    [ -n "${ref}" ] || continue
    REFS_LIST+=("${ref}")
    ACCS+=("$(python3 -c \
        "import hashlib,sys; print(int.from_bytes(hashlib.sha256(('agent:'+sys.argv[1]).encode()).digest()[:16],'little'))" \
        "${ref}")")
done <<< "${REFS}"

# One repl invocation per account: the repl is interactive-only in this
# TigerBeetle version — it refuses a piped stdin with "ANSI escape sequences not
# supported" — so each statement goes through its non-interactive --command flag,
# which runs exactly one statement per call. All of them share one SSH session.
REPL="sudo docker compose -f ${VM_COMPOSE_FILE} exec -T tigerbeetle /tigerbeetle repl --cluster=0 --addresses=3000"
REMOTE=""
for acc in "${ACCS[@]}"; do
    REMOTE+="${REPL} --command=\"lookup_accounts id=${acc};\"; "
done
echo "== read ${#ACCS[@]} ledger account(s) =="
REPL_OUT="$("${SSH_CMD[@]}" "${REMOTE}" 2>&1)"

# Pairs, so the parser matches each answer to its agent by ACCOUNT ID rather than
# by position. The repl prints a connection log line before every answer, and an
# account that does not exist produces no object at all — so counting answers
# against the input order would silently shift each later row onto the wrong
# agent.
PAIRS=""
for i in "${!REFS_LIST[@]}"; do
    PAIRS+="${REFS_LIST[$i]}=${ACCS[$i]} "
done

# The repl output reaches python through the ENVIRONMENT, not a pipe: the heredoc
# is itself a stdin redirection and would override any pipe on this command,
# leaving the program to read its own source as input. PAIRS is unquoted on
# purpose: it must word-split into one argument per agent.
REPL_OUT="${REPL_OUT}" python3 - ${PAIRS} <<'PY'
import json
import os
import re
import sys
from decimal import Decimal

pairs = [a.split("=", 1) for a in sys.argv[1:]]
text = os.environ["REPL_OUT"]

# The repl answers with one JSON object per account, every number quoted as a
# string, preceded by a connection log line. Pull the objects out and key them by
# the id they report rather than by the order they arrive in.
found = {}
for match in re.finditer(r'\{[^{}]*"credits_posted"[^{}]*\}', text, re.S):
    try:
        account = json.loads(match.group(0))
    except json.JSONDecodeError:
        continue
    # Asset scale 8: 10^8 minor units per euro.
    found[account["id"]] = (
        Decimal(account["credits_posted"]) - Decimal(account["debits_posted"])
    ).scaleb(-8)

print()
print("%-40s %16s" % ("BILLING_REF", "BALANCE (EUR)"))
missing = 0
for ref, account_id in pairs:
    balance = found.get(account_id)
    if balance is None:
        # "no account" rather than 0.00 on purpose. An account that was never
        # created and one holding nothing are different facts, and only the first
        # means the agent has never been funded.
        missing += 1
        print("%-40s %16s" % (ref, "no account"))
    else:
        print("%-40s %16s" % (ref, f"{balance:.2f}"))

print()
print("%d agent(s); %d with no ledger account" % (len(pairs), missing))
PY
