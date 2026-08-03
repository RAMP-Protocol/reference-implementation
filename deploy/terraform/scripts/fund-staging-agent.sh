#!/usr/bin/env bash
# Adds prepaid test money to the smoke agent's TigerBeetle account, so the
# paid articles in the demo feed can actually be bought (the smoke check's
# canary article costs a flat 9.99 EUR per run).
#
# A freshly deployed stack starts with an EMPTY ledger. There is no API to add
# money on purpose: per ADR-009 D2 balance is created only by an operator's
# manual credit into TigerBeetle. This script IS that manual credit for
# staging — the ledger analogue of seed-staging.sh's documented one-time SQL.
# The commands are printed in full before they run, never hidden.
#
# How it works: account and transfer ids in TigerBeetle are derived
# deterministically (low 16 bytes of sha256, little-endian — the same
# derivation as src/exchange/internal/billing/tigerbeetle/ids.go), so this
# script computes them locally and posts one settled credit transfer from a
# staging "liquidity" source account into the agent's account, using the
# `tigerbeetle repl` client inside the running tigerbeetle container over SSH.
#
# The agent's account id is derived from its BILLING_REF, not its agent id.
# The billing_ref is a random handle the Exchange mints at Register and stores
# on the agent's row; it is the only string the Exchange ever hashes into an
# account id. Funding an account derived from the agent id would credit money
# nothing will ever debit. Because the ref is random it cannot be computed
# locally, so this script asks the Exchange for it through the same Register
# RPC the seed step used — Register is idempotent, so re-asking returns the
# already-minted ref and changes nothing.
#
# Safe to re-run: the transfer id is derived from (billing_ref, amount, label),
# so running it again with the same values is a no-op (TigerBeetle rejects the
# duplicate id; the balance is not doubled). To add MORE money later, set a
# new FUND_LABEL (e.g. FUND_LABEL=topup-2026-08-01).
#
# Env (all optional):
#   STACK_DIR    default deploy/terraform/stacks/staging-aws
#   BILLING_REF  skip the Register lookup and fund this ref directly. For
#                recovering a specific account; normally leave it unset.
#   AMOUNT       euros to add, decimal string, default 100
#   FUND_LABEL   names this top-up, default "initial" — change it to top up again
#   LEDGER       TigerBeetle ledger id, default 978 (EUR). MUST match the
#                stack's billing_ledger tfvar (also 978 by default) — a
#                mismatch would create the account on the wrong ledger and
#                break the Exchange's own account creation with a conflict.
#
# There is deliberately no AGENT_ID setting: the funded account is whichever
# one the key at keys/agent-key.json is registered under — the Register call
# is signed with that key, and the Exchange resolves the caller from the
# signature, not from any name this script could pass.
#
# Usage:
#   deploy/terraform/scripts/fund-staging-agent.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"
AMOUNT="${AMOUNT:-100}"
FUND_LABEL="${FUND_LABEL:-initial}"
LEDGER="${LEDGER:-978}"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "missing: python3" >&2; exit 2; }
command -v uv >/dev/null 2>&1 || { echo "missing: uv" >&2; exit 2; }

read -r -a SSH_CMD <<< "$(tf_out ssh_command)"

# The account handle to fund. Asking Register is a no-op for an agent the seed
# step already registered — it returns the stored ref (ADR-021 D4, "the stored
# id wins"). It fails loudly if the agent was never seeded, which is the right
# outcome: there is no account to fund yet.
if [ -z "${BILLING_REF:-}" ]; then
    echo "== resolve the smoke agent's billing_ref =="
    BILLING_REF="$(
        RAMP_STAGING_EXCHANGE_URL="$(tf_out exchange_url)" \
        RAMP_STAGING_AGENT_KEY="${KEYS_DIR}/agent-key.json" \
            uv run --project "${REPO_ROOT}/tests/e2e" \
            python "${REPO_ROOT}/tests/e2e/register_staging_agent.py"
    )"
fi
if [ -z "${BILLING_REF}" ]; then
    echo "could not resolve the smoke agent's billing_ref — run seed-staging.sh first" >&2
    exit 2
fi
# Register mints refs with uuid.NewString, so anything else here is not a real
# account handle — most likely stray stdout from the resolver or a mistyped
# override. Without this check the garbage would be sha256'd into a valid-looking
# account id and funded successfully, stranding the money in an account the
# Exchange never debits.
if ! [[ "${BILLING_REF}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
    echo "billing_ref does not look like the UUID Register mints: '${BILLING_REF}'" >&2
    exit 2
fi

# Derive the ids and the integer amount locally. The Exchange stores amounts
# at asset scale 8 (10^8 minor units per euro — see tigerbeetle_adapter.go),
# and account ids as the little-endian low 16 bytes of sha256(prefix || id).
IDS="$(python3 - "${BILLING_REF}" "${AMOUNT}" "${FUND_LABEL}" <<'PY'
import hashlib
import sys
from decimal import Decimal, InvalidOperation

billing_ref, amount, label = sys.argv[1:4]

def tb_id(s: str) -> int:
    return int.from_bytes(hashlib.sha256(s.encode()).digest()[:16], "little")

try:
    minor = Decimal(amount).scaleb(8)
except InvalidOperation:
    sys.exit(f"AMOUNT is not a decimal number: {amount!r}")
if minor != minor.to_integral_value() or minor <= 0:
    sys.exit(f"AMOUNT must be positive with at most 8 decimal places: {amount!r}")

print(f"AGENT_ACC={tb_id('agent:' + billing_ref)}")
print(f"LIQ_ACC={tb_id('platform:liquidity')}")
print(f"TRANSFER={tb_id(f'staging-fund:{billing_ref}:{amount}:{label}')}")
print(f"MINOR={int(minor)}")
PY
)"
eval "${IDS}"

# The four ledger commands, in order:
#
#   1. Create the "liquidity" account — the money source. TigerBeetle is a
#      double-entry ledger: money never appears from nowhere, every credit to
#      one account must be a debit from another. This account is that other
#      side. It starts at zero and goes negative by the amount handed out,
#      which is allowed for it (no spending limit flag) and is the normal
#      shape for an operator funding account.
#   2. Create the agent's account — prepaid: the flag forbids spending more
#      than was put in.
#   3. Move the money from 1 into 2. The only command that changes a balance.
#   4. Read the agent's account back — the check at the bottom of this script
#      parses this answer to confirm the money is really there.
#
# The codes and flags copy the Exchange adapter exactly (ids.go,
# DefaultFlagsForCode: code 1 = agent prepaid account, code 3 = platform
# account). The agent's account normally exists already — Register creates it
# when it mints the billing_ref — so create_accounts here answers "already
# exists" and that is expected, not a failure. It stays in the batch because
# whichever side runs first must win, and the fields match exactly either way.
STMTS=(
    "create_accounts id=${LIQ_ACC} ledger=${LEDGER} code=3 flags=history;"
    "create_accounts id=${AGENT_ACC} ledger=${LEDGER} code=1 flags=debits_must_not_exceed_credits;"
    "create_transfers id=${TRANSFER} debit_account_id=${LIQ_ACC} credit_account_id=${AGENT_ACC} amount=${MINOR} ledger=${LEDGER} code=1;"
    "lookup_accounts id=${AGENT_ACC};"
)

echo "== funding the smoke agent's account (billing_ref ${BILLING_REF}) with ${AMOUNT} EUR (label: ${FUND_LABEL}) =="
echo "== ledger commands (via ${SSH_CMD[*]}) =="
printf '%s\n' "${STMTS[@]}"
echo "=========================================================="

# The repl is interactive-only in this TigerBeetle version (it refuses a
# piped stdin with "ANSI escape sequences not supported"), so each statement
# goes through its non-interactive --command flag instead — which runs
# exactly ONE statement per invocation, hence one repl call per statement,
# all in a single SSH session. Statements are joined with ';' on purpose:
# "already exists" answers are EXPECTED on re-runs (accounts on every run,
# the transfer when this exact top-up already happened), so a failed create
# must not stop the batch — the balance check below is the real verdict.
REPL="sudo docker compose -f ${VM_COMPOSE_FILE} exec -T tigerbeetle /tigerbeetle repl --cluster=0 --addresses=3000"
REMOTE=""
for stmt in "${STMTS[@]}"; do
    REMOTE+="${REPL} --command=\"${stmt}\"; "
done
REPL_OUT="$("${SSH_CMD[@]}" "${REMOTE}" 2>&1)"
echo "${REPL_OUT}"

# The lookup at the end of the batch reports the agent account as it is NOW.
# credits_posted must be > 0 (money arrived, this run or an earlier one);
# print the spendable balance so the operator knows how many smoke runs are
# left. Exits non-zero if the account is missing or still empty. The output
# is handed over via the environment — never spliced into the code.
REPL_OUT="${REPL_OUT}" python3 - <<'PY'
import os
import re
import sys
from decimal import Decimal

out = os.environ["REPL_OUT"]
def field(name: str) -> Decimal:
    m = re.search(rf'"{name}":\s*"?(\d+)"?', out)
    if m is None:
        sys.exit(f"could not find {name} in the ledger answer — funding NOT confirmed")
    return Decimal(m.group(1))

balance = (field("credits_posted") - field("debits_posted")).scaleb(-8)
if field("credits_posted") <= 0:
    sys.exit("agent account still has no money — funding FAILED")
print(f"agent balance is now {balance.normalize():f} EUR")
PY
