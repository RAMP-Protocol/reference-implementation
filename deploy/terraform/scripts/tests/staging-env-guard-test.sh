#!/usr/bin/env bash
# Prove require_ids_match_stack does its one job: fail loudly when the smoke
# key kids and the applied stack's directory hostnames disagree, stay silent
# when they agree, and fail with the re-apply hint when the stack exports no
# hostname outputs. A guard that exists to fire has to be SEEN firing — a
# guard nobody has watched fail is indistinguishable from a broken one. The
# harness stubs `terraform` on PATH (env-controlled outputs) and fabricates
# key files in a temporary stack directory, then drives the guard through
# lib/staging-env.sh exactly the way smoke.sh and seed-staging.sh do.
#
# Run directly, or via test-terraform.sh (which wires it into the suite).
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mkdir -p "${work}/bin" "${work}/stack/keys"
cat > "${work}/bin/terraform" <<'EOF'
#!/usr/bin/env bash
# Stub for `terraform -chdir=<dir> output -raw <name>`: prints the
# env-controlled value for the two hostname outputs, exits 1 (like a stack
# applied without them) when the value is empty or the output is unknown.
name="${!#}"
case "${name}" in
    smoke_agent_hostname)         [ -n "${STUB_AGENT_HOST:-}" ] && echo "${STUB_AGENT_HOST}" || exit 1 ;;
    catalog_contributor_hostname) [ -n "${STUB_CONTRIB_HOST:-}" ] && echo "${STUB_CONTRIB_HOST}" || exit 1 ;;
    *) exit 1 ;;
esac
EOF
chmod +x "${work}/bin/terraform"

printf '{"kid": "smoke-agent.zone.example"}\n' > "${work}/stack/keys/agent-key.json"
printf '{"kid": "catalog-contributor.zone.example"}\n' > "${work}/stack/keys/contributor-key.json"

# run_guard <agent-host> <contrib-host> → the guard's exit status, in a
# subshell wired the way the consumer scripts are (stub terraform first on
# PATH, STACK_DIR at the fabricated stack).
run_guard() {
    (
        export PATH="${work}/bin:${PATH}"
        export STACK_DIR="${work}/stack"
        export STUB_AGENT_HOST="$1" STUB_CONTRIB_HOST="$2"
        . "${SCRIPTS_DIR}/lib/staging-env.sh"
        require_ids_match_stack
    )
}

fail() { echo "staging-env guard test FAILED: $1" >&2; exit 1; }

# Agreement: both hostnames equal the key kids → the guard stays silent.
run_guard "smoke-agent.zone.example" "catalog-contributor.zone.example" \
    || fail "guard rejected matching ids"

# Agent mismatch (contributor agrees) → the guard MUST fail.
if run_guard "smoke-agent.other.example" "catalog-contributor.zone.example" 2>/dev/null; then
    fail "guard passed an agent kid/hostname mismatch"
fi

# Contributor mismatch (agent agrees) → the guard MUST fail. This case
# exercises the contributor half of the comparison on its own: with only the
# agent-mismatch case above, the contributor clause could be deleted and the
# suite would still pass.
if run_guard "smoke-agent.zone.example" "catalog-contributor.other.example" 2>/dev/null; then
    fail "guard passed a contributor kid/hostname mismatch"
fi

# Stack without the hostname outputs → the guard MUST fail (re-apply hint).
if run_guard "" "" 2>/dev/null; then
    fail "guard passed with no stack outputs"
fi

echo "staging-env guard test passed (match accepted; mismatch and missing outputs rejected)"
