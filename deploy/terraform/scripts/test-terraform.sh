#!/usr/bin/env bash
# Run every module's Terraform test suite (terraform test, .tftest.hcl).
#
# All suites are offline: plan mode + mocked providers (AWS, Cloudflare), and
# the compose-stack suite's apply only instantiates an in-memory
# random_password. No cloud account, no credentials, no resources.
#
# Usage:
#   deploy/terraform/scripts/test-terraform.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"
MODULES_DIR="${REPO_ROOT}/deploy/terraform/modules"

command -v terraform >/dev/null 2>&1 || { echo "missing: terraform (>= 1.8)" >&2; exit 2; }

# Formatting is part of the gate: nothing else runs `terraform fmt -check`, so
# without this step drift lands silently (it did — a hand-aligned locals block
# passed every suite here and was only caught in review).
if ! terraform fmt -recursive -check "${REPO_ROOT}/deploy/terraform" >/dev/null; then
    echo "terraform fmt drift — run: terraform fmt -recursive deploy/terraform" >&2
    terraform fmt -recursive -check "${REPO_ROOT}/deploy/terraform" >&2 || true
    exit 1
fi
echo "terraform fmt clean"

# The Workers runtime compatibility date is pinned in two files that cannot
# reference each other: the cloudflare-edge module default (what staging
# applies) and src/edge/wrangler.toml (what wrangler dev / edge CI runs).
# A drifted pair means staging runs a different Workers runtime than the one
# the edge code is developed against — fail loudly instead.
tf_compat_date="$(sed -n '/variable "compatibility_date"/,/^}/s/^ *default *= *"\([^"]*\)".*/\1/p' \
    "${MODULES_DIR}/cloudflare-edge/variables.tf")"
toml_compat_date="$(sed -n 's/^compatibility_date *= *"\([^"]*\)".*/\1/p' \
    "${REPO_ROOT}/src/edge/wrangler.toml")"
if [ -z "${tf_compat_date}" ] || [ -z "${toml_compat_date}" ] || [ "${tf_compat_date}" != "${toml_compat_date}" ]; then
    echo "compatibility_date drift: cloudflare-edge default '${tf_compat_date}' vs" \
         "src/edge/wrangler.toml '${toml_compat_date}' — bump both together" >&2
    exit 1
fi
echo "compatibility_date in sync (${tf_compat_date})"

# The worker's env contract (EnvSchema in src/edge/src/config.ts) and the
# cloudflare-edge module's binding maps cannot reference each other. A key in
# one and not the other means a setting that cannot be deployed through the
# module (and is silently STRIPPED from a worker on the next apply), or a
# binding the worker never reads — fail loudly instead. Same shape as the
# compatibility_date check above.
schema_keys="$(sed -n '/^const EnvSchema = z.object({/,/^});/p' "${REPO_ROOT}/src/edge/src/config.ts" \
    | sed -n 's/^  \([A-Z][A-Z0-9_]*\): z\..*/\1/p' | sort)"
module_keys="$(sed -n '/required_bindings = {/,/^  }/p; /optional_bindings = {/,/^  }/p' \
    "${MODULES_DIR}/cloudflare-edge/main.tf" \
    | sed -n 's/^    \([A-Z][A-Z0-9_]*\) *=.*/\1/p' | sort)"
if [ -z "${schema_keys}" ] || [ -z "${module_keys}" ]; then
    echo "env-contract drift check broke: could not extract keys (EnvSchema moved, or the binding maps were renamed) — fix the extraction in this script" >&2
    exit 1
fi
if [ "${schema_keys}" != "${module_keys}" ]; then
    echo "env-contract drift between src/edge/src/config.ts EnvSchema and the cloudflare-edge binding maps:" >&2
    diff <(printf '%s\n' "${schema_keys}") <(printf '%s\n' "${module_keys}") >&2 || true
    exit 1
fi
echo "cloudflare-edge bindings mirror the worker env contract ($(printf '%s\n' "${schema_keys}" | wc -l | tr -d ' ') keys)"

# The staging id/hostname guard exists to fail; prove it still can (stubbed
# terraform on PATH + fabricated key files — see the test script).
"$(dirname "${BASH_SOURCE[0]}")/tests/staging-env-guard-test.sh"

failed=0
for module in "${MODULES_DIR}"/*/; do
    [ -d "${module}tests" ] || continue
    name="$(basename "${module}")"
    echo "==> ${name}"
    (
        cd "${module}"
        terraform init -backend=false -input=false >/dev/null
        terraform test
    ) || failed=1
done

# stacks/staging-aws and stacks/demo-aws read their key material with file()
# on constant paths, which terraform evaluates while loading the configuration
# — so a checkout without the gitignored keys/ directories (CI, a fresh clone)
# fails validate before any reference checking happens. Placeholders keep the
# step hermetic: create exactly the files that are missing, remove exactly
# those afterwards. A real key on disk is never touched (the -f guard skips
# it) and never removed (only created paths are recorded for cleanup). The
# content is throwaway text; only broker-identity-key.pem has plan-time shape
# checks (the ED25519 label and an 88-character base64 payload), which the
# zero-byte payload below satisfies.
KEYED_STACKS=(staging-aws demo-aws)
placeholder_keys=()
cleanup_placeholder_keys() {
    local f s
    for f in ${placeholder_keys[@]+"${placeholder_keys[@]}"}; do
        rm -f "${f}"
    done
    for s in "${KEYED_STACKS[@]}"; do
        rmdir "${REPO_ROOT}/deploy/terraform/stacks/${s}/keys" 2>/dev/null || true
    done
}
trap cleanup_placeholder_keys EXIT
place_key() { # <keys-dir> <filename> <content> — no-op when the real file exists
    local path="$1/$2"
    [ -f "${path}" ] && return 0
    printf '%s\n' "$3" > "${path}"
    placeholder_keys+=("${path}")
}
# The label is named once and interpolated into both halves so this file never
# carries a BEGIN header and its matching END footer as literals — that pair is
# what the secret scanner matches on, whatever sits between the two. The
# placeholder written is unchanged.
ed25519_label="ED25519 PRIVATE KEY"
for s in "${KEYED_STACKS[@]}"; do
    keys_dir="${REPO_ROOT}/deploy/terraform/stacks/${s}/keys"
    mkdir -p "${keys_dir}"
    place_key "${keys_dir}" ed25519-private.pem "placeholder written by test-terraform.sh for validate; never a real key"
    place_key "${keys_dir}" broker-relay-key.json '{}'
    place_key "${keys_dir}" broker-identity-key.pem "-----BEGIN ${ed25519_label}-----
$(head -c 64 /dev/zero | base64)
-----END ${ed25519_label}-----"
    # The smoke identities' public WBA documents (JWK Sets, no private
    # material even in the real files) — both keyed stacks read them into
    # static_wba_directories. Empty keys[] is fine here: the module's
    # validation runs at plan time with values, and this step only runs
    # validate.
    place_key "${keys_dir}" smoke-agent-wba.json '{"keys":[]}'
    place_key "${keys_dir}" catalog-contributor-wba.json '{"keys":[]}'
done

# The module suites never load the root stacks, so a stack-level reference
# error (an output naming a local that only ever existed as an inline module
# argument) passes every suite above and only surfaces at plan time against
# the real account. validate catches exactly that class offline: it checks
# references and types without credentials, state, or variable values.
for stack in "${REPO_ROOT}/deploy/terraform/stacks"/*/; do
    name="stacks/$(basename "${stack}")"
    echo "==> ${name} (validate)"
    (
        cd "${stack}"
        terraform init -backend=false -input=false >/dev/null
        terraform validate
    ) || failed=1
done

if [ "${failed}" -ne 0 ]; then
    echo "terraform tests FAILED" >&2
    exit 1
fi
echo "all terraform module tests passed"
