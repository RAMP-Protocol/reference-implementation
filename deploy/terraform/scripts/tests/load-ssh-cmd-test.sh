#!/usr/bin/env bash
# Prove load_ssh_cmd builds the right ssh command line: the bare destination
# when the operator selects no key, "-o IdentitiesOnly=yes -i <path>" spliced in
# ahead of the destination when RAMP_SSH_IDENTITY_FILE is set, and a path
# containing a space kept in ONE array element. A helper that exists to keep the
# identity out of Terraform has to be SEEN doing it — the previous line built
# SSH_CMD by word-splitting a Terraform output, which both carried the last
# applier's key path and broke on a path with a space. The harness stubs
# `terraform` on PATH (env-controlled outputs) and drives the helper through
# lib/staging-env.sh exactly the way seed-staging.sh and fund-all-agents.sh do.
#
# Run directly, or via test-terraform.sh (which wires it into the suite).
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

mkdir -p "${work}/bin" "${work}/stack"
cat > "${work}/bin/terraform" <<'EOF'
#!/usr/bin/env bash
# Stub for `terraform -chdir=<dir> output -raw <name>`: answers vm_public_ip and
# nothing else, so a helper that reaches for any other output fails loudly.
name="${!#}"
case "${name}" in
    vm_public_ip) echo "198.51.100.10" ;;
    *) exit 1 ;;
esac
EOF
chmod +x "${work}/bin/terraform"

# emit_cmd [identity] → SSH_CMD's elements, one per line, from a subshell wired
# the way the consumer scripts are. One element per line is what makes the
# space case checkable: a split path would show up as two lines.
emit_cmd() {
    (
        export PATH="${work}/bin:${PATH}"
        export STACK_DIR="${work}/stack"
        if [ "$#" -gt 0 ]; then
            export RAMP_SSH_IDENTITY_FILE="$1"
        else
            unset RAMP_SSH_IDENTITY_FILE
        fi
        . "${SCRIPTS_DIR}/lib/staging-env.sh"
        load_ssh_cmd
        printf '%s\n' "${SSH_CMD[@]}"
    )
}

fail() { echo "load_ssh_cmd test FAILED: $1" >&2; exit 1; }

# No identity selected: exactly "ssh ubuntu@<ip>", nothing spliced in. An
# unconditional -i would show up here as extra elements.
got="$(emit_cmd)"
want="$(printf 'ssh\nubuntu@198.51.100.10\n')"
[ "${got}" = "${want}" ] || fail "bare command was: ${got}"

# Identity selected: IdentitiesOnly comes first so ssh stops offering every
# agent key before the named one, and the destination stays last.
got="$(emit_cmd /opt/operator-keys/ramp)"
want="$(printf 'ssh\n-o\nIdentitiesOnly=yes\n-i\n/opt/operator-keys/ramp\nubuntu@198.51.100.10\n')"
[ "${got}" = "${want}" ] || fail "identity command was: ${got}"

# A path with a space stays ONE element. The line this helper replaced split on
# whitespace, so this case failed before the change.
got="$(emit_cmd "/opt/operator keys/ramp")"
want="$(printf 'ssh\n-o\nIdentitiesOnly=yes\n-i\n/opt/operator keys/ramp\nubuntu@198.51.100.10\n')"
[ "${got}" = "${want}" ] || fail "spaced identity path was split: ${got}"

echo "load_ssh_cmd test passed (bare destination; identity spliced in; spaced path kept whole)"
