# Sourced by every script in deploy/terraform/scripts/ — not runnable on its
# own. Defines the values that more than one script must agree on, exactly
# once:
#
#   REPO_ROOT         absolute path to the repository root, resolved from this
#                     file's location so the scripts work from any cwd.
#
#   BROKER_RELAY_KID  Staging identity ids, overridable via env. The suffixes
#   AGENT_ID          differ on purpose: KID names a KEY (a versioned key id,
#   CONTRIBUTOR_ID    JOSE "kid" — rotating the key changes it), ID names an
#                     ACTOR (stable across key rotation). Key files on
#                     disk are named by these ids and ramp.agents rows are
#                     keyed by them, so key generation, seeding, and smoke
#                     MUST all use the same values. Seeding upserts by
#                     agent_id (ON CONFLICT DO UPDATE): if a default drifted
#                     in one script, seeding would silently insert a stray row
#                     and staging auth would break with no clear error. That
#                     is why the defaults live only here. The staging-aws
#                     stack needs the same two values as agent_id /
#                     catalog_contributor_id — its variables carry NO default
#                     (terraform errors until tfvars sets them) so this file
#                     stays the only home.
#
#   STACK_DIR         Staging stack directory, overridable via env; tf_out()
#   tf_out            reads one raw terraform output from it. Shared by
#                     seed-staging.sh and smoke.sh.
#
#   KEYS_DIR          The stack's key directory — where gen-staging-keys.sh
#                     WRITES and seed-staging.sh, fund-staging-agent.sh, and
#                     smoke.sh READ. Derived from STACK_DIR so an overridden
#                     stack keeps producer and consumers on the same
#                     directory; defined only here for the same reason as the
#                     identity ids above.
#
#   VM_COMPOSE_FILE   Where cloud-init puts the Compose bundle ON THE VM
#                     (modules/compose-stack/templates/cloud-init.yaml.tftpl).
#                     Scripts that run docker compose over SSH must use this
#                     value, so a path move touches the template and this one
#                     line, not every script. Named VM_* to avoid colliding
#                     with docker compose's own COMPOSE_FILE variable.
#
#   VM_COMPOSE_PROJECT  The bundle's `name:` — the prefix Docker puts on the
#                     network and volumes it creates (<project>_default,
#                     <project>_<volume>). A script that runs a one-off
#                     container alongside the stack has to name them, and the
#                     value is set in docker-compose.yml.tftpl; changing it
#                     there means changing it here.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"

BROKER_RELAY_KID="${BROKER_RELAY_KID:-broker.staging.v1}"
AGENT_ID="${AGENT_ID:-agent-staging}"
CONTRIBUTOR_ID="${CONTRIBUTOR_ID:-catalog-contributor-staging}"

STACK_DIR="${STACK_DIR:-${REPO_ROOT}/deploy/terraform/stacks/staging-aws}"
KEYS_DIR="${STACK_DIR}/keys"
tf_out() { terraform -chdir="${STACK_DIR}" output -raw "$1"; }

VM_COMPOSE_FILE="/opt/ramp/docker-compose.yml"
VM_COMPOSE_PROJECT="ramp"
