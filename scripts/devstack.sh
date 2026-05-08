#!/usr/bin/env bash
# Per-project docker dev stack (Postgres + Redis) with dynamic ports.
#
# Designed so parallel executors / contributors can each bring up their own
# isolated stack without port collisions.  Each project gets its own compose
# namespace (`docker compose -p <project>`) and its own random host ports.
#
# Usage:
#   eval "$(scripts/devstack.sh up <project>)"   # starts stack, exports DSNs
#   scripts/devstack.sh down <project>           # tears down + removes volume
#   scripts/devstack.sh status <project>         # prints current ports / URLs
#   scripts/devstack.sh env <project>            # prints export lines for eval
#
# Environment variables exported on `up` / `env`:
#   RAMP_PROJECT       compose project name
#   RAMP_PG_PORT       host port for Postgres
#   RAMP_REDIS_PORT    host port for Redis
#   RAMP_DATABASE_URL  full DSN (pgx-compatible)
#   RAMP_REDIS_URL     full redis:// URL
#   EXCHANGE_DSN       alias for RAMP_DATABASE_URL (services read this)
#   BROKER_DSN         alias for RAMP_DATABASE_URL
#   REDIS_URL          alias for RAMP_REDIS_URL

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${REPO_ROOT}/.devstack"
mkdir -p "${STATE_DIR}"

usage() {
    cat >&2 <<USAGE
Usage: $0 {up|down|status|env} <project>

Commands:
  up      Start a fresh stack for <project> with random ports; prints export lines.
  down    Tear down <project> and remove its volumes.
  status  Report running state and ports for <project>.
  env     Print export lines for an already-running <project> (suitable for eval).
USAGE
    exit 2
}

require_project() {
    if [ -z "${1:-}" ]; then
        echo "error: <project> is required" >&2
        usage
    fi
    if ! [[ "$1" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
        echo "error: project name must be lowercase alphanumerics, '_' or '-'" >&2
        exit 2
    fi
}

pick_free_port() {
    # Ask the kernel for a free ephemeral port, release it, return the number.
    python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

write_env_file() {
    local project="$1" pg_port="$2" redis_port="$3"
    local env_file="${STATE_DIR}/${project}.env"
    cat >"${env_file}" <<ENV
RAMP_PG_PORT=${pg_port}
RAMP_REDIS_PORT=${redis_port}
ENV
    echo "${env_file}"
}

read_env_file() {
    local project="$1"
    local env_file="${STATE_DIR}/${project}.env"
    if [ ! -f "${env_file}" ]; then
        echo "error: no active stack for project '${project}' (expected ${env_file})" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "${env_file}"
}

emit_exports() {
    local project="$1"
    read_env_file "${project}"
    cat <<ENV
export RAMP_PROJECT=${project}
export RAMP_PG_PORT=${RAMP_PG_PORT}
export RAMP_REDIS_PORT=${RAMP_REDIS_PORT}
export RAMP_DATABASE_URL='postgres://ramp:ramp@127.0.0.1:${RAMP_PG_PORT}/ramp?sslmode=disable'
export RAMP_REDIS_URL='redis://127.0.0.1:${RAMP_REDIS_PORT}/0'
export EXCHANGE_DSN="\${RAMP_DATABASE_URL}"
export BROKER_DSN="\${RAMP_DATABASE_URL}"
export REDIS_URL="\${RAMP_REDIS_URL}"
ENV
}

wait_healthy() {
    local project="$1" service="$2" max_wait="${3:-45}"
    local elapsed=0
    while [ "${elapsed}" -lt "${max_wait}" ]; do
        local status
        status=$(docker compose -p "${project}" ps --format json 2>/dev/null |
            python3 -c "
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    row = json.loads(line)
    if row.get('Service') == '${service}':
        print(row.get('Health', '') or row.get('State', ''))
        break
" || echo "")
        if [ "${status}" = "healthy" ] || [ "${status}" = "running" ]; then
            # running without health means the healthcheck hasn't run yet
            # — poll once more to be sure
            if [ "${status}" = "healthy" ]; then
                return 0
            fi
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo "warn: ${service} in project ${project} did not report healthy within ${max_wait}s" >&2
    return 1
}

cmd_up() {
    local project="$1"
    local pg_port redis_port env_file
    pg_port="$(pick_free_port)"
    redis_port="$(pick_free_port)"
    env_file="$(write_env_file "${project}" "${pg_port}" "${redis_port}")"
    (
        cd "${REPO_ROOT}"
        docker compose -p "${project}" --env-file "${env_file}" up -d >&2
    )
    wait_healthy "${project}" postgres 60 || true
    wait_healthy "${project}" redis 30 || true
    emit_exports "${project}"
}

cmd_down() {
    local project="$1"
    local env_file="${STATE_DIR}/${project}.env"
    if [ ! -f "${env_file}" ]; then
        echo "no active stack for project '${project}'; nothing to do" >&2
        return 0
    fi
    (
        cd "${REPO_ROOT}"
        docker compose -p "${project}" --env-file "${env_file}" down -v >&2
    )
    rm -f "${env_file}"
}

cmd_status() {
    local project="$1"
    if [ ! -f "${STATE_DIR}/${project}.env" ]; then
        echo "project '${project}': not started"
        return 0
    fi
    read_env_file "${project}"
    echo "project: ${project}"
    echo "  pg_port: ${RAMP_PG_PORT}"
    echo "  redis_port: ${RAMP_REDIS_PORT}"
    (cd "${REPO_ROOT}" && docker compose -p "${project}" ps)
}

cmd_env() {
    emit_exports "$1"
}

main() {
    local cmd="${1:-}" project="${2:-}"
    case "${cmd}" in
    up)     require_project "${project}"; cmd_up "${project}" ;;
    down)   require_project "${project}"; cmd_down "${project}" ;;
    status) require_project "${project}"; cmd_status "${project}" ;;
    env)    require_project "${project}"; cmd_env "${project}" ;;
    ""|-h|--help) usage ;;
    *)      echo "error: unknown command '${cmd}'" >&2; usage ;;
    esac
}

main "$@"
