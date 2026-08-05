# Sourced by the edge bundle build scripts (build-cloudflare-edge.sh,
# build-lambda-edge.sh) — not runnable on its own. One home for the setup both
# need: the src/edge path and the reproducible dependency install.

. "$(dirname "${BASH_SOURCE[0]}")/staging-env.sh"
EDGE_DIR="${REPO_ROOT}/src/edge"

# Fail fast with one clear line when a build tool is absent — the errors npm
# and the bundler print without it are much harder to read. Then install from
# the lockfile for a reproducible dependency tree. Run npm ci unconditionally:
# skipping on an existing node_modules would keep a stale dependency tree on a
# warm checkout — a bumped @ramp-protocol/sdk-l1 (the package that supplies
# verify) would silently not make it into the bundle.
edge_npm_ci() {
    command -v node >/dev/null 2>&1 || { echo "missing: node" >&2; exit 2; }
    command -v npm >/dev/null 2>&1 || { echo "missing: npm" >&2; exit 2; }
    cd "${EDGE_DIR}"
    echo "==> npm ci (src/edge)"
    npm ci
}
