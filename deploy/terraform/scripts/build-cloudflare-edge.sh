#!/usr/bin/env bash
# Build the Cloudflare edge worker bundle Terraform uploads.
#
# Output: src/edge/dist/worker.mjs — consumed by the cloudflare-edge module
# (worker_bundle_path). Run this before every `terraform apply` that should
# pick up worker code changes; Terraform only re-uploads when the file content
# changes.
#
# Usage:
#   deploy/terraform/scripts/build-cloudflare-edge.sh

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"
EDGE_DIR="${REPO_ROOT}/src/edge"

# Fail fast with one clear line when a build tool is absent — the errors npm
# and the bundler print without it are much harder to read.
command -v node >/dev/null 2>&1 || { echo "missing: node" >&2; exit 2; }
command -v npm >/dev/null 2>&1 || { echo "missing: npm" >&2; exit 2; }

cd "${EDGE_DIR}"

# npm ci needs the lockfile; it gives a reproducible dependency tree. Run it
# unconditionally: skipping on an existing node_modules would keep a stale
# dependency tree on a warm checkout — a bumped @ramp-protocol/sdk-l1 (the
# package that supplies verify) would silently not make it into the bundle.
echo "==> npm ci (src/edge)"
npm ci

echo "==> bundling worker"
node scripts/build-worker.mjs

echo "built ${EDGE_DIR}/dist/worker.mjs"
