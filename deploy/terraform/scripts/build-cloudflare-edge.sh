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

. "$(dirname "${BASH_SOURCE[0]}")/lib/edge-build.sh"

edge_npm_ci

echo "==> bundling worker"
node scripts/build-worker.mjs

echo "built ${EDGE_DIR}/dist/worker.mjs"
