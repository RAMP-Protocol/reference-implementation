#!/usr/bin/env bash
# Build the Lambda@Edge worker bundle + zip Terraform deploys.
#
# Lambda@Edge has no environment variables, so the per-deployment config is
# baked into the bundle at build time from a flat JSON file of env-shaped
# string values (see src/edge/scripts/build-lambda-edge.mjs for the file's
# contract and the bake mechanism). Run this before every `terraform apply`
# that should pick up worker code OR config changes — both live in the zip.
#
# Output: src/edge/dist/lambda-edge.zip — a single index.mjs, handler
# "index.handler". The build smoke-invokes the bundle locally before zipping,
# so a config the worker's schema rejects fails here, not at the edge.
#
# Usage:
#   deploy/terraform/scripts/build-lambda-edge.sh <deploy-config.json>

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/edge-build.sh"

CONFIG_ARG="${1:?usage: build-lambda-edge.sh <deploy-config.json>}"
# Absolute before any cd, so a path relative to the caller's cwd keeps working.
CONFIG="$(cd "$(dirname "${CONFIG_ARG}")" && pwd)/$(basename "${CONFIG_ARG}")"
[ -f "${CONFIG}" ] || { echo "missing config file: ${CONFIG_ARG}" >&2; exit 2; }
command -v zip >/dev/null 2>&1 || { echo "missing: zip" >&2; exit 2; }

edge_npm_ci

echo "==> bundling Lambda@Edge worker"
node scripts/build-lambda-edge.mjs --config "${CONFIG}"

# -X drops platform extra fields, -j stores index.mjs at the archive root —
# the flat layout the "index.handler" handler string expects.
rm -f dist/lambda-edge.zip
zip -X -q -j dist/lambda-edge.zip dist/lambda-edge/index.mjs

echo "built ${EDGE_DIR}/dist/lambda-edge.zip"
