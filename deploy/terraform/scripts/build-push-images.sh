#!/usr/bin/env bash
# Build + push the staging images (exchange, broker, identity, publisher).
#
# Registry, path prefix, and tag are first-class knobs so the same script
# serves GitLab Container Registry (default), GHCR, Docker Hub, or ECR:
#
#   REGISTRY  registry host                 (default: registry.gitlab.com)
#   PREFIX    path under the registry        (required, e.g. group/project)
#   TAG       image tag                      (default: latest)
#
# Resulting names: <REGISTRY>/<PREFIX>/{exchange,broker,identity,publisher}:<TAG>
# — exactly what stacks/staging-aws composes from image_registry/image_prefix/
# image_tag.
#
# Log in to the registry first (docker login <REGISTRY>); this script does not
# handle credentials.
#
# Usage:
#   PREFIX=group/project deploy/terraform/scripts/build-push-images.sh [--tag=<tag>]

set -euo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/staging-env.sh"
REGISTRY="${REGISTRY:-registry.gitlab.com}"
TAG="${TAG:-latest}"

for arg in "$@"; do
    case "${arg}" in
        --tag=*) TAG="${arg#--tag=}" ;;
    esac
done

if [ -z "${PREFIX:-}" ]; then
    echo "PREFIX is required (path under the registry, e.g. PREFIX=group/project)" >&2
    exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "missing: docker" >&2; exit 2; }

push_image() {
    local service="$1"
    local dockerfile="$2"
    local context="$3"
    local full="${REGISTRY}/${PREFIX}/${service}:${TAG}"
    echo "==> build ${full}"
    docker build --platform=linux/amd64 -f "${dockerfile}" -t "${full}" "${context}"
    echo "==> push ${full}"
    docker push "${full}"
}

cd "${REPO_ROOT}"
push_image exchange  src/exchange/Dockerfile                .
push_image broker    src/broker/Dockerfile                  .
# Repo root is the build context on purpose: src/identity/Dockerfile copies the
# root go.mod/go.sum and the shared internal/ tree, not just src/identity.
push_image identity  src/identity/Dockerfile                .
push_image publisher deploy/terraform/publisher/Dockerfile  .

echo "done: ${REGISTRY}/${PREFIX}/{exchange,broker,identity,publisher}:${TAG}"
