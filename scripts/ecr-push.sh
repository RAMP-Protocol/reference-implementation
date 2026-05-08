#!/usr/bin/env bash
# Build + push exchange, broker, mcp images to ECR for the AWS demo deploy.
#
# Usage:
#   scripts/ecr-push.sh [--tag=<tag>]
#
# Env:
#   AWS_REGION   (default: us-east-1)
#   AWS_ACCOUNT_ID (optional; resolved via aws sts get-caller-identity)
#   TAG          (default: latest)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AWS_REGION="${AWS_REGION:-us-east-1}"
TAG="${TAG:-latest}"

: "${RAMP_AWS_PROFILE:=<DEPLOYER_PROFILE>}"
export AWS_PROFILE="${RAMP_AWS_PROFILE}"

for arg in "$@"; do
    case "${arg}" in
        --tag=*) TAG="${arg#--tag=}" ;;
    esac
done

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }; }
require_cmd aws
require_cmd docker

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws --profile "${AWS_PROFILE}" sts get-caller-identity --query Account --output text)}"
REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "ecr-push: profile='${AWS_PROFILE}' region='${AWS_REGION}' account='${AWS_ACCOUNT_ID}' tag='${TAG}'"
aws --profile "${AWS_PROFILE}" ecr get-login-password --region "${AWS_REGION}" \
    | docker login --username AWS --password-stdin "${REGISTRY}" >/dev/null

push_image() {
    local service="$1"
    local dockerfile="$2"
    local context="$3"
    local repo="ramp-demo-${service}"
    local full="${REGISTRY}/${repo}:${TAG}"
    echo "==> build ${repo}:${TAG}"
    docker build --platform=linux/amd64 -f "${dockerfile}" -t "${full}" "${context}"
    echo "==> push ${full}"
    docker push "${full}"
}

cd "${REPO_ROOT}"
push_image exchange src/exchange/Dockerfile .
push_image broker   src/broker/Dockerfile   .
push_image mcp      src/mcp/Dockerfile      src/mcp

cat <<EOS
done via profile '${AWS_PROFILE}'. roll the ECS services to pick up the new images:
  make aws-roll-services   # or:
  aws --profile ${AWS_PROFILE} ecs update-service --cluster ramp-demo --service ramp-demo-{exchange,broker,mcp} --force-new-deployment
EOS
