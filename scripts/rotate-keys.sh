#!/usr/bin/env bash
# Generate fresh Ed25519 + RSA-2048 keypairs for the AWS demo deployment.
#
# Writes the RSA public key (PKIX SPKI PEM) into the pi-terraform repo so the
# aws_cloudfront_public_key resource picks it up on next apply. Stages the
# private keys to a scratch directory; `publish` then uploads them to
# Secrets Manager.
#
# Usage:
#   scripts/rotate-keys.sh generate [--staging=/tmp/ramp-demo-keys]
#   scripts/rotate-keys.sh publish  [--staging=/tmp/ramp-demo-keys]
#
# Prereqs:
#   - openssl in PATH
#   - aws CLI with creds that can write the ramp-demo/* secrets (publish only)
#   - PI_TERRAFORM_ROOT env var OR the repo cloned at ../pi-terraform

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PI_TF_ROOT="${PI_TERRAFORM_ROOT:-$(cd "${REPO_ROOT}/../pi-terraform" 2>/dev/null && pwd || true)}"
STAGING="/tmp/ramp-demo-keys"
CF_PUBLIC_PEM_PATH="AWS/global/aws-ramp-demo-cloudfront/keys/ramp-demo-public-key.pem"

# Locked to the <DEPLOYER_PROFILE> profile: the only profile authorized for ramp-demo.
# Override with `RAMP_AWS_PROFILE=<other>` only if you've explicitly extended
# another profile's IAM to cover the ramp-demo supplemental policy.
: "${RAMP_AWS_PROFILE:=<DEPLOYER_PROFILE>}"
export AWS_PROFILE="${RAMP_AWS_PROFILE}"
: "${AWS_REGION:=us-east-1}"
export AWS_REGION

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }; }

parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --staging=*) STAGING="${arg#--staging=}" ;;
        esac
    done
}

require_pi_tf() {
    if [ -z "${PI_TF_ROOT}" ] || [ ! -d "${PI_TF_ROOT}/AWS" ]; then
        echo "error: pi-terraform repo not found" >&2
        echo "       set PI_TERRAFORM_ROOT, or clone at ../pi-terraform" >&2
        exit 2
    fi
}

cmd_generate() {
    require_cmd openssl
    parse_args "$@"
    require_pi_tf

    mkdir -p "${STAGING}"
    chmod 700 "${STAGING}"

    local ed_priv="${STAGING}/ed25519-private.pem"
    local rsa_priv="${STAGING}/rsa-private.pem"
    local rsa_pub="${STAGING}/rsa-public.pem"

    openssl genpkey -algorithm ed25519 -out "${ed_priv}"
    chmod 600 "${ed_priv}"

    openssl genrsa -out "${rsa_priv}" 2048
    chmod 600 "${rsa_priv}"
    openssl rsa -in "${rsa_priv}" -pubout -out "${rsa_pub}"

    # Write the public RSA key into the terraform repo for aws_cloudfront_public_key.
    cp "${rsa_pub}" "${PI_TF_ROOT}/${CF_PUBLIC_PEM_PATH}"

    cat <<EOS
generated keypairs in ${STAGING}:
  ${ed_priv}  (ed25519 private, PKCS#8 PEM)
  ${rsa_priv} (RSA private, traditional PEM)
  ${rsa_pub}  (RSA public, PKIX SPKI PEM)

updated terraform repo:
  ${PI_TF_ROOT}/${CF_PUBLIC_PEM_PATH}

next steps:
  1. commit + push pi-terraform (CloudFront apply will pick up the new PEM).
  2. once terraform-apply has created the Secrets Manager entries:
        scripts/rotate-keys.sh publish --staging=${STAGING}
EOS
}

cmd_publish() {
    require_cmd aws
    parse_args "$@"

    local ed_priv="${STAGING}/ed25519-private.pem"
    local rsa_priv="${STAGING}/rsa-private.pem"
    for f in "${ed_priv}" "${rsa_priv}"; do
        if [ ! -f "${f}" ]; then
            echo "missing: ${f} — run \`scripts/rotate-keys.sh generate\` first" >&2
            exit 2
        fi
    done

    aws --profile "${AWS_PROFILE}" secretsmanager put-secret-value \
        --secret-id ramp-demo/ed25519-private \
        --secret-string "$(cat "${ed_priv}")" \
        --output text >/dev/null

    aws --profile "${AWS_PROFILE}" secretsmanager put-secret-value \
        --secret-id ramp-demo/rsa-private \
        --secret-string "$(cat "${rsa_priv}")" \
        --output text >/dev/null

    echo "published ed25519 + rsa private keys to Secrets Manager (ramp-demo/*) via profile '${AWS_PROFILE}'."
    echo "roll the ECS services so tasks pick up the new secrets:"
    echo "  make aws-roll-services   # or:"
    echo "  aws --profile ${AWS_PROFILE} ecs update-service --cluster ramp-demo --service ramp-demo-{exchange,broker,mcp} --force-new-deployment"
}

main() {
    local sub="${1:-}"
    shift || true
    case "${sub}" in
        generate) cmd_generate "$@" ;;
        publish)  cmd_publish "$@" ;;
        *)
            echo "Usage: $0 {generate|publish} [--staging=<dir>]" >&2
            exit 2
            ;;
    esac
}

main "$@"
