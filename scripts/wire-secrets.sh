#!/usr/bin/env bash
# Post-terraform-apply wiring: read RDS + ElastiCache endpoints from terraform
# outputs and write the corresponding Secrets Manager entries so ECS tasks can
# boot with real DSNs.
#
# Usage:
#   scripts/wire-secrets.sh
#
# Env:
#   PI_TERRAFORM_ROOT   (default: ../pi-terraform)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PI_TF_ROOT="${PI_TERRAFORM_ROOT:-$(cd "${REPO_ROOT}/../pi-terraform" && pwd)}"

: "${RAMP_AWS_PROFILE:=<DEPLOYER_PROFILE>}"
export AWS_PROFILE="${RAMP_AWS_PROFILE}"
: "${AWS_REGION:=us-east-1}"
export AWS_REGION

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 2; }; }
require_cmd aws
require_cmd terraform

echo "wire-secrets: profile='${AWS_PROFILE}' pi_tf='${PI_TF_ROOT}'"

pg_address=$(terraform -chdir="${PI_TF_ROOT}/AWS/us-east-1/aws-rds" output -raw ramp_demo_pg_address)
pg_password_raw=$(aws --profile "${AWS_PROFILE}" secretsmanager get-secret-value \
    --secret-id ramp-demo/pg-password \
    --query SecretString \
    --output text)
# URL-encode the password so `:` and other specials don't break the DSN parser.
pg_password=$(python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.stdin.read().rstrip("\n"), safe=""))' <<< "${pg_password_raw}")

redis_endpoint=$(terraform -chdir="${PI_TF_ROOT}/AWS/us-east-1/aws-elasticache" output -raw ramp_demo_redis_endpoint)
redis_port=$(terraform -chdir="${PI_TF_ROOT}/AWS/us-east-1/aws-elasticache" output -raw ramp_demo_redis_port)

# Exchange + Broker share the same Postgres; they write into different schemas.
exchange_dsn="postgres://ramp:${pg_password}@${pg_address}:5432/ramp?sslmode=require"
broker_dsn="postgres://ramp:${pg_password}@${pg_address}:5432/ramp?sslmode=require"
redis_url="redis://${redis_endpoint}:${redis_port}/0"

aws --profile "${AWS_PROFILE}" secretsmanager put-secret-value \
    --secret-id ramp-demo/exchange-dsn \
    --secret-string "${exchange_dsn}" \
    --output text >/dev/null
aws --profile "${AWS_PROFILE}" secretsmanager put-secret-value \
    --secret-id ramp-demo/broker-dsn \
    --secret-string "${broker_dsn}" \
    --output text >/dev/null
aws --profile "${AWS_PROFILE}" secretsmanager put-secret-value \
    --secret-id ramp-demo/redis-url \
    --secret-string "${redis_url}" \
    --output text >/dev/null

echo "wired Secrets Manager via profile '${AWS_PROFILE}': exchange-dsn, broker-dsn, redis-url."
echo "ECS services will pull the new values on next deployment (make aws-roll-services)."
