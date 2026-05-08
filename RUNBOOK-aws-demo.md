# AWS Demo Deployment Runbook

Deploys `demo.ramp-protocol.org` end-to-end. Produces:
- ECS Fargate services for Exchange, Broker, MCP
- RDS Postgres + ElastiCache Redis
- CloudFront distribution with trusted key group (native RSA signed-URL verification)
- Lambda@Edge for bot-redirect

Assumes the legacy v0.2 stack, the n8n instance, and the shared pi-cold-mail VPC / ALB / Route53 zone already exist. Those are not touched by this runbook.

The architectural rationale for the per-deployment module layout is in `pi-terraform/RAMP-DEMO.md`.

## Prerequisites

- `aws` CLI, `terraform` (>= 1.8), `docker` (buildx for linux/amd64), `openssl`.
- **AWS profile `<DEPLOYER_PROFILE>`** configured in `~/.aws/config` (maps to `<DEPLOYER_IAM_USER>` IAM user on account <AWS_ACCOUNT_ID>). Every script + make target locks to this profile explicitly — no implicit fallback. Override with `RAMP_AWS_PROFILE=<name>` only if you've attached the `pi_poc_ramp_demo` policy to a different IAM user.
- Admin has applied `pi-terraform/AWS/global/aws-iam` so `aws_iam_policy.pi_poc_ramp_demo` is attached to `<DEPLOYER_IAM_USER>`.
- This repo at `$REPO_ROOT`.
- The `pi-terraform` repo cloned at `$PI_TERRAFORM_ROOT` (default: `../pi-terraform`).
- Docker Desktop running; compose E2E green (`make test-e2e` from repo root).

## One-time: generate keys + commit to pi-terraform

```bash
scripts/rotate-keys.sh generate
# Writes RSA public key PEM to:
#   $PI_TERRAFORM_ROOT/AWS/global/aws-ramp-demo-cloudfront/keys/ramp-demo-public-key.pem
# Stages privates at /tmp/ramp-demo-keys (0700).

cd "$PI_TERRAFORM_ROOT"
git add AWS/global/aws-ramp-demo-cloudfront/keys/ramp-demo-public-key.pem
git commit -m "rotate: ramp-demo public key"
```

## One-time: admin cleanup of legacy ramp-demo state

If earlier ramp-demo attempts left resources inside legacy modules (`aws-acm`, `aws-ec2`, `aws-s3`, `aws-lambda`, `aws-cloudfront`), the admin needs to destroy those entries once so the new ramp-demo modules can own them cleanly:

```bash
# Only run if aws-acm still has a ramp-demo cert in state.
cd "$PI_TERRAFORM_ROOT/AWS/us-east-1/aws-acm"
AWS_PROFILE=<ADMIN_PROFILE> terraform apply   # destroys demo.ramp-protocol.org cert + validation records
```

The other legacy modules (`aws-ec2`, `aws-s3`, `aws-lambda`, `aws-cloudfront`) were never applied with ramp-demo additions — the `.tf` files are simply gone, so no state cleanup is needed there.

## Apply order

Every `terraform` invocation runs with `AWS_PROFILE=<DEPLOYER_PROFILE>` — either export once or prefix each command:

```bash
export AWS_PROFILE=<DEPLOYER_PROFILE>
```

```
1. AWS/us-east-1/aws-ramp-demo-acm              # cert for *.demo.ramp-protocol.org
2. AWS/us-east-1/aws-ramp-demo-ecs              # ECR + Secrets + ECS cluster + SG + ALB rules
3. AWS/us-east-1/aws-rds                        # Postgres (uses ramp-demo-ecs-sg)
4. AWS/us-east-1/aws-elasticache                # Redis (uses ramp-demo-ecs-sg)
5. AWS/global/aws-ramp-demo-s3                  # ramp-demo-content bucket
6. AWS/us-east-1/aws-ramp-demo-lambda           # Lambda@Edge bot-redirect
7. AWS/global/aws-ramp-demo-cloudfront          # distribution + trusted key group
8. AWS/global/aws-route53/other/ramp-protocol.org   # A record → CloudFront
```

For step 8, after step 7 is applied, pipe in CloudFront outputs:

```bash
cd "$PI_TERRAFORM_ROOT/AWS/global/aws-route53/other/ramp-protocol.org"
AWS_PROFILE=<DEPLOYER_PROFILE> terraform apply \
  -var=ramp_demo_cloudfront_domain=$(AWS_PROFILE=<DEPLOYER_PROFILE> terraform -chdir=../../../global/aws-ramp-demo-cloudfront output -raw ramp_demo_cloudfront_domain) \
  -var=ramp_demo_cloudfront_hosted_zone_id=$(AWS_PROFILE=<DEPLOYER_PROFILE> terraform -chdir=../../../global/aws-ramp-demo-cloudfront output -raw ramp_demo_cloudfront_hosted_zone_id)
```

## Push images + wire secrets

After step 2 (ECR repos exist):

```bash
scripts/ecr-push.sh                    # builds linux/amd64 + pushes :latest
```

After steps 3-4 (RDS + Redis endpoints known):

```bash
scripts/wire-secrets.sh                # writes DSNs + Redis URL to Secrets Manager
scripts/rotate-keys.sh publish         # writes ed25519 + rsa privates to Secrets Manager
```

## Kick the ECS services

Either: `aws ecs update-service --cluster ramp-demo --service ramp-demo-{exchange,broker,mcp} --force-new-deployment` per service, or wait for the ECS scheduler to pick up the new task definition automatically.

## Smoke check

```bash
curl https://exchange.demo.ramp-protocol.org/healthz
curl https://broker.demo.ramp-protocol.org/healthz
curl https://mcp.demo.ramp-protocol.org/mcp   # returns 406 — correct (SSE accept required)
curl https://demo.ramp-protocol.org/          # served by CloudFront from S3
```

## Real-AWS E2E test (optional)

```bash
RAMP_E2E_AWS=1 \
RAMP_E2E_BROKER_URL=https://broker.demo.ramp-protocol.org \
RAMP_E2E_CLOUDFRONT_URL=https://demo.ramp-protocol.org \
make test-e2e-aws
```

## Tearing it all down

Reverse apply order across the ramp-demo modules only (route53 A-record → cloudfront → lambda → s3 → elasticache → rds → ecs → acm). The legacy `aws-ec2`, `aws-s3`, `aws-lambda`, `aws-cloudfront`, `aws-acm` modules are not involved. CloudFront distro + Lambda@Edge take ~20 min to fully delete because of edge replication.

## Rollback

The legacy v0.2 stack, n8n, and every other tenant of the pi-terraform repo are untouched by any of this. Destroying the ramp-demo modules in reverse order restores the account to its pre-deploy state.
