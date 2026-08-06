# RAMP Terraform deployment package

Everything needed to run the full RAMP stack on AWS for staging, plus the one
piece a publisher applies themselves: the Cloudflare edge worker module.

Three ways to use this package:

1. **All-inclusive staging** (`stacks/staging-aws`) — one EC2 VM runs the
   whole stack with Docker Compose (Postgres, Redis, TigerBeetle, Exchange,
   Broker, the Identity Service with its key store and OIDC provider, Caddy
   for TLS, and a demo publisher origin). Cloudflare provides DNS and runs the
   edge worker in front of the demo publisher hostname. This is what we use to
   test the complete flow before handing anything to a publisher.
2. **All-AWS demo** (`stacks/demo-aws`) — the all-AWS sibling of staging:
   the same backend VM, but DNS lives in Route 53 and the publisher hostname
   is fronted by CloudFront + Lambda@Edge running the same Ed25519 edge
   worker. No Cloudflare account, zone, or token is involved anywhere. See
   `docs/deploy-demo-aws.md`.
3. **Standalone edge** (`stacks/edge`) — ONLY the Cloudflare edge worker,
   applied by a publisher against their own Cloudflare
   account. It needs nothing else from this package. See
   `docs/deploy-edge-standalone.md`.

The Compose file rendered for staging is also the reference bundle for a
publisher running the backend in their own data center — staging tests the
exact artifact we hand over. It carries the agent-identity plane too, which
such a publisher does not need; see "Deferred scope".

## Layout

```
modules/                 reusable building blocks (flat, purpose-named)
  compose-stack/         renders compose file + Caddyfile + cloud-init (no cloud provider)
  aws-vm/                VPC + EC2 + Elastic IP for the staging VM
  cloudflare-dns/        A records for the service hostnames
  route53-dns/           the Route 53 counterpart of cloudflare-dns
  cloudflare-edge/       the edge worker (the publisher handoff module)
  aws-cloudfront-edge/   the CloudFront + Lambda@Edge counterpart of cloudflare-edge
  publisher-manifest/    renders the publisher-manifest env values both edge modules consume
stacks/                  root configurations you actually apply
  staging-aws/           the all-inclusive staging environment
  demo-aws/              the all-AWS demo environment (Route 53 + CloudFront/Lambda@Edge)
  edge/                  standalone edge worker (publisher-facing)
scripts/                 build, key-generation, bootstrap, seed, and smoke helpers
docs/                    step-by-step guides + variables reference
publisher/               Dockerfile for the staging demo origin image
```

Modules follow the Terraform community layout: each is self-contained
(`main.tf` / `variables.tf` / `outputs.tf` / `versions.tf`), nothing is shared
between sibling modules, and `cloudflare-edge` stays independently applyable
because it is the handoff artifact. Stacks are compositions — they hold
environment wiring and values, nothing reusable.

## Deployment

Each guide starts with its own prerequisites list and explains every step —
the guides are the single home of the procedures, nothing is repeated here:

- **Staging on AWS** (`stacks/staging-aws`):
  [docs/deploy-staging-aws.md](docs/deploy-staging-aws.md) — keys → images →
  worker bundle → apply → bootstrap identity → seed + smoke.
- **All-AWS demo** (`stacks/demo-aws`):
  [docs/deploy-demo-aws.md](docs/deploy-demo-aws.md) — covers what differs
  from staging (Route 53, CloudFront + Lambda@Edge) and points at the staging
  guide for everything shared; the operator scripts select this stack via
  `STACK_DIR`.
- **Standalone edge worker** (`stacks/edge`, what a publisher applies):
  [docs/deploy-edge-standalone.md](docs/deploy-edge-standalone.md) — needs
  only a Cloudflare account, no AWS, no registry.
- **Variables reference**:
  [docs/variables.md](docs/variables.md).
- **Removing everything**: [docs/teardown.md](docs/teardown.md).

## Tests

Every module ships a `terraform test` suite (`modules/*/tests/*.tftest.hcl`).
All suites run **without any cloud account**: the AWS and Cloudflare providers
are mocked, assertions run against the plan, and the compose-stack suite's
apply only creates the stack's in-memory random secrets (database passwords,
the Vault root token, Zitadel's master key and admin password, the Identity
Service's session and token-signing keys) — no credentials, no API calls, no
resources, no cost.

```bash
deploy/terraform/scripts/test-terraform.sh   # all modules
# or per module:
cd modules/compose-stack && terraform init && terraform test
```

What they cover: template rendering (TigerBeetle static-IP wiring, optional
publisher/registry-login/RSA blocks, the identity plane and its generated
secrets, on-demand TLS for agent subdomains, ACME staging toggle, the
no-insecure-overrides guarantee), input validation (Graviton and open-SSH
rejection, billing-adapter and route-pattern checks), and resource wiring
(security-group rules, gzipped user data, worker bindings mirroring the
`config.ts` contract, DNS-only vs proxied records including the wildcard).

One of them is a budget rather than a behaviour: the fully-loaded cloud-init
must stay under EC2's 16 KB user-data limit. It currently renders at ~8.2 KB
gzipped (~28 KB raw, so the compression is load-bearing). If that assertion
ever trips, the answer is to stop inlining the bundle and fetch it at boot —
a deliberate design change, not something to trim comments until it fits.

Run the suites before every commit that touches this package. Anything that
needs real infrastructure is covered by the staging rehearsal
(`docs/deploy-staging-aws.md`), not by these tests.

## Why one VM and not ECS Fargate

TigerBeetle (the billing ledger) needs the `IPC_LOCK` capability,
`seccomp=unconfined`, and io_uring. Fargate allows none of these (only
`SYS_PTRACE` can be added, no privileged mode, no custom seccomp). A plain
EC2 VM with Docker Compose runs TigerBeetle with the same flags as local
development — and it means staging runs the exact Compose bundle we hand to
own-DC publishers.

## Secrets — read this

- The Terraform **state files are secrets**: they contain the rendered
  cloud-init — the signing keys, the database passwords, and every secret the
  identity plane generates (the Vault root token, Zitadel's master key and
  console admin password, the Identity Service's session and token-signing
  keys). State is local and gitignored in both stacks. Do not move it to a
  shared backend without encryption.
- The staging VM receives its whole configuration — **every secret above
  included** — as EC2 user data. Anyone with EC2 read access in the AWS
  account can read user data back through the API
  (`ec2:DescribeInstanceAttribute`); IMDSv2 only protects the on-instance
  path.

  This was accepted when the bundle carried only staging signing keys, which
  are trivially regenerated. The identity plane widened it: the Vault root
  token unlocks every agent key the service custodies, and the Zitadel admin
  password controls the provider that gates developer sign-up. Whoever reads
  the user data can therefore sign RAMP requests as any agent registered on
  the instance. Still accepted for staging — the agents are test identities on
  a throwaway VM — but it is impersonation exposure now, not just key
  disclosure, and the AWS account's EC2 read access is what bounds it.

  Before any production use of this pattern, secret delivery must move to a
  secrets store (SSM Parameter Store / Secrets Manager) fetched at boot with
  an instance role.
- `terraform.tfvars` / `*.auto.tfvars` and `stacks/staging-aws/keys/` are
  gitignored. Only the `.example` files are committed.
- Follow-up (not baseline): SOPS-encrypted tfvars or an encrypted remote
  backend.

## Deferred scope

Recorded here so nobody hunts for the missing pieces:

- **S3 object-storage export**: design only, no code — nothing to deploy.
- **Durable agent key custody**: the bundled Vault runs in dev mode, so its
  store is in-memory and a restart loses every custodied agent key. A sealed
  Vault with real storage and an auth method other than a root token is the
  production shape.
- **Splitting the Compose bundle**: it now carries the agent-identity plane
  (Identity Service, Vault, Zitadel) alongside the publisher-facing services.
  A publisher running only an Exchange and Broker does not need those three,
  and cannot currently switch them off.
- **External Postgres**: every database in the bundle is a container it starts
  itself. Nothing accepts an existing instance's endpoint.
