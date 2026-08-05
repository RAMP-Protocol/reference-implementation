# RAMP — snapshot

This document is a snapshot of the current repository state. It describes
what is here, not how it got here.

## 1. What this is

RAMP is a content-licensing protocol that lets autonomous agents
discover, pay for, and fetch licensed content from publishers. This
repository implements the protocol as a working vertical slice:

```
Agent ── MCP ──► Identity ──► Broker ──► Exchange ──► (signed URL) ──► Edge ──► Origin
```

An agent connects to the **Identity** service's MCP endpoint and calls
one of five `ramp_*` tools (`ramp_register`, `ramp_discover`,
`ramp_execute`, `ramp_report`, `ramp_status`). Identity turns each tool
call into a key-signed RAMP request (RFC 9421, signed with the agent's
registered key) and forwards it to the **Broker**, which discovers the
right exchange (EXA-backed discovery, `ramp.json` probe, bare-URL
fallback), relays to the **Exchange**, and relays back a signed URL plus
transaction metadata. The agent fetches the signed URL through the
**Edge**, which verifies the signature and reverse-proxies to the
publisher Origin. The Exchange writes a ledger row. The agent reports
usage back through the same path.

## 2. Components

| Component | Path | Stack | Role |
|---|---|---|---|
| Identity | `src/identity/` | Go, Connect-Go, Postgres, Vault, Zitadel | Web Bot Auth registry: agent directories, developer sign-up (Zitadel-backed OIDC), per-agent key custody (Vault keystore), and the MCP adapter (`internal/mcp`, five `ramp_*` tools) that signs each tool call as a RAMP request |
| Broker | `src/broker/` | Go, Connect-Go, Postgres + Redis | Exchange discovery (EXA-backed, `internal/exa`) and routing; relays signed RPCs to the Exchange |
| Exchange | `src/exchange/` | Go, Connect-Go, Postgres (sqlc), TigerBeetle | Owns the catalog, mints offers and signed URLs (Ed25519 or CloudFront RSA per tenant), writes the transaction log; TigerBeetle-backed billing ledger (`internal/sor`) |
| Edge | `src/edge/` | TypeScript, Hono | Multi-runtime signed-URL verifier (Cloudflare Miniflare, Fastly Compute via Viceroy, AWS Lambda@Edge); verification via `@ramp-protocol/sdk-l1` |
| Shared Go | `internal/` | Go | 18 packages: `agentid`, `agentkeys`, `clock`, `db`, `guards`, `httpsig`, `keypolicy`, `pemkeys`, `proto`, `rampauth`, `rampcost`, `ramphttpsig`, `rampwellknown`, `replay`, `reqctx`, `runhttp`, `testutil`, `wellknownbuild` |

The canonical protocol is `github.com/RAMP-Protocol/protocol`, pinned in
the root `go.mod` at `v0.1.1-0.20260731084709-104d867aa9a1` (a
pseudo-version past `v0.1.1`). The repo carries no local `proto/`
directory; generated Go bindings come from the published module. The
edge worker consumes the same protocol repo as `@ramp-protocol/sdk-l1`,
pinned by commit in `src/edge/package.json`.

## 3. Deploying

Two paths, usable independently.

### Terraform stacks (reference)

`deploy/terraform/` is a self-contained deployment package. Use it as
the reference for setting up everything at once, or the edge alone:

| Stack | Path | What it deploys |
|---|---|---|
| All-inclusive staging | `deploy/terraform/stacks/staging-aws/` | One EC2 VM running the whole platform via Docker Compose (Postgres, Redis, TigerBeetle, Exchange, Broker, Identity with key store and OIDC provider, Caddy for TLS, demo publisher origin); Cloudflare provides DNS and runs the edge worker |
| Standalone edge | `deploy/terraform/stacks/edge/` | ONLY the Cloudflare edge worker, applied by a publisher against their own Cloudflare account; needs nothing else from the package |
| AWS demo | `deploy/terraform/stacks/demo-aws/` | The AWS-fronted demo deployment (CloudFront + Lambda@Edge edge) |

Start at `deploy/terraform/README.md`. Step-by-step guides live in
`deploy/terraform/docs/`: `deploy-staging-aws.md`,
`deploy-edge-standalone.md`, `deploy-demo-aws.md`, `variables.md`, and
`teardown.md`. The Compose file the staging stack renders is also the
reference bundle for a publisher running the backend in their own data
center — staging tests the exact artifact handed over.

### Per-component deployment (on your own)

Each component can be deployed separately, without Terraform. Every
deployable piece carries its own `DEPLOYMENT.md` with the container,
configuration, and wiring it needs:

- `src/exchange/DEPLOYMENT.md`
- `src/broker/DEPLOYMENT.md`
- `src/identity/DEPLOYMENT.md`
- `src/edge/DEPLOYMENT.md`
- `deploy/storage/postgres/DEPLOYMENT.md`
- `deploy/storage/redis/DEPLOYMENT.md`
- `deploy/storage/tigerbeetle/DEPLOYMENT.md`
- `deploy/storage/vault/DEPLOYMENT.md`
- `deploy/zitadel/DEPLOYMENT.md`

## 4. Pointers

- Canonical proto: <https://github.com/RAMP-Protocol/protocol> at
  `v0.1.1-0.20260731084709-104d867aa9a1` (pinned in `go.mod`)
