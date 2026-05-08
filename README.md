# RAMP — Reference Implementation

A working multi-language implementation of the [RAMP protocol](https://github.com/RAMP-Protocol/protocol) for licensed AI content access.

The reference implementation pairs an Exchange (offer signing, transaction execution, signed-URL minting), a Broker (discovery, marketplace routing), an Edge worker (bot detection, signed-URL gate), and an MCP shim (`ramp_fetch` tool for MCP-aware agents). Together they let an autonomous agent discover, negotiate, and pay for licensed content access without exposing the underlying delivery URL to the agent and without sharing secrets across tenants.

## Components

| Path | Language | Role |
|------|----------|------|
| [`src/exchange/`](src/exchange/) | Go (Connect-Go, `pgx/v5`, sqlc) | Offer signing, transaction log, signed-URL minting (Ed25519 or RSA CloudFront), usage reporting |
| [`src/broker/`](src/broker/) | Go (Connect-Go, Postgres + Redis) | Marketplace registry, agent budget, discovery (EXA), Exchange relay |
| [`src/edge/`](src/edge/) | TypeScript (Hono, multi-runtime) | Cloudflare Workers / Fastly Compute / AWS Lambda@Edge bot-redirect + signed-URL verification |
| [`src/mcp/`](src/mcp/) | Python (FastMCP, `httpx`) | `ramp_fetch` MCP tool — exposes RAMP to MCP-aware agents (Claude Desktop, Cursor, etc.) |
| [`internal/`](internal/) | Go | Shared packages: db setup, HTTP server harness, proto re-exports |
| [`proto/`](proto/) | Protobuf + generated Go/TS | RAMP wire format |
| [`tests/e2e/`](tests/e2e/) | Python (pytest) + docker-compose | End-to-end suite covering bot redirect, signed URL, ramp.json discovery, MCP negotiation |

## Quick start (local stack)

Requires `docker`, `go ≥ 1.23`, `node ≥ 20` (`nvm use`), and `uv` for the Python shim.

```bash
make test-fast          # unit + lightweight tests across all four languages
make test-integration   # spins testcontainers Postgres for the Go services
make test-e2e           # docker-compose stack: Exchange + Broker + Edge + MCP + Postgres + Redis
```

## Live demo

Deployed at `*.demo.ramp-protocol.org`. Full deploy walkthrough lives in
[`RUNBOOK-aws-demo.md`](RUNBOOK-aws-demo.md). The accompanying
[`docs/HANDOFF-aws-demo.md`](docs/HANDOFF-aws-demo.md) documents the deployed
state, the cryptographic chain, and the operational procedures.

The deploy uses dedicated per-deployment Terraform modules under a separate
infrastructure repository; placeholders (`<AWS_ACCOUNT_ID>`,
`<DEPLOYER_PROFILE>`, etc.) in those files indicate which values you would
substitute when standing up your own copy.

## Cryptographic evidence chain

Every successful transaction produces a six-row reconciliation chain that
spans the Exchange, the Broker, the Edge, and the agent:

```
$ make ledger TX=<transaction_id>

  party     step                event                    correlator                          crypto
  exchange  1. offer issued     DiscoverResources        offer=...                           offer_sig=...
  broker    2a. broker routed   POST /broker/v1/resolve  agent=...  marketplace=...         ✓ broker selected this exchange
  exchange  2b. offer accepted  ExecuteTransaction       tx=...  req=...                    ✓ offer_sig matches step 1
  exchange  3. ledger row       transaction_log INSERT   tx=...                              url_sig=...
  edge      4. signed-URL hit   lambda@edge (region)     tx=...  sig_prefix=...             ✓ url_sig matches step 3
  edge      5. origin served    cloudfront → s3          uri=...  ua=...                     decision=pass:signed
  exchange  6. usage reported   reporting_obligations    tx=...                              ✓ state=RECEIVED
```

The "✓ matches" cells re-derive nothing — they assert that the verbatim
bytes one party stored share the prefix another party logged. Tampering at
any layer breaks the assertion. See [`scripts/ledger.py`](scripts/ledger.py).

## Repository layout

```
src/
  exchange/   Go service — Exchange (offers, transactions, URL signing)
  broker/     Go service — Broker (discovery, marketplace registry, relay)
  edge/       TypeScript worker — runtime-agnostic edge gate
  mcp/        Python shim — FastMCP server with ramp_fetch tool
internal/     Shared Go packages (db, runhttp, proto re-exports)
proto/        Protocol buffers + generated language bindings
tests/        E2E and integration test harness
docs/         Design documents, deployment runbook, protocol notes
scripts/      Operational helpers (ledger, ecr-push, key rotation, secrets wiring)
```

## Status

This implementation tracks the RAMP protocol spec at
[`RAMP-Protocol/protocol`](https://github.com/RAMP-Protocol/protocol). It is a
reference implementation: the transport surfaces, ledger primitives, and
signing schemes are intended to be canonical, while the deployment topology
(AWS Fargate + RDS + CloudFront for the demo) is a single example among
several supported by the edge worker (Cloudflare, Fastly, and AWS).

## License

See [`LICENSE`](LICENSE).
