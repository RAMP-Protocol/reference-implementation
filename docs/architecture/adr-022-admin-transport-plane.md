# ADR-022 — Exchange Admin Transport Plane

**Status:** Accepted

---

## Overview

The Exchange needs an operator control plane: the authoritative place to override the
tenant fee rate and the reporting policy. RSL `<amount>` and sitemap `ramp:rate` supply
only *defaults* at ingestion; without setters, an operator has no supported way to change
the commission rate or the reporting policy (tolerance / window / required fields) in
production. This ADR records how that plane is exposed on the wire and why — a **typed
proto `AdminService` on a separate internal listener, with no request-signing and no
per-operator identity in v1**. It complements ADR-010 (which makes `tenants.fee_rate_bps`
a mutable, writable column) and ADR-019 (the error/response and idempotency contract).

The v1 surface is **two** setters — `SetTenantFeeRate`, `SetReportingPolicy`.
`SetOfferPrice` and `SetDeliveryWitnessMode` are out of scope.

## The problem

These setters change money and policy, so the surface must not be reachable by agents or
the public internet, and it must be traceable after the fact. Three constraints shape the
design:

- **Interoperability + one validation source.** A hand-rolled REST admin endpoint would
  re-express its field rules in each language and each service; the rest of the platform
  already validates on a single proto contract (protovalidate CEL flowing to Go, Zod,
  Pydantic).
- **Plane separation.** The operator/config plane must be delineated from the agent
  hot-path contract so the two evolve independently and cannot be confused at the
  boundary.
- **Attribution without a login.** v1 has no identity server for operators. The surface
  must still leave an audit trail sufficient to detect and reconstruct a change, because
  the setters are full-replace and last-writer-wins.

## Decision

### 1. Typed proto `AdminService`, in its own `ramp.admin.v1` package

The admin surface is a proto-defined Connect service, not plain HTTP — so its field rules
(`fee_rate_bps ∈ [0, 10000)`, the `required_fields` pattern, `quantity_tolerance ∈ [0, 1]`,
`window_seconds ∈ (0, 31536000]`, lengths, uniqueness) are one contract the SDK validates
in every language. It lives in a **separate `ramp.admin.v1` package**, not under
`ramp.v1.ExchangeService`, so the operator/config plane is delineated from the agent
hot-path contract. The messages use a **nested shared-payload envelope**: the payload
(`TenantFeeRate` / `ReportingPolicy`) is shared by the request and its response, so the
echoed read-back cannot drift from the write.

The response envelope — including the `ver` field — is assembled in the **transport
handler** (`admin_handler.go`), not the service. The service returns plain Go value
structs and never imports `ramp.admin.v1`, so the operator/config plane's wire types
stay out of the business layer (the same plane-isolation motive as the separate
package). The setter's input and its echoed result are the same value under
full-replace, so the service represents each with a single shared payload type.

### 2. Raw handler, emit-unpopulated codec, bidirectional validate, NO request-signing

The generated handler mounts **raw** on a dedicated admin mux with three load-bearing
options and nothing else:

- **Emit-unpopulated JSON codec** (`connectserver.EmitUnpopulatedJSONCodec()`,
  `{EmitUnpopulated: true, UseProtoNames: true}`). `fee_rate_bps` is a non-optional scalar,
  so default protojson drops it from the response when it is `0` — hiding the exact value
  the read-back exists to confirm. The codec emits it and keeps snake_case, the RAMP wire
  convention.
- **Bidirectional protovalidate interceptor** (validates requests AND responses, per
  ADR-019). This gives every `buf.validate` bound for free on both directions; the service
  layer does not re-implement range/pattern checks.
- **No request-signing.** The admin plane has no verified RFC 9421 signer. The handler is
  therefore *not* wrapped by the public-surface signature middleware and *not* mounted
  through the `connectserver` verify seam — that seam gates on
  `strings.HasPrefix(path, "/ramp.")`, which matches `/ramp.admin.v1.` too and would
  fail-closed-reject every (unsigned) admin call. The admin mux carries only a request-id
  middleware (correlation, Architecture Rule 8) and the IP-allowlist (§8).

### 3. No `idempotency_key`

Unlike the state-mutating agent RPCs (ADR-019 §4), the admin setters carry no idempotency
key. They are **full-replace** — there is nothing to dedupe — and the admin plane has no
verified signer to dedupe *per*. This is the same rationale that leaves the naturally
idempotent catalog upsert/delete keyless.

### 4. No per-operator identity in v1

There is no operator login and no per-tenant admin scope inside the service. Anyone who can
reach the admin listener from an allowlisted source can call any setter. The **network
layer is the only gate**; the `audit_log` row plus the source address is the only
attribution. This is an accepted v1 posture, recorded so it is a decision and not an
oversight; an identity server + biscuit-scoped admin authz is the post-v1 target.

### 5. Last-writer-wins

The messages carry no `revision` / `applied_at` / etag, so two concurrent operators
silently overwrite each other. There is no optimistic-concurrency check. The **`audit_log`
is the reconstruction path** — each successful setter appends one row (actor, source
address, action, applied values as JSONB, tenant, request id, timestamp) inside the SAME
transaction as the mutation, after the rows-affected check, so an unknown-tenant no-op
persists nothing. Accepted for v1 at 1–3 customers; a bitemporal history is deferred until
a customer asks.

### 6. `0 ≤ fee_rate_bps < 10000` is a protocol invariant, not just a DB mirror

The settlement split charges `feeMinor = floor(gross × bps / 10000)`
(`billing/tigerbeetle_settle.go`); the bound keeps the fee strictly under 100% and integer
basis points avoid float drift. The DB `CHECK` (migration `000019`) and the proto rule are
**two expressions of one invariant**, per ADR-010 **D1** (the mutable `fee_rate_bps` +
`fee_rate_notes` column), with **D4** explaining why mutability is safe — historical
ledger postings carry their own truth, so the rate column is freely re-writable without
rewriting history — and **Amendment B** making the tenant rate the default/fallback under
per-`(tenant, resource_owner)` overrides. The setter writes the tenant-level default; an
override, if present, shadows it. The rate is resolved live at Authorize and frozen on the
hold, so a change takes effect on transactions authorized after the call, never
retroactively.

### 7. Full-replace semantics; `quantity_tolerance = 0` is exact-match

Both setters are full replace, never "leave unchanged": a zero value is never read as
"unset". Omitting `notes` clears the column to NULL. Omitting a `ReportingPolicy` optional
falls back to the Exchange default; setting `quantity_tolerance = 0` means **exact match**,
which the report validator now honours (the prior `tol <= 0` fallback that swallowed an
explicit zero into ±20% was a bug fixed alongside this surface).

### 8. Second internal listener + IP-allowlist; networking split out

The Exchange runs a **second listener** on `ADMIN_ADDR`, co-managed with the public
listener under one signal-driven shutdown context, serving the admin mux. An **IP-allowlist
middleware** parses operator CIDRs/IPs, takes the source from `RemoteAddr` (never
`X-Forwarded-For`), and rejects (403) anything off the list; an empty allowlist denies
everything (fail-closed). The deployment-side controls — binding the listener to an
internal interface, the firewall / security-group operator ranges, keeping the admin port
off the public ingress — are **deployment-side work, out of scope here**. **mTLS is deferred**
(dropped from the v1 auth model). *Handoff caveat:* if the admin port is ever fronted with
a proxy, `RemoteAddr`
becomes the proxy address and the allowlist goes vacuous — bind directly, do not front.

## Consequences

- **Positive.** One validated contract for the admin surface across languages; the
  operator plane is a distinct package and a distinct port, so it cannot be confused with
  or reached through the agent hot-path; every change is attributable through the
  `audit_log` even without an operator login; the read-back confirms the persisted value
  exactly (emit-unpopulated) so tooling can verify a `0` fee took effect.
- **Negative.** No per-operator identity and no optimistic concurrency in v1: an
  allowlisted caller can overwrite another operator's change silently, recoverable only
  from the audit log. Network reachability, not code, is what protects the plane, so a
  misconfigured deployment (admin port on the public interface) is a real exposure —
  mitigated by fail-closed allowlist defaults and the handoff.

## Rejected alternatives

- **Plain HTTP/JSON admin endpoint.** Re-expresses field rules per language and per
  service; loses the single validated contract and cross-language conformance.
- **Admin methods on `ramp.v1.ExchangeService`.** Collapses the operator/config plane into
  the agent hot-path contract and pushes the service past the god-class method budget.
- **Mounting admin behind the `connectserver` verify seam.** The seam matches
  `/ramp.admin.v1.` and would fail-closed-reject unsigned admin calls; the plane has no
  verified signer.
- **Reviving `/admin/*` on the public mux.** That REST shortcut was deliberately removed;
  two tripwire tests keep it at 404. The new surface is a signed-off separate listener, not
  a return of the shortcut.
- **An `idempotency_key` on the setters.** Full-replace has nothing to dedupe and there is
  no verified signer to dedupe per.
- **Per-operator identity / optimistic concurrency in v1.** Both are real post-v1 work; at
  1–3 customers the network allowlist + audit log is the accepted posture, recorded here so
  the gap is a decision.
- **mTLS in v1.** Dropped from the v1 auth model; the deployment-side network controls are the v1
  boundary.

## Non-goals

- Does not design the deployment-side network controls (internal-interface binding,
  firewall/security-group ranges, ingress) — those are deployment-side work.
- Does not add an operator identity server or per-tenant admin scope (post-v1).
- Does not add rate-change history / bitemporality — deferred per ADR-010 "Out of scope".
- Does not cover `SetOfferPrice` (v1.1) or `SetDeliveryWitnessMode`.

## References

- **ADR-010** — Publisher Payout — **D1** (mutable `fee_rate_bps` + `fee_rate_notes`
  column), **D4** (why mutability is safe), **Amendment B** (tenant rate as default under
  per-owner overrides). The fee-rate invariant this ADR's setter enforces.
- **ADR-019** — Proto-Defined Error and Response Contract — the `ver` envelope, the
  transport-error mapping the admin handler reuses, and the idempotency rationale this ADR
  applies in the negative.
- **`github.com/RAMP-Protocol/protocol`** — `proto/ramp/admin/v1/admin.proto` (the landed
  contract, pinned via `go.mod`).
- **Deployment-side networking** — internal bind, firewall, ingress — is tracked separately.
