# ADR-020 — RAMP SDK: Layered Protocol Libraries, Co-located with the Contract, Consumed Off-Commit

**Status:** Accepted

---

## Overview

PR10 in `RAMP-Protocol/protocol` ships generated, field-validated **types** for the wire — Zod (TS), Pydantic (Python), protobuf-go (Go), plus single-source vocabulary modules. That is the *noun* layer: a faithful, validated description of *what is on the wire*. It is not, on its own, an SDK.

What every consumer hand-rolls is the *verb* layer — *how you talk over the wire*: sign the request (RFC 9421), correlate it (`X-Request-ID`), call a Connect method (protobuf **or** JSON), parse a typed `ErrorDetail`, mint/format decimal money, compute a key thumbprint (RFC 7638), build/parse/follow a signed retrieval URL with proof-of-possession. This ADR defines that verb layer — the **RAMP SDK** — its internal layering, where it lives, how it is consumed, and the boundary it must not cross.

The motivation is specific to RAMP being **a protocol with an OSS reference implementation**: third parties are expected to stand up their own Exchanges, Brokers, agents, and edges. If the protocol mechanics live only inside our platform repo as private `internal/` packages, every integrator re-derives them from the spec — and the four we already maintain (Exchange, Broker, MCP, Edge) prove that path produces three independent, drift-prone re-implementations of the same RFC 9421/7638 logic.

## The problem

The cross-cutting protocol mechanics are re-implemented per consumer and per language, today:

- **RFC 9421 sign/verify** — was triplicated: Go `internal/httpsig` (~1.35k LoC) plus the broker `cosign`, a Python implementation in the MCP shim, and a TypeScript one in the edge. The Python and TypeScript copies have since been retired in favour of the SDK.
- **RFC 7638 thumbprint** — was duplicated across Go and Python; it is now single-sourced in the SDK and wrapped by `internal/rampwellknown`.
- **Signed-URL build/parse/follow + PoP** — Exchange mints, Broker passes through, MCP follows, Edge verifies: four ad-hoc takes on one URL format.
- **Connect call + `ErrorDetail`-envelope parse** — Broker `xclient` vs MCP `broker.py`: two client implementations of "signed Connect call, then parse the typed result or the typed error."
- **`X-Request-ID` correlation**, **money-decimal** parse/format (after the PR10 `double → string` change, ~10 sites), **vocab membership** (already generated for all three).

Three failure modes follow: (1) **drift** — the same rule diverges subtly across languages, and RAMP only works if they are byte-identical (signatures, thumbprints, money); (2) **bad integrator DX** — an OSS Exchange author must re-derive all of this from prose; (3) **our own duplication** — ~4.7k LoC of protocol plumbing maintained in parallel.

A second, sharper question this ADR settles: an SDK that bundles validation, signing, and a network client is one step from *owning application concerns* (state, retries, key custody, lifecycle). We must draw that line explicitly, or the SDK quietly becomes a framework.

## Decision

### 1. Four layers, with a hard stop at "transport"

- **L0 — Wire types + field validation (generated).** Zod / Pydantic / protobuf-go + vocab. Pure data; single-source; cannot drift. (Delivered by PR10.)
- **L1 — Stateless protocol helpers (hand-written, pure).** No IO, no state: RFC 9421 sign/verify, RFC 7638 thumbprint, signed-URL build/parse, money decimal parse/format, vocab checks, `ErrorDetail`↔domain mapping, idempotency-key mint — **plus scope/entitlement framing (§5) and the verification logic (§4)**. Consumed by **both** clients and servers.
- **L2 — Transport + orchestration (IO, application-owned lifecycle).** Two faces over the same primitives:
  - **Client + server interceptors** — a configurable Connect client (the application **injects** a signer and a base URL; cross-cutting concerns are composable interceptors: sign · request-id · validate · verify · error-detail) and the mirror-image server interceptors (verify-signature · validate · request-id · error-detail-emit). Methods mirror the protocol (`discover / execute / report / resolve / fetch`). The application owns the instance and decides *when* to call. This is the **low tier** (§2).
  - **Agent convenience** — the batteries-included `fetch(url)` that orchestrates discover→select→execute→fetch→report, with all state **injected** (§2, §3). Returns the canonical typed model. This is the **high tier** (§2), built strictly on top of the low tier.
- **L3 — Framework adapters (optional, separate packages).** Convert the canonical typed model ↔ framework-native shapes (e.g. a LangChain `RampRetriever` returning `Document`s, a `@tool`-wrapped `discover`). **Conversion, never replacement** — the raw canonical model is always reachable underneath. **L3 depends on L2, never the reverse**; the core SDK never imports a framework.

L0/L1 are reusable across every RAMP role in every language; L2/L3 are language-idiomatic (connect-go interceptors, Python `httpx`, Web-Crypto in the edge) and interop-guarded by the conformance suite rather than shared.

### 2. Two tiers, two audiences — state injected at the high tier

The SDK serves two audiences at two altitudes, stacked (never competing):

- **Low tier — the protocol SDK (control).** L0 + L1 + the L2 client/server interceptors. Verb-level, no orchestration, no state. This is what **our own components** (Broker, Exchange, MCP, Edge) and any OSS implementor build on — they own the flow and want the protocol mechanics, nothing more.
- **High tier — the agent SDK (convenience).** The L2 agent-convenience surface (`fetch`) for **external agent developers** who want one call. It MAY offer auto-budget, auto-report, and registry caching — but only via **injected stores** (`BudgetStore` / `ReportSink` / `RegistryCache` interfaces, easy defaults provided): the application owns the state, the SDK orchestrates. It is **opt-in**; drop to the low tier for full control. This reconciles the convenience of the prior "Agent SDK" design (now superseded) with the state-ownership boundary (§3) — the prior design owned state by default; this one injects it.

### 3. The SDK never owns state; it makes state *operations* trivial

Inclusion test — a thing belongs in the SDK **iff** it is (1) protocol-defined, (2) stateless or a single state *operation* (no lifecycle ownership), and (3) duplicated across ≥2 consumers. Otherwise it stays in the application. Concretely the SDK MUST NOT:

- **hold secrets** — the application injects a signer; the SDK never custodies or rotates keys;
- **dedupe/replay** — the SDK *mints/attaches* an idempotency key; the application decides reuse-vs-new; the **server** enforces dedup;
- **own settlement/budget/quota/obligation/dispute state** — the application owns its store; the SDK exposes the typed shape and easy read/write/invalidate calls, and nothing about *when* to call them;
- **retry/wait/cache by default** — opt-in middleware only, off by default; waiting on a long-running process is the application's decision.

The rule of thumb: **if there is a long-running process, the application owns it; the SDK only makes checking, writing, or invalidating that state easy.**

### 4. Verify everything received, fail-closed — verification logic in L1, key resolution injected

Today the agent selects and commits on **unverified** offers. Servers verify their inbound traffic (Exchange: RFC 9421 + offer signature, but only *at execute* — too late to inform selection; Edge: signed-URL + PoP), but the **Broker does not verify the offers it relays** from the Exchange, and the **MCP/agent verifies nothing it receives**. A malicious broker or a MITM can therefore steer the agent's selection with doctored terms that only fail much later at execute. The SDK closes this gap structurally:

- **Split logic from resolution.** The verification **logic** is L1 — pure `(message, pubkey) → ok`. The key **resolution** is an injected `KeyResolver` ("give me the verifying key for this Exchange/keyid"). The SDK ships a default `WellKnownKeyResolver` (fetch `/.well-known/ramp.json` + in-memory TTL cache); the application injects its own for a private registry, a preloaded set, a proxy, or mTLS. The same interface serves the client `Verifier` and the server's verify interceptor. The server-side pieces already exist to reuse (`internal/httpsig` — incl. `keyresolver.go`, `internal/rampwellknown`, `src/exchange/internal/signing`; on the TS side the edge now consumes `@ramp-protocol/sdk-l1/verify` and `/pop`).
- **Verify-everything, fail-closed, by default strict.** The SDK verifies each returned object **before** handing it back. "Can't consume an unverified offer" is made structural: `discover`/`resolve` return `{ verified, rejected }` — the application acts on `verified`; `rejected` (offer + reason) is *visible* but the execute path refuses it. Strictness is configurable, but turning verification **off is a loud, named opt-out** (`WithVerification(Off)`), never silent; acting on a rejected offer requires an explicit `.unsafe()`.
- **One `Verifier` + one `KeyResolver` serves all three roles** — server inbound, edge delivery, client received-offers — and closes the missing one. It *unifies* existing verification surface rather than adding a new one. Scope of "everything": (1) offer signatures (*the gap*), (2) signed-URL (the client can pre-check), (3) content attestations (hash / third-party — a *separate* guarantee: content integrity vs offer authenticity).

### 5. Scopes / entitlements are a supplied credential

"Scopes" — the subscriptions/entitlements the caller holds — follow the **same injection pattern as the signing key**: the application supplies them, the SDK plumbs them into `RAMPRequest`/`ResourceQuery` (requester scopes / delegation / `subscription_id`). The proto already carries the denial vocabulary (`ENTITLEMENT_*`, `SUBSCRIPTION_LAPSED`, `SCOPE_INSUFFICIENT`). **Today the Exchange trusts what is supplied** (no JWT/biscuit issuance yet). When issuance lands, **only the L1 verify implementation changes** — the surface above (`discover(uri, scopes=…)`) does not move. The change is additive.

### 6. The contract repo hosts the SDK; consumers pin a commit

The `RAMP-Protocol/protocol` repo — which already hosts `gen/{go,ts,python}` — is the SDK's home. It is organized as **conventional per-language packages**, not a monorepo build system:

```
RAMP-Protocol/protocol
├── proto/                  # the contract
├── gen/{go,ts,python}/     # GENERATED  (L0 types + vocab) — single source, no drift
└── sdk/{go,ts,python}/     # HAND-WRITTEN (L1 helpers · L2 client+interceptors+agent convenience · L3 framework adapters)
```

Consumed **off-commit** while the contract is in flux — every ecosystem supports a git+commit(+subdir) dependency natively, so **no registry publish and no semver tag are required**:

- Go: `go get github.com/RAMP-Protocol/protocol/...@<sha>`
- TS: `"@ramp/sdk": "github:RAMP-Protocol/protocol#<sha>&path:/sdk/ts"`
- Python: `pip install "ramp-sdk @ git+https://github.com/RAMP-Protocol/protocol@<sha>#subdirectory=sdk/python"`

A Go consumer pulls only the Go subtree (no TS/Python toolchain), and so on. When the contract stabilizes, the same repo can be semver-tagged and the packages optionally published to npm/PyPI for external integrators — **no restructure**.

### 7. The platform becomes a pure consumer

The platform imports the protocol SDK and deletes its own copies of the protocol mechanics. Partly executed: `rampthumbprint` and `rampcodec` are gone and the MCP and edge re-implementations have been replaced by SDK imports, while `internal/{httpsig, ramphttpsig, rampwellknown}` remain — `rampwellknown` now as a thin wrapper over the SDK helper. The dependency is one-way (`platform → protocol-SDK`); no circular dependency, no shared build system. Business logic — selection ranking, budget policy, the billing adapter, catalog management — never moves; only protocol mechanics do.

`internal/reqctx` is the one **deliberately retained** member of the original deletion set: it is request-id correlation middleware + a reject-logger, i.e. application-owned structured logging (Architecture Rule 8), not a protocol verb. Its protocol-shaped part already delegates to the SDK (`connectserver.ClassifyReject` / `WithOnReject`); the request-id-scoped logging stays app-side. Retaining it is intentional and not a gap against this section or the SDK-extraction acceptance criteria.

### 8. Migration is relocation, done green-to-green

The ~4.7k LoC already exist and are tested; this is a strangler/repackage, not a rewrite. Order by language, one consumer at a time, suite green throughout:

- **L1 helpers are flow-agnostic** (signing, thumbprint, signed-URL, money) — extract them at any time, independent of the broker two-phase reconciliation (ADR-019).
- **The Broker's L2 client** (its calls to the Exchange) changes shape with the two-phase relay — sequence that slice *after* the relay lands.
- **Both tiers are designed up front, but the low tier ships first.** Our own components need the low tier now; the high tier (agent SDK) follows on top. Designing both up front is load-bearing: the high tier's injected-store interfaces (`BudgetStore` / `ReportSink` / `RegistryCache`) must shape the low-tier surface from the start so the high tier adds *no* breaking reshape later. The companion API-surface design fixes the surface-level choices — `Decimal`-in/string-wire money, throw + `safe()` errors, async-first + Python sync facade, one-package-modular packaging, runtime `{verified, rejected}` + a `VerifiedOffer` compile guard.

The one load-bearing invariant: RFC 9421 canonicalization and RFC 7638/money formatting must stay **byte-identical** across the move (they already are — the four components interoperate today) and are guarded by the cross-language conformance suite.

## Consequences

- **Single source for the verb layer** co-located with the noun layer it implements — the SDK cannot drift from the contract (the dominant SDK rot).
- **OSS integrators get a real SDK**, not a spec to re-derive — types + signing + client + interceptors from one pinned commit.
- **The client-side verification gap closes** (§4): the agent stops selecting on unverified offers, fail-closed by default, with no new verification surface — the same `Verifier`/`KeyResolver` serves server-inbound, edge-delivery, and client-received roles.
- **Two audiences, one stack** (§2): external agent developers get a one-call high tier; our own components keep the verb-level low tier. The high tier's convenience never costs the state boundary — stores are injected.
- **Framework reach without framework coupling** (§1, L3): LangChain/LlamaIndex adapters are opt-in, separate packages depending on L2; the core SDK imports no framework.
- **The platform sheds ~4.7k LoC** of duplicated plumbing; net complexity drops.
- **One pin per consumer** (the protocol commit) — no version matrix, no multi-repo lockstep.
- **Cost:** the protocol repo grows hand-written code (already true since it carries `gen/`); cross-language consistency becomes a standing obligation, paid for by the conformance suite; off-commit pins churn while the contract is in flux (acceptable, and a sign to stabilize + tag when churn slows).

## Rejected alternatives

- **Separate `ramp-sdk-{go,ts,python}` repos.** The multi-repo version-matrix problem (which SDK commit pairs with which proto commit) and a publish pipeline per repo — exactly the lockstep pain we want to avoid.
- **SDK as platform-internal `pkg/`.** Not consumable by external integrators or by the Edge as a package, and it couples the protocol's reusable mechanics to one implementation's repo.
- **A heavyweight monorepo build (Bazel/Nx/Turborepo) in the protocol repo.** Overkill: per-language packages in subdirectories need no cross-language build orchestration.
- **Generate the helpers too.** Signing, the transport client, and the interceptors are idiomatic per language (connect-go vs `httpx` vs Web-Crypto) and cannot be generated from JSON Schema; they are hand-written and interop-tested.
- **Publish to npm/PyPI now.** Premature while the contract is in flux; off-commit consumption is sufficient and avoids release ceremony. Revisit on stabilization.
- **Leave it as types-only (status quo).** Pushes the verb layer onto every integrator and keeps our four-way duplication — the failure mode this ADR exists to end.

## Non-goals

- Not replacing application business logic, policy, or orchestration. (The high tier orchestrates the protocol flow; it does not own the policy or the state behind it — those are injected.)
- Not holding keys, settlement/budget/obligation/dispute state, scope/entitlement state, or any long-running process.
- Not importing or wrapping any agent framework in the core SDK — framework adapters (L3) are separate, opt-in packages that depend on the SDK, never the reverse.
- Not issuing scope/entitlement credentials (JWT/biscuit) — the SDK plumbs supplied scopes and verifies them; issuance, when it lands, changes only the L1 verify implementation (§5).
- Not mandating retry, caching, or waiting (opt-in, off by default).
- Not a semver release or registry publication — those follow stabilization.
- Not redefining the wire contract (ADR-019) or the success-side licensing model (ADR-014).

## References

- ADR-019 — Proto-Defined Error and Response Contract (the typed `ErrorDetail` the SDK maps).
- ADR-014 — Universal Licensing Core (the success-side shapes the SDK carries).
- ADR-013 — agent identity / proof-of-possession (the signed-URL + PoP helpers).
- `RAMP-Protocol/protocol` PR10 — generated Zod + Pydantic types + vocab (L0).
- SDK generation and the cross-language conformance suite — the interop guard for L1.
- The inclusion test (§3) — the boundary every future SDK addition is tested against.

---

## Addendum (2026-07-01) — L0 validation approach + reconciliation

**Context.** Phase-0 verification found the L0 layer largely *built* but *fragmented* across unmerged protocol-repo branches, and the two languages diverged on *how* they validate: the Python SDK (branch `c0fafba`) shipped a JSON-Schema → `datamodel-code-generator` → Pydantic v2 path with a shared conformance-corpus parity test; the TypeScript side left validation unwired (a half-present `protovalidate-es` import that does not resolve). Reconciliation onto one canonical line is Phase 0.0, which branches off PR15's current tip and becomes the re-pin target.

**Decision — standardize on the corpus-driven JSON-Schema path** for L0 runtime validation, in both languages:

- **Python** keeps `datamodel-code-generator` → Pydantic v2 (already shipped on `c0fafba`).
- **TypeScript** adopts **Zod**, generated to mirror the same JSON-Schema, replacing the half-wired `protovalidate-es` import (and fixing the dangling `buf/validate/validate_pb` reference so the package imports).
- **Per-field rules — deterministically generated.** Types, presence, patterns, bounds, enum membership: the standard `buf.validate` *field* rules compiled JSON Schema → Pydantic / Zod. Fully mechanical, no human input.
- **Cross-field rules — a semi-deterministic, agent-maintained layer (L1/L2 helpers).** They MAY be enforced client-side (not left purely server-side), implemented as hand-authored **Pydantic `@model_validator`** / **Zod `.refine()` / `.superRefine()`** predicates that live as L1 validation helpers. The process is *semi-deterministic*: a deterministic per-message scaffold is emitted from the proto template, and the cross-field predicate body is authored / re-authored / updated by an agent against that template when the contract changes. There is **no CEL / `protovalidate` runtime engine** — the rules are compiled into idiomatic Pydantic/Zod, not interpreted. The **server stays authoritative regardless**: client-side cross-field validation is defense-in-depth + better DX, never the source of truth.
- The **shared conformance corpus** (`conformance/corpus/cases.json`) is the single cross-language source of truth: every SDK — per-field *and* cross-field — asserts its verdict matches the Go oracle for every case (guarded in proto CI).

**Why not `protovalidate-{es,python}` at runtime.** It re-introduces a runtime CEL engine + dependency per language. The same cross-field coverage is achieved by compiling those rules into hand-authored, corpus-guarded Pydantic/Zod predicates — idiomatic, dependency-free, and keyed to one source of truth (the corpus). Revisit only if the hand-authored surface grows unmaintainable.

This refines §1 (L0) and §8: L0 validation is corpus-guarded and JSON-Schema-derived for per-field rules, extended by a semi-deterministic agent-maintained cross-field layer in Pydantic/Zod — full field-and-cross-field parity across languages, without a CEL runtime.
