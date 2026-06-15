# ADR-005 — Biscuit Transport Carriage and Canonical-Form Request Binding (Gate F)

**Status:** Accepted + Implemented (2026-04-26)
**Tracks:** ye6f-12 (agentic-content-access-x9pr, shipped) + agentic-content-access-xp2e (this ADR) + agentic-content-access-e9vt (Gate F implementation, forthcoming).
**Refines / extends:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — single biscuit + mandatory per-request attenuation; this ADR pins WHERE the biscuit lives on the wire and HOW it binds to the request body.
- `docs/architecture/adr-004-protocol-layers.md` — this ADR is the concrete realization of ADR-004's "inner layer is transport-independent" claim. Canonical-form request-hash is the mechanism.
**Companion documents:**
- `docs/architecture/adr-003-key-rotation-revocation.md` — rotation semantics for the keys that sign the attenuation block.
- `docs/architecture/adr-006-broker-intermediation.md` (forthcoming) — depends on Pattern-2 attenuation-append, established here.
- `docs/design/request-lifecycle.md` §2a — runtime flow.
- `proto/ramp/v1/ramp.proto` — top comment documents the three-tier rule.

---

## Context

Three unresolved questions forced this ADR:

1. **Where does the biscuit live on the wire?** HTTP can carry it in a header; non-HTTP transports (A2A, MCP tool-to-tool, queues, archives, dispute replay) cannot. A header-only design ties RAMP to HTTP and breaks ADR-004's inner-layer transport-independence. A proto-only design drops the RFC 9421 coverage and the enterprise SIEM visibility that ADR-004's outer layer depends on. Both are unacceptable.

2. **How does the biscuit bind to the request body?** RFC 9421 binds header to body at the HTTP layer — but if the biscuit isn't in a header (Tier 2 envelope, Tier 3 sub-message), RFC 9421 cannot cover it. The inner layer needs a body-bind that does not depend on the transport.

3. **How do bridges work?** An intermediary (broker) that receives a `RAMPRequest` from a non-HTTP transport and forwards it over HTTP must move the biscuit from envelope to header. If the signature binding depends on "biscuit was in envelope at sign time," bridging breaks the signature. If the binding depends on "biscuit is somewhere in the message," bridging works — but then the signature doesn't pin the biscuit to the request in a useful way.

A 2026-04-23 design review resolved these three questions together. The biscuit has three possible carriers per transport mode, and the binding is a canonical-form hash that explicitly excludes the biscuit-carrier fields so bridges are free.

---

## Decision

### Part 1 — Three-tier biscuit carriage

The biscuit is carried in one of three tiers. The tier is determined by the transport mode; the sender populates exactly one carrier per request; Exchange enforces strict exactly-one intake.

**Tier 1 — HTTP + Connect-Go wire.**
Biscuit rides the `X-RAMP-Entitlement-Biscuit` HTTP header (base64url-encoded, 8 KiB cap, HTTP 431 on overflow). The `RAMPRequest.entitlement_biscuit` envelope field (proto field 8) AND every sub-message `entitlement_biscuit` field MUST be empty. RFC 9421 `Signature-Input` covers `x-ramp-entitlement-biscuit` so the header binds to the body at the transport layer.

**Tier 2 — `RAMPRequest` envelope.**
For transports that carry proto bytes without HTTP framing: archives, queues, dispute-resolution replay, A2A where both sides speak proto. Biscuit rides `RAMPRequest.entitlement_biscuit` (field 8, `optional bytes`). Sub-message `entitlement_biscuit` fields MUST be empty. No HTTP header exists.

**Tier 3 — Sub-message standalone.**
For surfaces that auto-derive schemas from function signatures (FastMCP, MCP signature-style RPC, any flat-parameter RPC where the top-level message IS the sub-message). Biscuit rides the sub-message's own `entitlement_biscuit` field: `ResourceQuery #12`, `TransactionRequest #13`, `ResourceQuery #3`, `TransactionRequest #3`. No envelope. No HTTP header.

**Intake rule at Exchange.**
Precedence on intake: header > envelope > sub-message. Zero carriers populated → `connect.CodeUnauthenticated "biscuit missing"`. More than one carrier populated → `connect.CodeInvalidArgument "conflicting biscuit carriers"`, regardless of whether the bytes are byte-identical. The sender has a bug and should pick one tier; tolerant fallback would hide integration bugs at bridges.

**Bridges.**
Intermediaries that translate between transports MUST move the biscuit from the inbound carrier to the outbound carrier appropriate for the outbound transport AND MUST NOT leave the biscuit populated in the inbound carrier. Current Broker implements this at the HTTP level only (relay X-RAMP-Entitlement-Biscuit verbatim); future envelope-aware brokers grow the translation path. See ADR-006 for the authorization-chain extension that governs which intermediaries are permitted to do this translation.

### Part 2 — Canonical-form request-hash binding (Gate F)

Every per-request attenuation block (appended by the buyer-side delegation key at call time, mandatory per ADR-002) MUST carry one additional Datalog fact:

```
request_hash(hex($bytes));
```

where `$bytes = sha256(canonical_request_form)`.

**Canonical form.** The canonical form is the deterministic proto serialization of the top-level message (either `RAMPRequest` or, for Tier 3 standalone calls, the top-level sub-message directly), with the following normalization rules:

1. All `entitlement_biscuit` fields are zeroed (treated as empty bytes) at every depth: `RAMPRequest.entitlement_biscuit` (field 8), `ResourceQuery.entitlement_biscuit` (field 12), `TransactionRequest.entitlement_biscuit` (field 13), `ResourceQuery.entitlement_biscuit` (field 3), `TransactionRequest.entitlement_biscuit` (field 3). Biscuit is opaque framing; the hash commits to request substance, not to where the biscuit rides.
2. Proto deterministic-marshal semantics: fields encoded in ascending field-number order, map entries sorted by key, no unknown fields preserved, zero-length optional fields omitted.
3. Unknown proto fields: rejected (canonical form requires schema consensus between attenuator and verifier).

**Gate F at Exchange.** Between Gates A–E and the final authorizer, compute `sha256(canonical_form(received_request))` and assert equal to `attenuation.request_hash`. Denial reason: `request_body_tamper`. Maps to `connect.CodePermissionDenied`. Gate F runs after carrier resolution (ResolveBiscuit / CanonicalBiscuit) and before biscuit-chain verification — in order, A/B/C/D/E/F all independent.

**Attenuator responsibility.** The MCP shim's per-request attenuator (`src/mcp/src/ramp_mcp_shim/entitlement.py`, `entitlement_biscuit_py.py`) computes `sha256(canonical_form(outbound_request))` immediately before appending the attenuation block and emits it as the `request_hash` fact. The attenuation block's existing `sub(...)`, `operation(...)`, `resource_prefix(...)`, `time(T<T+ttl)` facts are preserved.

**Bridges are free.** Because canonical form strips all biscuit-carrier fields, an intermediary that moves the biscuit from envelope to header (or any other tier transition) does not change the canonical form and does not invalidate the `request_hash` fact. The hash covers what it was designed to cover: request substance, not carriage.

### Part 3 — Pattern-3 explicitly rejected

Intermediaries MUST NOT re-sign requests on behalf of the originating agent. Specifically:

- A broker receiving a biscuit with attenuation from Agent A MUST NOT strip Agent A's attenuation and replace it with its own.
- A broker MAY append its own attenuation block to the existing chain, documenting that the broker forwarded the request. This is a future feature; Pattern-2 attenuation-append is the sanctioned mechanism.
- Every hop in the chain is cryptographically visible end-to-end. Exchange sees the full attenuation chain and can enumerate every signer.

**Rationale.** A re-signing broker (Pattern 3) breaks end-to-end transparency: Exchange cannot tell whether the request came from Agent A or from the broker impersonating Agent A. Shadow exchanges — unauthorized intermediaries that insert themselves in the chain — become detectable only via out-of-band means. Pattern-2 attenuation-append keeps every hop visible in the biscuit chain; combined with ADR-006's `authorized_intermediaries` authority-block fact, Exchange can verify that every appending intermediary was authorized by the resource owner.

---

## Consequences

### Positive

- **ADR-004's inner layer is now fully transport-independent.** Biscuit rides any of three carriers; binding to body does not depend on HTTP headers; bridges are free because canonical form excludes carriers.
- **RFC 9421 is demoted cleanly.** From "primary body-bind for authz" to "transport integrity + SIEM observability." ADR-004 called this; Part 2 makes it real.
- **Gate F catches body tampering at biscuit layer.** Even if RFC 9421 is stripped or ignored (non-HTTP transports, or an adversary who replays the biscuit against a different body), the request_hash fact binds biscuit to body at the authz layer.
- **ADR-006 becomes implementable.** Pattern-2 attenuation-append is the mechanism that makes intermediary hops visible. ADR-006 governs which appends are authorized.

### Negative

- **Attenuator complexity increases.** The MCP shim's `EntitlementAttenuator` must canonicalize the outbound request before attaching the attenuation. Implementation cost is small (proto deterministic marshal + zero-fill helper) but introduces a new source of subtle bugs if the sender and verifier disagree on canonical form.
- **Canonical-form bugs are silent.** A mismatch between attenuator canonicalization and verifier canonicalization presents as Gate F denial with reason `request_body_tamper` — indistinguishable from an actual tampering attempt at the log level. Mitigation: explicit unit tests that roundtrip (marshal → attenuate → canonicalize → marshal → attenuate → canonicalize) identically at MCP shim and Exchange; test that carrier-location changes produce identical canonical forms.
- **Unknown-field rejection is strict.** An older Exchange parsing a newer request will reject it rather than accept with unknown fields. Mitigation: proto schema versioning carried in `RAMPRequest.ver`, coupled with a client-side version negotiation before sending with unknown fields present.

---

## Rejected alternatives

### Hash-over-biscuit-populated-form

Compute `request_hash` over the canonical form with the biscuit present at the tier where the attenuator placed it. Rejected because this breaks bridges: an intermediary that moves the biscuit from envelope to header produces a different canonical form and invalidates the hash. Either bridges become impossible (kills Tier 2↔Tier 1 translation) or the canonical-form rule requires the attenuator to know the outbound tier (kills transport-independence).

### Hash-over-body-only, no biscuit-carrier logic

Hash covers the request body as originally sent, without any zero-filling logic. Rejected because the attenuator and verifier end up hashing different bytes whenever the carrier differs — same root cause as above.

### Multiple hashes, one per tier

Attach three `request_hash` facts, one for each canonical form (biscuit-in-header-form, biscuit-in-envelope-form, biscuit-in-submessage-form). Rejected because it triples attenuation size, requires the attenuator to decide three canonicalizations it doesn't need, and Exchange picks whichever matches its received tier — effectively a tolerant match that the strict exactly-one-populated rule explicitly rejects.

### Keep RFC 9421 as primary body-bind, skip Gate F

Rejected because RFC 9421 is HTTP-only; non-HTTP transports would have no body-bind. Viable only if we give up ADR-004's inner-layer transport-independence.

### Pattern 3 — broker re-signs on behalf of agent

Rejected on user direction (2026-04-23): "We want full transparency between the moment of the request by an agent and the moment that the final exchange receives the request. Every step cryptographically signed in both directions, no exceptions." Pattern-2 attenuation-append preserves full chain visibility; Pattern 3 collapses hop visibility into broker identity.

---

## Non-goals

- This ADR does not redesign the Exchange gate order. Gates A–E are unchanged; Gate F is added after them.
- This ADR does not change the biscuit library choice (biscuit-go at Exchange, biscuit-python at MCP shim). The `request_hash` fact is a Datalog fact like any other; both libraries support it.
- This ADR does not specify how ADR-006 authorizes intermediaries; it only pins that Pattern-2 attenuation-append is the mechanism ADR-006 builds on.
- This ADR does not cover the `RAMPRequest` envelope's use in future transports (Kafka, NATS, A2A bindings). Those are out-of-scope deployments; the envelope field is provided so they can be built.

---

## Implementation follow-up

Filed as beads `agentic-content-access-e9vt` (Implement Gate F) — **closed**. Scope: canonical-form helper + MCP shim request_hash emission + Exchange Gate F + unit + integration tests + request-lifecycle.md update.

Wire-in landed via beads `agentic-content-access-ihgb` (Wire Gate F into Exchange service-layer authorizer) — **closed**, commit `6f5d102` on `refactor/state-schema-redesign` (2026-04-26). Gate F is wired end-to-end at Exchange `ExecuteTransaction`:

- ExecuteTransaction authorizer: `src/exchange/internal/service/execute_transaction.go` (`authorizeAccept` → `runGateF`).
- Verifier extracts `request_hash` via `tok.Code()` regex: `src/exchange/internal/entitlement/verifier.go`.
- Gate F primitive: `src/exchange/internal/policygate/fivegate.go`.
- Canonical hash: `internal/rampcanonical/hash.go`.
- E2E tests (happy / tamper / staged-rollout): `src/exchange/internal/transport/gatef_integration_test.go`.

**Staged rollout still active.** When the inbound biscuit's attenuation block lacks a `request_hash` fact, Gate F is a no-op (passes). Strict presence will be enforced once buyer-side MCP shims emit `request_hash` in production; the no-op path is retained until then so partner integrations that have not yet upgraded their attenuator do not break.

---

## References

- ADR-002 — single biscuit + mandatory per-request attenuation (the source of the attenuation block this ADR extends).
- ADR-003 — key rotation and revocation (the keys that sign the attenuation and the rotation lifecycle that governs them).
- ADR-004 — protocol layers (the two-layer framing that makes "biscuit is transport-independent" meaningful).
- ADR-006 (forthcoming) — broker intermediation and transparency chain, which depends on this ADR's Part 3.
- `docs/design/request-lifecycle.md` §2a — end-to-end runtime flow; updated in e9vt to reflect Gate F.
- `proto/ramp/v1/ramp.proto` — top comment documents the three-tier rule and (post-e9vt) the six-gate verification order.
