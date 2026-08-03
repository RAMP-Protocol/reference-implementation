# ADR-007 — Per-Request Freshness Primitive: Wiring on Negotiation Handlers

**Status:** Accepted as a design (2026-05-04). **Not implemented — the primitive it wires no
longer exists.** This ADR's premise was that the freshness check already existed as `GateA` in
the Exchange policy-gate package and only needed calling on the negotiation path. That package,
the entitlement-biscuit layer it gated, and the per-request attenuation blocks it inspected were
all deleted in the v1 scope cut. Nothing replaced them: no surface enforces attenuation
freshness today. Kept for the reasoning; reinstating it means rebuilding the primitive first.
**Tracks:** the per-request freshness wiring.
**Supersedes / Closes:** the parked design-work cluster from the xfail audit.

**Companion documents:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — defines the primitive (mandatory per-request attenuation block, ≤10-minute TTL, buyer-signed).
- `docs/architecture/adr-004-protocol-layers.md` — the layer (transport vs negotiation vs authorization) the wiring lands in.
- `docs/architecture/adr-005-biscuit-transport-canonical-binding.md` — Gate F (canonical-form request_hash) shares the attenuation-block surface with the freshness primitive.
- The freshness check existed as `GateA` in the Exchange policy-gate package at the time of writing; this ADR's wiring was what would call it on the negotiation path. Both the gate and the package have since been deleted.

---

## Context

ADR-002 §B specifies a per-request freshness primitive: every entitlement biscuit on the wire MUST carry a buyer-signed attenuation block whose deepest `time() < T` Datalog check satisfies `T > now AND T - now ≤ 10m`, plus a `sub(jwt.sub)` fact and a chain signature that binds back to the authority block's `buyer_delegation_pubkey`. The authority block carries `check if signed_by(buyer_delegation_pubkey)` so a bare authority is structurally unverifiable — the design intent is that the freshness gate fires every time.

`GateA` implemented that check exactly: it consumed `AttenuationFacts{Present, SignedByBuyer, Sub, TTL, …}`, returned `ErrAttenuationStale` with a specific message when any of the four sub-conditions failed, and was composed into the gate chain alongside Gates B–F. The whole chain was removed in May 2026.

The negotiation surface — `OffersService.DiscoverResources` (via `verifyEntitlements`) and `OffersService.ExecuteTransaction` (via `verifySubscriptionCoverage`) — does NOT call `policygate.Run` and does NOT call `GateA` directly. It calls only `entitlement.Verifier.Verify`, which performs biscuit-go chain verification + the RAMP narrowing-only invariant + authority-block fact extraction, but does NOT enforce the attenuation block's presence, TTL cap, or sub-binding. The chain-verification step does NOT compensate: when a biscuit carries no attenuation block at all, biscuit-go's chain verifier reports success — there is nothing to chain — and the authority block's `check if signed_by(buyer_delegation_pubkey)` is silently satisfied because no Datalog rule checks it (the check was a documentation hint, not an enforcement primitive on its own without a downstream rule).

The result: a biscuit carrying only an authority block flows through `DiscoverResources.verifyEntitlements` and is treated as covering a SUBSCRIPTION offer at `coveringContract` (the price is downgraded to zero, no refusal is surfaced). This is an ADR-002 violation regardless of any test that surfaces it. Obligation-05 happy-05 ("per-request confirmation missing or stale → refuse with freshness reason") cannot pass honestly while the violation stands.

The xfail audit flagged this as the "parked design-work" cluster on the assumption that a new primitive would be needed. When this was written that assumption looked wrong — the primitive existed and only the wiring did not. It has since become moot in the other direction: the gate chain that held the primitive was removed, so neither half survives.

---

## Decision

This ADR records two binding wiring decisions and one refusal-vocabulary decision. It introduces NO new protocol surface — the primitive is already specified in ADR-002.

### 1. Negotiation handlers MUST run the freshness gate

`OffersService.verifyEntitlements` (the DiscoverResources entry point) and `OffersService.verifySubscriptionCoverage` (the ExecuteTransaction entry point) MUST invoke a freshness check that enforces ADR-002 §B's attenuation-block contract on every entitlement biscuit they accept as covering a SUBSCRIPTION offer. The check fires AFTER `entitlement.Verifier.Verify` succeeds (chain verification + narrowing invariant) and BEFORE the biscuit is admitted to `coveringContract` / `verifySubscriptionCoverage`'s grant-cover gate.

The check evaluates the attenuation-block presence and (when the buyer's mint emits `time() < T` checks) the TTL bound, returning a typed denial when either fails:

- **Missing attenuation block** — the biscuit's `tok.Code()` slice (the per-block Datalog source biscuit-go exposes) is empty. This is the obligation-05 happy-05 "missing per-request confirmation" case. The freshness check returns the new `KindEntitlementStaleAttenuation` denial.
- **Stale attenuation TTL** (when present and parseable) — the deepest `time() < T` check has `T <= now` or `T - now > MaxAttenuationTTL` (10 minutes per `policygate.MaxAttenuationTTL`). Same denial Kind.

The full Gate-A check (sub-binding to `jwt.sub`, signature-bound-to-`buyer_delegation_pubkey`) requires JWT claims and biscuit-go chain-verification state that the negotiation handlers do not yet have plumbed end-to-end (DiscoverResources supports anonymous browse; ExecuteTransaction's JWT integration is staged behind Zitadel wiring tracked in cluster `c5`). Those sub-checks remain in `policygate.GateA` for the path that has the inputs; this ADR commits the negotiation surface to the **structural subset** — presence + TTL — which is sufficient to make the obligation-05 happy-05 refusal honest, and composes cleanly with the full gate when JWT-claim plumbing lands.

### 2. New refusal family `KindEntitlementStaleAttenuation`

The design adds an `exchange.Error` kind, `KindEntitlementStaleAttenuation`, to the refusal-family taxonomy, mapping to `connect.CodeUnauthenticated` at the transport boundary to match the rest of the entitlement-failure family, and grows a parallel `refusalStaleAttenuation` family in the DiscoverResources refusal classifier. Neither landed — that error kind does not exist, and the refusal classifier has since been replaced by the typed denial-reason vocabulary in `src/exchange/internal/service/denial.go`.

### 3. Vocabulary contract (binding)

Operator-facing vocabulary surfaced for the new family MUST contain at least one of `{stale, fresh, confirmation}`. These three tokens are sufficient: they identify the freshness failure family for triage, distinguish it from the other four obligation-05 families (`missing` / `unreadable` / `expired` / `wrong-buyer`), and satisfy the OR-disjunctions in the obligation-05 acceptance tests as they stood when this was written. Those acceptance tests no longer carry the contract this vocabulary was written against — the slots were reused by the May 2026 obligation-05 rewrite for unrelated scenarios, so matching on filename would assert against the wrong contract. `nonce` and `replay` are NOT required by this ADR — neither is a protocol surface RAMP exposes.

The canonical vocabulary line is:

> "entitlement biscuit refused — per-request confirmation is not fresh
> (stale or missing buyer-signed attenuation block)"

This phrasing covers both the missing-block and stale-TTL sub-cases; the verbose denial message produced by `policygate.GateA` (or the wiring's structural subset) is logged at INFO for operator diagnostics.

---

## Consequences

### Positive

- **ADR-002 honesty.** The negotiation surface stops silently accepting authority-only biscuits. The contract on the wire (mandatory per-request attenuation, ≤10m TTL) is now also the contract Exchange enforces.
- **Theft-blast-radius bound becomes real.** ADR-002's central security argument — that a stolen authority biscuit, unattenuated, is unusable — was a documentation claim until this wiring lands. With the wiring in place, it is also a runtime invariant on every DiscoverResources and ExecuteTransaction call.
- **Obligation-05 happy-05 passes honestly.** No xfail, no special-case. The freshness primitive surfaces as a distinct refusal family with distinct vocabulary, exactly as the obligation describes.
- **Composes with Gates B–F.** The structural-subset wiring this ADR commits is a forward-compatible foothold: when JWT-claim plumbing lands on the negotiation path, the wiring grows from "presence + TTL" to a full `policygate.Run` invocation without rewriting the call site.

### Negative / costs accepted

- **Hot-path cost on DiscoverResources.** `verifyEntitlements` is on every DiscoverResources request that carries a biscuit. The freshness check adds one structural pass over `tok.Code()` per biscuit (slice walk + regex match for the deepest `time() < T`). No I/O, no JWKS fetch, no DB call. Single-digit microseconds; negligible for the demo stack and CI's measurement floor.
- **Buyer mint must emit fresh attenuation blocks for happy-path traffic.** At the time of writing the e2e biscuit fixture produced authority-only biscuits — sufficient for negative tests — while the buyer shim's per-call attenuator produced fresh blocks for positive tests. The fixture, the shim and its attenuator have all since been deleted, so neither side of this cost exists to pay.
- **Structural subset is not the full Gate-A.** A biscuit with a present-but-unsigned-by-buyer attenuation block, or one whose `sub()` fact disagrees with `jwt.sub`, would still slip through the wiring this ADR commits — until the JWT-claim plumbing arrives. That is a *narrower* gap than the one this ADR closes, and lives under cluster `c5` (Zitadel + JWT verification on the negotiation path). It is documented here for completeness, not because this ADR has any obligation to close it.

### Out of scope for this ADR

- Buyer-side mint-tool changes. The MCP shim's `PerCallAttenuator` already emits the correct shape; ADR-002 §C tracks any further mint-side work.
- Full `policygate.Run` invocation on the negotiation path (waits for JWT-claim plumbing — cluster `c5`).
- Changes to the obligation itself. Its "missing OR stale" framing remains correct: the wiring this ADR commits routes a missing block to the same `refusalStaleAttenuation` family as a stale TTL would, so a buyer operator's triage experience is uniform across the two sub-cases.
- Per-request HTTP-header carriers (`X-RAMP-Confirmation-Nonce`, `X-RAMP-Confirmation-Timestamp`, etc.). RAMP carries freshness in the biscuit's attenuation block, not in HTTP headers. Test harnesses that previously synthesized HTTP-header inputs to simulate stale confirmation are aligned with the actual surface (the missing-attenuation biscuit) as part of landing this ADR.

---

## Alternatives considered

### (a) New protocol primitive (nonce / server-issued challenge / replay-cache TTL) — rejected

ADR-002 §B already specifies the primitive. Adding a second one would either duplicate the existing surface (two freshness mechanisms — the buyer must satisfy both, with no incremental security gain) or contradict it (a header-based nonce would carry per-request freshness outside the biscuit's signed envelope, allowing a tampered nonce to satisfy freshness while the biscuit's attenuation contract is silently bypassed). The biscuit's attenuation block is the right surface because it is signed by the buyer's delegation key and chain-verifiable against the authority block's `buyer_delegation_pubkey` — the trust path the rest of ADR-002 already pays for.

### (b) Rewrite obligation-05 happy-05 to drop the freshness clause — rejected

The user directive on that task was explicit: "no debt". The obligation bullet describes a real failure mode: a stolen authority biscuit reused without a fresh attenuation block. Dropping the bullet to make the test pass would re-open the ADR-002 §B violation it documents. Rewriting the test to assert "the protocol does not promise freshness" would be asserting on fiction, since ADR-002 §B is the protocol promising exactly that.

### (c) Wire full `policygate.Run` (Gates A–F) on the negotiation path now — deferred

The full gate set requires JWT claims (Gate A's `sub()` cross-check, Gate D's `org` cross-check) and a buyer JWKS fetcher (Gate B). The negotiation-path JWT plumbing lives behind Zitadel wiring (cluster `c5`); committing to the full gate set on this ADR would block on that cluster. The structural-subset wiring this ADR commits is forward-compatible — the call site grows from `freshnessCheck` to `policygate.Run` without a rewrite — and unblocks obligation-05 happy-05 today.

---

## Test surface

Two e2e tests act as the regression guard for this ADR:

- A happy-path obligation-05 test driving an authority-only biscuit through DiscoverResources and asserting a freshness-family refusal.
- The multiplexed obligation-05 failure test, extended so the freshness scenario reuses the authority-only biscuit.

Neither exists. The obligation-05 suite was rewritten in May 2026 against signed-request refusals, and no test in it covers attenuation freshness. Beware the near-namesakes: the current `test_05_happy_04_replay_refused.py` is an RFC 9421 replay-window test and `test_05_failure_07_refusal_reasons_are_distinct.py` covers bad-signature rather than bad-proof cases — neither is the test described here.

Those tests would have dropped their `@pytest.mark.xfail` decorators when the wiring landed, and their assertions would have become the regression guard.

---

## 2026-05-07 amendment — negotiation-surface gate relocates to ExecuteTransaction

**Status of this amendment:** Accepted (2026-05-07)
**Tracks:** this task and its predecessor (commit `ef9cc33`).

### What changed

The DiscoverResources entry point NO LONGER calls the freshness check. As amended, the gate was to keep firing on the ExecuteTransaction path, where stolen-authority replay matters. Neither surface enforces it now: the gate, and the service methods named here, were removed with the biscuit layer. The ExecuteTransaction pipeline today is `src/exchange/internal/service/exchange_batch.go`. DiscoverResources, the read-only browse surface, surfaces what the catalog holds and what coverage the presented biscuit grants, but does NOT enforce per-request attenuation freshness.

### Why

A structural conflict between two valid e2e contracts surfaced once commit `ef9cc33` closed obligation-02 happy-1 / failure-3:

- **Obligation-02 happy-1 and failure-3** — since deleted along with the whole obligation-01 and obligation-02 clusters when v1 dropped the subscription path — drove the renewal flow and POSTed the refreshed biscuit to DiscoverResources, expecting the SUBSCRIPTION offer to surface at zero price. The historical renewal endpoint emitted an authority-only biscuit — it did NOT append a buyer-signed attenuation block. A freshness gate on DiscoverResources refused these tests by construction.
- **Obligation-05 happy-4** (this ADR's regression guard) drives an authority-only biscuit and expects the platform to refuse with a freshness reason.

Both contracts are honest. The original ADR-007 wiring (FreshnessCheck on both DiscoverResources and ExecuteTransaction) closed the obligation-05 case but, against the actual renewal-handler shape, broke obligation-02. The 2026-05-07 reconciliation:

- DiscoverResources (read-only browse, no signed-URL minting, no billing-state commit) remains permissive for authority-only biscuits.
- ExecuteTransaction (commit surface, mints the signed URL, opens the transaction-log row) keeps `policygate.FreshnessCheck`, so a stolen authority biscuit still cannot extract content.
- Obligation-05 happy-4's regression guard relocates to ExecuteTransaction (the same surface used by obligation-05 happy-02 / happy-03 / failure-07) where the freshness gate actually fires.

### Why this is a deferral, not a fix

ADR-002 §B specifies a per-request freshness primitive that fires on **every** entitlement biscuit on the wire — both browse and commit surfaces. The 2026-05-07 amendment narrows the negotiation-surface enforcement to the commit surface only. This is a *deferral* of the strict ADR-002 §B wiring, not a fix.

The structural cause of the deferral is that the historical renewal handler returned an authority-only biscuit. The buyer shim's per-call attenuator was the mechanism that would attach a fresh buyer-signed attenuation block before each outbound call (browse OR commit), but the obligation-02 e2e tests used raw `httpx.post` to drive DiscoverResources, bypassing it. That shim has since been retired, so the option below that depends on it is no longer runnable as written. Two paths can re-instate the strict wiring:

1. **MCP-shim attenuator wired into all outbound calls.** Test flows that drive DiscoverResources route through the MCP shim, which calls `PerCallAttenuator` to append a fresh buyer-signed attenuation block before every call. Obligation-02 tests acquire fresh attenuation; obligation-05 happy-4 and failure-07 retain their existing input shape (no attenuation) and the freshness gate refuses them at DiscoverResources as ADR-002 §B requires.

2. **Renewal handler emits a fresh attenuation block as part of the issued biscuit.** This is a smaller change but conflates buyer-side and resource-owner-side keys (the resource owner does not hold the buyer's delegation private key). It would require a buyer-side post-renewal step that appends the attenuation block before the biscuit is stored. Operationally this is similar to (1).

Either path is the proper ADR-aligned outcome. The follow-up work is tracked separately; this amendment makes the deferral explicit and durable.

### Theft-blast-radius argument under this amendment

ADR-002's central security argument — that a stolen authority biscuit, unattenuated, is unusable — remains a runtime invariant for ExecuteTransaction. A stolen authority biscuit can browse DiscoverResources (read-only, no content served) but cannot mint a signed URL, cannot commit a transaction-log row, and cannot trigger billing. The blast radius bound is therefore "browse visibility on the catalog the biscuit would otherwise cover", not "full-contract bearer-capability access". This is a weaker invariant than ADR-002 §B specifies but is sufficient to retain the commercial property the bound exists to protect (no content extraction without per-request freshness).

### Composition with future wiring

When (1) or (2) above lands, the DiscoverResources freshness gate is restored without rewriting ExecuteTransaction's call site. The composition rule is: the call site grows from "ExecuteTransaction-only" to "both surfaces" as a single edit to `OffersService.verifyEntitlements`. No protocol change, no proto change, no client-side code change beyond the test-harness or renewal-handler edit that re-instates the buyer-signed block on the wire.

### Test surface change

- The obligation-05 stale-confirmation test would POST ExecuteTransaction with the authority-only biscuit and assert refusal, no signed URL, no transaction-log row, and freshness-family vocabulary.
- The multiplexed obligation-05 failure test's stale-confirmation scenario would keep driving DiscoverResources, and is structurally affected by the same gate relocation.

As above, neither test exists; the obligation-05 suite was rewritten and no successor covers attenuation freshness.

---

## Related

- **ADR-002** §B — defines the per-request attenuation-block primitive this ADR wires.
- **ADR-004** — places this wiring at the negotiation layer (above transport, below business logic).
- **ADR-005** Part 2 — Gate F (canonical-form request_hash) shares the attenuation-block surface; this ADR was to bring DiscoverResources and ExecuteTransaction to parity on the freshness sibling. Gate F was itself removed, so neither is wired today.
- **ADR-008** D3 — strict xfail markers; the upstream rule that surfaces the obligation-05 gap as a build-breaker the moment the wiring catches up. This ADR is the wiring catching up.
- The fix task that produces this ADR + the wiring + the test rewrites.
- The parked design-work cluster this ADR closes.
