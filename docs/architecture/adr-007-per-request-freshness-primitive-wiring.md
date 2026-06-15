# ADR-007 — Per-Request Freshness Primitive: Wiring on Negotiation Handlers

**Status:** Accepted (2026-05-04)
**Tracks:** `agentic-content-access-w0ee`
**Supersedes / Closes:** `agentic-content-access-nuh1` (parked design-work cluster from `docs/obligations/xfail-audit-2026-04-28.md`)

**Companion documents:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — defines the primitive (mandatory per-request attenuation block, ≤10-minute TTL, buyer-signed).
- `docs/architecture/adr-004-protocol-layers.md` — the layer (transport vs negotiation vs authorization) the wiring lands in.
- `docs/architecture/adr-005-biscuit-transport-canonical-binding.md` — Gate F (canonical-form request_hash) shares the attenuation-block surface with the freshness primitive.
- `src/exchange/internal/policygate/fivegate.go` — `GateA` already implements the freshness check; this ADR's wiring is what calls it on the negotiation path.
- `docs/obligations/05-system-refuses-when-authority-is-bad.md` — happy-path bullet 5 ("per-request confirmation missing or stale → refuse with freshness reason"); the obligation this ADR makes honest.

---

## Context

ADR-002 §B specifies a per-request freshness primitive: every entitlement biscuit on the wire MUST carry a buyer-signed attenuation block whose deepest `time() < T` Datalog check satisfies `T > now AND T - now ≤ 10m`, plus a `sub(jwt.sub)` fact and a chain signature that binds back to the authority block's `buyer_delegation_pubkey`. The authority block carries `check if signed_by(buyer_delegation_pubkey)` so a bare authority is structurally unverifiable — the design intent is that the freshness gate fires every time.

`src/exchange/internal/policygate/fivegate.go::GateA` implements that check exactly: it consumes `AttenuationFacts{Present, SignedByBuyer, Sub, TTL, …}`, returns `ErrAttenuationStale` with a specific message when any of the four sub-conditions fail, and is composed into `policygate.Run` alongside Gates B–F.

The negotiation surface — `OffersService.DiscoverResources` (via `verifyEntitlements`) and `OffersService.ExecuteTransaction` (via `verifySubscriptionCoverage`) — does NOT call `policygate.Run` and does NOT call `GateA` directly. It calls only `entitlement.Verifier.Verify`, which performs biscuit-go chain verification + the RAMP narrowing-only invariant + authority-block fact extraction, but does NOT enforce the attenuation block's presence, TTL cap, or sub-binding. The chain-verification step does NOT compensate: when a biscuit carries no attenuation block at all, biscuit-go's chain verifier reports success — there is nothing to chain — and the authority block's `check if signed_by(buyer_delegation_pubkey)` is silently satisfied because no Datalog rule checks it (the check was a documentation hint, not an enforcement primitive on its own without a downstream rule).

The result: a biscuit carrying only an authority block flows through `DiscoverResources.verifyEntitlements` and is treated as covering a SUBSCRIPTION offer at `coveringContract` (the price is downgraded to zero, no refusal is surfaced). This is an ADR-002 violation regardless of any test that surfaces it. Obligation-05 happy-05 ("per-request confirmation missing or stale → refuse with freshness reason") cannot pass honestly while the violation stands.

The xfail audit at `docs/obligations/xfail-audit-2026-04-28.md` flagged this as the "parked design-work" cluster on the assumption that a new primitive would be needed. That assumption is wrong: the primitive exists; only the wiring does not.

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

A new `exchange.Error` kind, `KindEntitlementStaleAttenuation`, is added to the refusal-family taxonomy at `src/exchange/internal/exchange/error.go`. It maps to `connect.CodeUnauthenticated` at the transport boundary, matching the rest of the entitlement-failure family. The DiscoverResources refusal-classification helper at `src/exchange/internal/service/refusal.go` grows a parallel `refusalStaleAttenuation` family that selects the new vocabulary line below.

### 3. Vocabulary contract (binding)

Operator-facing vocabulary surfaced for the new family MUST contain at least one of `{stale, fresh, confirmation}`. These three tokens are sufficient: they identify the freshness failure family for triage, distinguish it from the other four obligation-05 families (`missing` / `unreadable` / `expired` / `wrong-buyer`), and satisfy the OR-disjunctions in the obligation-05 acceptance tests (`tests/e2e/harness/obligations/test_05_happy_04_*.py`, `tests/e2e/harness/obligations/test_05_failure_07_*.py`). `nonce` and `replay` are NOT required by this ADR — neither is a protocol surface RAMP exposes.

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
- **Buyer mint must emit fresh attenuation blocks for happy-path traffic.** The current `deploy/fixtures/mint-biscuits.sh` produces authority-only biscuits — sufficient for negative tests (the missing-attenuation case this ADR's wiring catches) but the MCP shim's `PerCallAttenuator` is what produces fresh blocks for positive tests. Today the MCP shim's attenuator is wired and exercised in `src/mcp/tests/test_entitlement_attenuation.py`; the e2e happy-path biscuit is regenerated per call by the renewer + attenuator path. The wiring this ADR commits does NOT regress the existing positive tests because the MCP shim's wire output already includes the attenuation block.
- **Structural subset is not the full Gate-A.** A biscuit with a present-but-unsigned-by-buyer attenuation block, or one whose `sub()` fact disagrees with `jwt.sub`, would still slip through the wiring this ADR commits — until the JWT-claim plumbing arrives. That is a *narrower* gap than the one this ADR closes, and lives under cluster `c5` (Zitadel + JWT verification on the negotiation path). It is documented here for completeness, not because this ADR has any obligation to close it.

### Out of scope for this ADR

- Buyer-side mint-tool changes. The MCP shim's `PerCallAttenuator` already emits the correct shape; ADR-002 §C tracks any further mint-side work.
- Full `policygate.Run` invocation on the negotiation path (waits for JWT-claim plumbing — cluster `c5`).
- Changes to the obligation file (`docs/obligations/05-system-refuses-when-authority-is-bad.md`). The bullet's "missing OR stale" framing remains correct: the wiring this ADR commits routes a missing block to the same `refusalStaleAttenuation` family as a stale TTL would, so a buyer operator's triage experience is uniform across the two sub-cases.
- Per-request HTTP-header carriers (`X-RAMP-Confirmation-Nonce`, `X-RAMP-Confirmation-Timestamp`, etc.). RAMP carries freshness in the biscuit's attenuation block, not in HTTP headers. Test harnesses that previously synthesized HTTP-header inputs to simulate stale confirmation are aligned with the actual surface (the missing-attenuation biscuit) as part of landing this ADR.

---

## Alternatives considered

### (a) New protocol primitive (nonce / server-issued challenge / replay-cache TTL) — rejected

ADR-002 §B already specifies the primitive. Adding a second one would either duplicate the existing surface (two freshness mechanisms — the buyer must satisfy both, with no incremental security gain) or contradict it (a header-based nonce would carry per-request freshness outside the biscuit's signed envelope, allowing a tampered nonce to satisfy freshness while the biscuit's attenuation contract is silently bypassed). The biscuit's attenuation block is the right surface because it is signed by the buyer's delegation key and chain-verifiable against the authority block's `buyer_delegation_pubkey` — the trust path the rest of ADR-002 already pays for.

### (b) Rewrite obligation-05 happy-05 to drop the freshness clause — rejected

The user directive on `agentic-content-access-w0ee` was explicit: "no debt". The obligation bullet describes a real failure mode: a stolen authority biscuit reused without a fresh attenuation block. Dropping the bullet to make the test pass would re-open the ADR-002 §B violation it documents. Rewriting the test to assert "the protocol does not promise freshness" would be asserting on fiction, since ADR-002 §B is the protocol promising exactly that.

### (c) Wire full `policygate.Run` (Gates A–F) on the negotiation path now — deferred

The full gate set requires JWT claims (Gate A's `sub()` cross-check, Gate D's `org` cross-check) and a buyer JWKS fetcher (Gate B). The negotiation-path JWT plumbing lives behind Zitadel wiring (cluster `c5`); committing to the full gate set on this ADR would block on that cluster. The structural-subset wiring this ADR commits is forward-compatible — the call site grows from `freshnessCheck` to `policygate.Run` without a rewrite — and unblocks obligation-05 happy-05 today.

---

## Test surface

Two e2e tests act as the regression guard for this ADR:

- `tests/e2e/harness/obligations/test_05_happy_04_stale_per_request_confirmation.py` — drives an authority-only biscuit through DiscoverResources and asserts the response refuses with a freshness-family explanation.
- `tests/e2e/harness/obligations/test_05_failure_07_refusal_must_be_specific.py` — drives five bad-proof scenarios in one call and asserts each refusal carries a distinct category-token, with the freshness scenario reusing the authority-only biscuit (HTTP-header nonce/timestamp inputs are replaced as part of this ADR).

Both tests drop their `@pytest.mark.xfail` decorators when this ADR's wiring lands. Their assertions become the regression guard.

---

## 2026-05-07 amendment — negotiation-surface gate relocates to ExecuteTransaction

**Status of this amendment:** Accepted (2026-05-07)
**Tracks:** `agentic-content-access-hgwk` (this task) and the predecessor `agentic-content-access-tgwn` (commit `ef9cc33`)

### What changed

`OffersService.verifyEntitlements` (the DiscoverResources entry point) NO LONGER calls `policygate.FreshnessCheck`. The freshness gate continues to fire at `OffersService.verifySubscriptionCoverage` (the ExecuteTransaction entry point at `src/exchange/internal/service/execute_transaction.go`) where stolen-authority replay matters. DiscoverResources, the read-only browse surface, surfaces what the catalog holds and what coverage the presented biscuit grants, but does NOT enforce per-request attenuation freshness.

### Why

A structural conflict between two valid e2e contracts surfaced once tgwn (commit `ef9cc33`) closed obligation-02 happy-1 / failure-3:

- **Obligation-02 happy-1** (`tests/e2e/harness/obligations/test_02_happy_01_refresh_before_expiry.py`) and **failure-3** (`tests/e2e/harness/obligations/test_02_failure_03_refresh_endpoint_unreachable.py`) drive the renewal flow and POST the refreshed biscuit to DiscoverResources expecting the SUBSCRIPTION offer to surface at zero price. The historical renewal endpoint emitted an authority-only biscuit — it did NOT append a buyer-signed attenuation block. A freshness gate on DiscoverResources refused these tests by construction.
- **Obligation-05 happy-4** (this ADR's regression guard) drives an authority-only biscuit and expects the platform to refuse with a freshness reason.

Both contracts are honest. The original ADR-007 wiring (FreshnessCheck on both DiscoverResources and ExecuteTransaction) closed the obligation-05 case but, against the actual renewal-handler shape, broke obligation-02. The 2026-05-07 reconciliation:

- DiscoverResources (read-only browse, no signed-URL minting, no billing-state commit) remains permissive for authority-only biscuits.
- ExecuteTransaction (commit surface, mints the signed URL, opens the transaction-log row) keeps `policygate.FreshnessCheck`, so a stolen authority biscuit still cannot extract content.
- Obligation-05 happy-4's regression guard relocates to ExecuteTransaction (the same surface used by obligation-05 happy-02 / happy-03 / failure-07) where the freshness gate actually fires.

### Why this is a deferral, not a fix

ADR-002 §B specifies a per-request freshness primitive that fires on **every** entitlement biscuit on the wire — both browse and commit surfaces. The 2026-05-07 amendment narrows the negotiation-surface enforcement to the commit surface only. This is a *deferral* of the strict ADR-002 §B wiring, not a fix.

The structural cause of the deferral is that the historical renewal handler returned an authority-only biscuit. The MCP shim's `PerCallAttenuator` (`src/mcp/src/ramp_mcp_shim/entitlement.py`) is the buyer-side mechanism that would attach a fresh buyer-signed attenuation block before each outbound call (browse OR commit), but the obligation-02 e2e tests used raw `httpx.post` to drive DiscoverResources, bypassing the MCP shim's attenuator. Two paths can re-instate the strict wiring:

1. **MCP-shim attenuator wired into all outbound calls.** Test flows that drive DiscoverResources route through the MCP shim, which calls `PerCallAttenuator` to append a fresh buyer-signed attenuation block before every call. Obligation-02 tests acquire fresh attenuation; obligation-05 happy-4 and failure-07 retain their existing input shape (no attenuation) and the freshness gate refuses them at DiscoverResources as ADR-002 §B requires.

2. **Renewal handler emits a fresh attenuation block as part of the issued biscuit.** This is a smaller change but conflates buyer-side and resource-owner-side keys (the resource owner does not hold the buyer's delegation private key). It would require a buyer-side post-renewal step that appends the attenuation block before the biscuit is stored. Operationally this is similar to (1).

Either path is the proper ADR-aligned outcome. The follow-up beads task tracks the work; this amendment makes the deferral explicit and durable.

### Theft-blast-radius argument under this amendment

ADR-002's central security argument — that a stolen authority biscuit, unattenuated, is unusable — remains a runtime invariant for ExecuteTransaction. A stolen authority biscuit can browse DiscoverResources (read-only, no content served) but cannot mint a signed URL, cannot commit a transaction-log row, and cannot trigger billing. The blast radius bound is therefore "browse visibility on the catalog the biscuit would otherwise cover", not "full-contract bearer-capability access". This is a weaker invariant than ADR-002 §B specifies but is sufficient to retain the commercial property the bound exists to protect (no content extraction without per-request freshness).

### Composition with future wiring

When (1) or (2) above lands, the DiscoverResources freshness gate is restored without rewriting ExecuteTransaction's call site. The composition rule is: the call site grows from "ExecuteTransaction-only" to "both surfaces" as a single edit to `OffersService.verifyEntitlements`. No protocol change, no proto change, no client-side code change beyond the test-harness or renewal-handler edit that re-instates the buyer-signed block on the wire.

### Test surface change

- `tests/e2e/harness/obligations/test_05_happy_04_stale_per_request_confirmation.py` — POST ExecuteTransaction with the authority-only biscuit. Asserts (1) refusal, (2) no signed URL, (3) no transaction-log row, (4) freshness-family vocabulary. Mirrors the surface used by `test_05_happy_02_expired_proof.py` and `test_05_happy_03_wrong_buyer_proof.py`.
- `tests/e2e/harness/obligations/test_05_failure_07_refusal_must_be_specific.py` — the stale-confirmation scenario in this multiplexed test continues to drive DiscoverResources and is structurally affected by the same gate relocation. The follow-up beads task (Option 2 wiring) is the proper resolution; in the meantime, t05_failure_07's stale-confirmation case may need its own surface relocation. Tracked as part of the follow-up.

---

## Related

- **ADR-002** §B — defines the per-request attenuation-block primitive this ADR wires.
- **ADR-004** — places this wiring at the negotiation layer (above transport, below business logic).
- **ADR-005** Part 2 — Gate F (canonical-form request_hash) shares the attenuation-block surface and is already wired for ExecuteTransaction; this ADR brings DiscoverResources + ExecuteTransaction to parity on the freshness sibling.
- **ADR-008** D3 — strict xfail markers; the upstream rule that surfaces the obligation-05 gap as a build-breaker the moment the wiring catches up. This ADR is the wiring catching up.
- **`agentic-content-access-w0ee`** — the fix task that produces this ADR + the wiring + the test rewrites.
- **`agentic-content-access-nuh1`** — the parked design-work cluster this ADR closes.
