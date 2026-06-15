# ADR-008 — Testing Surface as a First-Class Subsystem

**Status:** Accepted (2026-05-01)
**Refines:**
- `docs/architecture/adr-002-entitlement-biscuit-model.md` — protocol-level TTL constants (≤10m attenuation, contract `valid_until`) are values; this ADR pins how those values are consulted at runtime so test-time and production-time read from the same port.
- `docs/architecture/adr-004-protocol-layers.md` — "refusal is the product" demands a refusal vocabulary; this ADR makes the vocabulary structured and enumerable.
**Companion documents:**
- `CLAUDE.md` Testing Doctrine — this ADR formalises the structural commitments that doctrine assumes.
- `docs/architecture/adr-005-biscuit-transport-canonical-binding.md` — Gate F's clock-dependence is one of D1's beneficiaries.
- `docs/architecture/adr-006-broker-intermediation.md` — D2's structured-vocabulary discipline mirrors ADR-006's `authorized_intermediaries` discipline applied to a different surface.

---

## Context

RAMP's protocol contracts (ADRs 001–006) are correct. The implementations of those contracts are correct. The system, viewed as production code, behaves the way the protocol says it should. Yet four classes of failure recur whenever the system is exercised under realistic test conditions:

1. **Time-coupled gates fail non-deterministically.** Policy gates whose semantics turn on time (attenuation TTL ≤ 10m, authority `valid_until`, reporting grace, key-cache TTL) consult the wall clock directly. A test that needs to assert "this biscuit is treated as expired" must either sleep until expiry or mutate constants — both fragile, both undeterministic, neither faithful to the gate's actual behavioural contract.

2. **Silent failure aliases legitimate refusal.** A request that returns "no offers" because the back-end is unhealthy is shape-identical to a request that returns "no offers" because the caller is not entitled. Both produce the same wire-level response. Callers cannot disambiguate; verifiers cannot distinguish a system regression from a contract refusal; observability tooling cannot route alerts.

3. **Tests that document a gap drift into tests that hide a gap.** When a test encodes a contract production has not yet implemented, marking it "expected to fail" lets the suite run. But "expected to fail, no strict check" — the lenient form — means the test will silently start passing for the wrong reasons (state leakage from another test, incidental refusal from a different layer) and the gap stays open while the suite reports green.

4. **Concurrent test executions corrupt each other's state.** When project-wide tooling (formatters, linters, code generators) is invoked from inside a test or task that runs in parallel with peer tasks, it touches files outside the caller's nominal scope and races peers' in-progress edits.

A fifth issue cuts across the previous four: **shared test environments accumulate state from prior tests**. The contract a test asserts may pass not because the production code under test is correct but because state from an earlier test made it appear correct.

These five symptoms are not independent. They share a root cause: **the testing surface has been treated as a consequence of production code rather than as a peer subsystem with its own architectural commitments.** Production code consults the wall clock → tests inherit the wall clock. Production returns silent empties → tests assert on silent empties. Production uses project-wide tooling → tests fight the tooling. Production does not declare per-test isolation → tests assume any state they encounter is correct.

This ADR pins five commitments — each a deliberate counterweight to one of the symptoms — that re-found the testing surface on principle rather than convenience.

---

## Decision

### D1 — Time is a port; the wall clock is a leaf

Every code path that consults time for **behaviour-gating** purposes — policy gates, validity windows, TTL checks, scheduling decisions, cache invalidation — receives its time source through a `Clock` interface. Direct calls to the language's wall-clock primitive (`time.Now()` in Go, `datetime.now()` / `time.time()` in Python) are forbidden inside the policy-relevant trees and lint-enforced.

**Interface (Go)**: a package-level `Clock` interface with at minimum `Now() time.Time`. Implementations: a system-clock realisation for production wiring; deterministic-clock realisations (fixed instant, manually-advanced counter) for tests. For code that schedules: `After(d time.Duration) <-chan time.Time` and equivalents on the same interface.

**Interface (Python)**: a matching `Clock` Protocol with `now() -> datetime` and `monotonic() -> float`. Implementations as above.

**Lint enforcement**:
- Go: an import-graph rule (`depguard` or equivalent) denying imports of `time.Now`, `time.Since`, `time.Until` inside the production policy trees. Allowed only in the clock package itself, observability shims, log formatters, and the production root that constructs the system clock.
- Python: a flake8 plugin denying `datetime.now`, `datetime.utcnow`, `time.time`, `time.monotonic` in policy-relevant modules with an equivalent allowlist.

**Rationale**: Protocol values like the 10-minute attenuation cap (ADR-002) are constants; their *consultation* is a runtime concern. Conflating them produces a protocol whose behavioural envelope can only be exercised by waiting for real time to pass. The port/leaf split keeps the protocol values where they belong (protocol-defined constants) while making behaviour observable under any clock.

### D2 — Every empty result carries a structured reason

A response that returns an empty result, a refusal, or a "no, but…" body MUST populate a structured `<Domain>AbsenceReason` enum naming why. Returning an empty result without populating the reason is forbidden and lint-enforced.

**Vocabulary requirements**: each enum is wire-format-defined (proto), exhaustive over the actual cause space the surface can produce, and includes an explicit `*_INTERNAL_ERROR` value so an unknown internal failure is never miscategorised as a clean refusal.

**Lint enforcement**: a static-analysis pass that flags any function returning a response type whose absence-bearing field can be empty without setting the reason field. Tests assert on the enum, not on length-zero or truthiness.

**Rationale**: ADR-004 establishes that refusal is the product — the inner protocol layer is responsible for accepting or refusing requests, and a refusal IS as load-bearing as an acceptance. A refusal without a reason is therefore a half-implementation of the contract: the verifier cannot tell what was refused, the observer cannot route alerts, the agent cannot adjust its retry policy. Structured reasons make refusals as inspectable as acceptances and as testable as any other response field.

### D3 — Test markers for known-failing assertions are strict, always

Tests that document a contract the production system has not yet implemented use the test framework's strict-mode marker (e.g. `pytest.mark.xfail(strict=True)`). The lenient form (`strict=False`) is forbidden across the codebase and lint-enforced.

**Rationale**: A contract that exists in the test suite but cannot fail-noisily is a contract that is being silently postponed. Strict mode makes the postponement visible at exactly the moment production catches up — the test flips from xfail to failure (because it's now expected to fail strictly but it passes), forcing the marker to be removed and the test to become a real regression guard. The lenient form was originally intended as a transition state for the window between "test landed encoding the contract" and "production caught up," but every variant of "transition state" is an attractor for forgotten obligations: strict mode IS the transition state, because the build breaks the moment the transition is complete and the marker must be removed. There is no scenario in which lenient mode produces signal a strict marker plus an open issue-tracker entry doesn't produce more cleanly.

**Operational complement**: when a strict-mode flip surfaces as a regression against a previously-green build, route it through the regression-diagnostic-predecessor pattern (`.claude/rules/workflows/regression-diagnostic-predecessor.md`) — its taxonomy distinguishes shipped bugs from exposed latent bugs (the dominant case under D3) and prevents panic-reverts of the marker change.

### D4 — Concurrent task executions run in isolated working copies

When two or more tasks execute concurrently against the same repository — whether by parallel test runners, parallel CI agents, parallel agentic executors, or parallel developers — each task runs in a `git worktree`-isolated copy of the repository. Tasks that run solo may run on the main working copy.

**Spawn shape**: the orchestration primitive that spawns concurrent tasks creates a worktree per spawn. Each task's filesystem writes — including side effects from project-wide tooling like formatters that touch every file — land in the worktree, not in the main copy.

**Merge shape**: after concurrent tasks return, the orchestrator pulls each worktree's commits sequentially, resolves conflicts, runs the authoritative quality gates once on the merged tree, and produces consolidated commits.

**Durability vs isolation**: a worktree is an isolation guarantee, not a durability guarantee. Files an executor writes outside a commit do not survive worktree teardown — uncommitted writes vanish with the worktree. The corollary binds the team-lead too: any file the team-lead writes via `cp`, `Write`, or `Edit` MUST resolve to an absolute path anchored at the project root, never a relative path that could resolve inside a worktree's tree and be destroyed at teardown.

**Merge before teardown**: the orchestration primitive that returns concurrent tasks MUST merge each worktree's commits to the main tree BEFORE invoking any teardown call. Teardown without a prior merge is a protocol violation: the worktree's history — including the executor's outputs — is unrecoverable once the directory is removed.

**Executor outputs land in commits before handoff**: an executor that produces output the team-lead will read after handoff (a diagnostic file, a generated artifact, a beads-task body, anything the next phase consumes) MUST commit that output inside its worktree before signaling completion. The team-lead's merge step then carries it to the main tree. Outputs left uncommitted at handoff are indistinguishable from outputs that never existed.

**Rationale**: Project-wide tooling (formatters, linters, code generators, dependency-graph builders) is a real and load-bearing part of the build. A "don't touch the same files" honour system fails the moment such tooling runs from inside a concurrent task: its writes are nominally outside the caller's scope but functionally affect every peer. Worktree isolation makes the property structural: a task literally cannot see or affect peers' in-progress edits. The durability constraints above are the dual property — isolation that keeps peers from seeing each other's edits is the same mechanism that makes uncommitted edits invisible to the team-lead at teardown, and the discipline that closes the gap is to commit before signaling and merge before tearing down.

### D5 — Test isolation is a declared contract, not an environmental coincidence

Each test declares its stack-isolation requirement explicitly. Three modes:

- **Isolated**: the test owns its environment exclusively. The orchestration primitive tears down and rebuilds shared infrastructure (containers, databases, caches) between this test and the next. Reserved for tests that mutate persistent state irrecoverably or assert on a clean baseline.
- **Shared with cleanup fixtures**: the shared environment persists across tests; declared cleanup fixtures run before each test to restore state the test depends on (e.g. obligations cleared, health states reset, transaction logs scoped by tenant). This is the default mode for the bulk of the suite.
- **Shared without cleanup**: no setup or teardown. Reserved for tests that observe stable cross-test invariants (service-health probes, version sentinels, schema fingerprints) and are genuinely indifferent to the state any other test leaves behind.

**Enforcement**: the test framework's per-test fixture hook reads the declared mode and dispatches the appropriate setup/teardown. Tests with no declared mode default to "shared with cleanup fixtures." Cleanup fixtures are owned by the modes they implement, not by individual tests — a test that needs unusual cleanup must add it to the appropriate fixture, not work around its absence.

**Rationale**: A shared environment that "happens to be in a usable state" because of incidental ordering of tests is a shared environment that will eventually break under reordering, retry, or parallelism. Declared isolation makes the test's dependence on the environment explicit and the environment's promise to the test enforceable. Tests that need full clean-slate isolation pay the wall-clock cost honestly; tests that can share pay nothing extra; the ambiguous middle (where a test passes only because of state from an earlier test) is removed.

---

## Consequences

### Positive

- **Test outcomes carry signal proportional to their assertion strength.** A test that passes proves the production code under test is correct, not that the test environment happened to be in a usable state.
- **Diagnostic locality.** A timing flake reads as "D1 wasn't applied to this gate." A silent-empty regression reads as "D2's enum is missing on this surface." A drifting xfail reads as "D3's sweeper found an aged marker." Each commitment is its own diagnostic axis.
- **The testing subsystem becomes auditable as code, not as practice.** Each commitment has lint or hook enforcement; "we forgot" stops being a viable explanation for a regression.

### Negative

- **Five lint/hook rules to land and maintain.** Each is small, but together they are a real toolchain investment.
- **Clock injection touches every gate signature.** The change is mechanical (constructor accepts a `Clock`; wall-clock calls become method calls on the injected clock) but the diff is broad across every package that gates on time.
- **Per-test isolation has wall-clock cost.** Tests declaring full isolation will be slow; the discipline is to declare full isolation only when genuinely needed, and to ensure cleanup fixtures for the shared mode are robust enough to be the default.
- **Worktree isolation requires the orchestration layer to know how to spawn and merge worktrees.** Without orchestration support, the discipline collapses back to the honour system.

### Specifically rejected alternatives

- **Tightening conventions in prose documentation rather than enforcing in lint.** Conventions in markdown are honour-system. Lint enforcement is the difference between an aspiration and a commitment.
- **Defaulting the shared test environment to "tests must clean up after themselves" without a declared isolation contract.** This is what permits ambiguous-state passes today; it is the problem D5 exists to solve.
- **Running concurrent executions solo (one task at a time) instead of with worktree isolation.** Loses the throughput concurrent execution exists to provide; doesn't address the other four commitments.
- **Keeping the wall clock direct because protocol values are constants anyway.** Conflates protocol values (constants) with consultation (a runtime concern). The values stay; the consultation routes through a port.

---

## Non-goals

- This ADR does not change the protocol. The TTL constants, the gate semantics, the refusal contract — all remain as their respective ADRs define them. Only the structural shape of the implementation's interaction with time, refusal, debt-marking, concurrency, and isolation changes.
- This ADR does not specify a particular language, tool, or framework for implementation. The Go and Python sketches in the decision sections are illustrative of the shape; equivalent implementations in other languages or frameworks satisfy the same commitments.
- This ADR does not redesign the obligation-driven testing model. Behavioural obligations remain the test-design source of truth; this ADR governs the testing infrastructure those obligations execute on.

---

## References

- ADR-002 — entitlement-biscuit model (TTL constants whose consultation D1 routes through a port).
- ADR-004 — protocol layers ("refusal is the product"; D2 makes the refusal vocabulary structured and enforceable).
- ADR-005 — biscuit transport carriage and canonical-form binding (every gate Gate F composes with consults time, and benefits from D1).
- ADR-006 — broker intermediation (D2's structured-vocabulary discipline is the same shape as ADR-006's `authorized_intermediaries` discipline applied to a different surface).
- `CLAUDE.md` Testing Doctrine — this ADR formalises the structural commitments that doctrine assumes.
