# ADR-011 — Three-Way Reconciliation Procedure

**Status:** Accepted (2026-06-02)

Refines the follow-up contract (post-commit `billing.Record`, pure-audit `ReportUsage`, `Refund` + `IdempotencyKey`) and the persisted-ledger ticket (`integrate-tigerbeetle-as-billing-adapter`). Consumes ADR-009 (identity binding at dispute submission), ADR-010 (inverse-posting policy for partial refunds), ADR-012 (Edge delivery-log contract), ADR-008 D1 (`Clock` port), and the dispute types in `ramp.proto` (module `github.com/RAMP-Protocol/protocol`) (lines 2014–2158).

---

## Context

The Exchange records a billing settlement at `ExecuteTransaction` commit time. The agent later reports usage (or doesn't) via `ReportUsage`, which is pure audit and does not move money. The Edge delivers (or doesn't) the signed URL's content and produces a delivery-log entry per ADR-012. Three independent parties have therefore each produced a signed record of "what happened" for the transaction: the Exchange (`transaction_log` + ledger transfer), the Agent (optional `UsageReport`), and the Edge (per ADR-012 delivery log).

Three independently-signed sources is what makes the Exchange auditable. Any single source can be lost or stale; agreement between any two is the smallest committee that can settle a fact. This ADR specifies how those three sources are reconciled per transaction — money matches delivered bytes, audit trail names what happened and why, operator can override the machine when evidence demands.

`billing.Record` runs after the WAL commit, outside the request transaction; the reconciler IS that recovery path. Partial refund reverses publisher revenue and platform fee proportionally. SLA values are per-Exchange product decisions; the ADR pins the shape, not the values.

---

## Decision

### D1 — Triggers and cadence

Reconciliation has four entry points; only the sweep is a "real" reconciliation.

**Hourly sweep (primary).** A worker wakes on a configurable interval (default `1h`, clamped `[10s, 1h]`) and reconciles every transaction within the latest billing period — defined as "the last completed billing period plus the in-flight period up to `now - reporting_grace`." Global `LIMIT N` (default 100) per cycle; at v1 scale (1–3 publishers) per-tenant fairness is not needed. Per-tenant row counts are logged each cycle.

**Queued-dispute drain.** Before each sweep scan, the worker drains `dispute_queue` rows with `status = 'QUEUED'` ordered by `queued_at ASC`. Same machinery as the sweep, higher priority. A flood of queued disputes surfaces as starvation of the routine sweep in metrics.

**Per-dispute point lookup.** `DisputeTransaction` enqueues a row in `dispute_queue` (D6) and returns `DISPUTE_STATUS_FILED` plus an `estimated_resolution`. Verdict lands on the next tick; agents poll `GetDisputeStatus`.

**Per-expiry point lookup.** When `expiry` passes and the reconciler asks "did this resolve?", it does a single-row probe through the rule table.

All four paths consume the same rule table (D3) and produce the same outcome shape (D4); only entry points differ. Point lookups optimize for latency; the sweep optimizes for completeness.

**Clock port.** Time reads go through ADR-008 D1's `Clock` interface. Tests advance the clock manually; production wires the system clock.

**Cross-tenant scope.** The sweep is cross-tenant. Each query carries the `admin:cross_tenant` marker; per-tick logs include `sweep_id`, `rows_scanned`, `rows_reconciled`, `rows_flagged_for_review`, `rows_per_tenant`, `duration_ms`.

### D2 — The three signed sources

Every reconciliation consumes three sources, each with an explicit contract.

**Source 1 — Exchange offer (always present).** `transaction_log` row + signed offer. Fields: `transaction_id`, `tenant_id`, `agent_id`, `publisher_id`, `resource_id`, `signed_url_hash`, `content_hash_promised`, `unit_cost`, `quantity_authorized`, `expiry`, `billing_id`, `billing_recorded_at`, `release_at`, `refund_history`.

**Source 2 — Agent report (optional).** `UsageReport` for `transaction_id` if any. Fields: `report_id`, `validation_status` (VALIDATED / REJECTED), `consumed_quantity`, `received_content_hash`, `received_at`.

**Source 3 — Edge delivery log (optional, authoritative on bytes).** Per ADR-012, an entry carrying `bytes_served`, `content_hash_served`, `served_at`, `edge_node_id`, signature. Queryable ≥ 90 days. Absence may mean true delivery failure OR transient query failure — the reconciler distinguishes these per D5.

The three sources jointly classify every outcome in D3. The reconciler does NOT consult external state; anything outside the records is operator judgment (D6).

### D3 — The rule table

| # | Agent report | Edge log | Quantity match | Outcome | Adapter action |
|---|---|---|---|---|---|
| 1 | VALIDATED | present, content_hash matches | yes | `RECONCILED_OK` | none (Record stands) |
| 2 | VALIDATED | present, content_hash matches | no (Edge says less) | `RECONCILED_PARTIAL_REFUND` | `Refund(delta)`, inverse postings per ADR-010 |
| 3 | VALIDATED | present, content_hash mismatch | — | `FLAGGED_FOR_REVIEW` (Tier 2 evidence path) | none yet; operator decides |
| 4 | VALIDATED | absent, query failed within SLA | — | `DEFERRED` (retry next tick) | none |
| 5 | VALIDATED | absent, query failed past SLA | — | `RECONCILED_REFUNDED` (per D5 default; per-Exchange override possible) | `Refund(full)` |
| 6 | REJECTED | present, content_hash matches | — | `DISMISSED_REPORT` (Edge delivered; agent's rejection is dismissed) | none; optional `abuse_flag` if pattern threshold hit |
| 7 | REJECTED | present, content_hash mismatch | — | `RECONCILED_REFUNDED` (delivery was wrong content) | `Refund(full)` |
| 8 | REJECTED | absent (past SLA) | — | `RECONCILED_REFUNDED` | `Refund(full)` |
| 9 | absent | present, content_hash matches | — | `RECONCILED_OK` (silent agent = satisfied agent) | none |
| 10 | absent | present, content_hash mismatch | — | `FLAGGED_FOR_REVIEW` (Edge served wrong content but agent didn't complain) | none yet; operator decides |
| 11 | absent | absent (past SLA) | — | `RECONCILED_REFUNDED` (default "agent is right" policy per D5) | `Refund(full)` |
| 12 | (any) | present, `bytes_served = 0` | — | treat as `Edge log absent` per rows 4 / 5 / 8 / 11 | (depends) |

**Pre-effective-date gate.** When `tenants.delivery_log_enabled_from` is NULL, or `transaction.created_at < delivery_log_enabled_from`, "missing Edge log" is expected — rows 5/8/11 downgrade to no-action. When `created_at >= delivery_log_enabled_from`, the table applies unchanged.

**Quantity disagreement.** Edge `bytes_served` is authoritative over agent `consumed_quantity`. The reconciler computes `refund_delta = recorded_amount × (1 - bytes_served / bytes_authorized)` and issues `billing.Refund(refund_delta, idempotencyKey=reconciliation_id, reason="quantity_reconciliation")`. Inverse postings execute proportionally per ADR-010.

### D4 — Reconciliation outcome model

Every reconciled transaction produces a `reconciliation_log` row in Postgres, plus (when money moves) a TigerBeetle transfer stamped to tie back to the original transfer chain.

```sql
CREATE TABLE reconciliation_log (
    reconciliation_id        UUID PRIMARY KEY,         -- also adapter idempotency key for any Refund this row issues
    transaction_id           UUID NOT NULL,            -- FK → transaction_log; NOT UNIQUE (re-reconciliation, appeals)
    tenant_id                UUID NOT NULL,            -- denormalized for per-tenant query without join
    sources_seen             JSONB NOT NULL,           -- {exchange:true, agent:bool, edge:"present"|"absent_within_sla"|"absent_past_sla"|"absent_pre_effective"}
    outcome                  reconciliation_outcome NOT NULL,  -- RECONCILED_OK | RECONCILED_PARTIAL_REFUND | RECONCILED_REFUNDED | DISMISSED_REPORT | FLAGGED_FOR_REVIEW | DEFERRED | OPERATOR_OVERRIDE
    refund_amount            NUMERIC(20,8),            -- NULL when no money moves
    decided_by               decided_by_enum NOT NULL, -- auto | operator
    decided_at               TIMESTAMPTZ NOT NULL,
    operator_id              UUID,                     -- NULL when decided_by=auto
    operator_note            TEXT,                     -- NULL when decided_by=auto
    tigerbeetle_transfer_id  BYTEA,                    -- NULL exactly when outcome was a no-op
    audit_signature          BYTEA NOT NULL            -- Ed25519 over preceding columns, ADR-005 signing key
);
CREATE INDEX rec_log_tenant_decided ON reconciliation_log (tenant_id, decided_at DESC);
CREATE INDEX rec_log_txn_decided    ON reconciliation_log (transaction_id, decided_at DESC);
CREATE INDEX rec_log_flagged        ON reconciliation_log (outcome) WHERE outcome = 'FLAGGED_FOR_REVIEW';
```

**Tenant isolation.** Every reconciler read filters by `tenant_id`; only the cross-tenant eligibility scan uses the `admin:cross_tenant` marker.

**TigerBeetle stamp.** Each reconciliation-issued transfer carries:

| Field | Carries | Why |
|---|---|---|
| `id` | `sha256("refund:" + reconciliation_id)` | Ledger convention: transfer-id derived from idempotency key; re-runs dedupe at the database layer. |
| `user_data_128` | `reconciliation_log.id` UUID raw bytes | UUIDs are 16 bytes; pass directly. `query_transfers(user_data_128: <id>)` returns every transfer for that run. |
| `code` | `RECONCILED_OK=1`, `RECONCILED_REFUNDED=2`, `RECONCILED_DISPUTED=3`, `RECONCILED_OPERATOR_OVERRIDE=4` | TigerBeetle's `code` is categorisation; enables "every full refund the reconciler issued in this window." |

No-op outcomes (`RECONCILED_OK`, `DISMISSED_REPORT`) produce no transfer; the `reconciliation_log` row IS the artifact. TigerBeetle answers "which run, which category, when"; Postgres answers "what were the sources, who decided, why."

### D5 — Failure handling and SLAs

The ADR fixes the shape of these knobs; values are per-Exchange product decisions.

| Knob | Default | Purpose |
|---|---|---|
| `EXCHANGE_RECONCILIATION_INTERVAL` | `1h` (clamped `[10s, 1h]`) | Sweep cadence. |
| `EXCHANGE_RECONCILIATION_REPORT_GRACE` | `15m` | Transactions whose `expiry + grace` has not passed are held out of the sweep. |
| `EXCHANGE_RECONCILIATION_EDGE_LOG_SLA` | `5d` | Time after which a missing Edge log is "unrecoverable" (rows 5, 8, 11) rather than `DEFERRED`. |
| `EXCHANGE_RECONCILIATION_DEFAULT_POLICY` | `agent_correct` | `agent_correct` issues `RECONCILED_REFUNDED` on missing Edge log; `evidence_required` issues `FLAGGED_FOR_REVIEW`. |
| `EXCHANGE_RECONCILIATION_DISPUTE_SLA` | `24h` | Tier-2 dispute budget; expiry escalates to Tier-3 (`DISPUTE_STATUS_ESCALATED`). |
| `EXCHANGE_RECONCILIATION_ABUSE_THRESHOLD` | `5%` reject rate / 7d | Threshold for row 6's optional `abuse_flag`. Below: dismissed silently. At or above: agent flagged for operational review (NOT auto-banned). |

**Publisher delivery-log effective date.** `tenants.delivery_log_enabled_from TIMESTAMPTZ NULL`. NULL → publisher has not enabled delivery logs; missing-Edge-log rules downgrade to no-action. Non-NULL → only transactions with `created_at >= delivery_log_enabled_from` run the full table.

**Why `agent_correct` is the default.** The agent pays the Exchange; the publisher (whose Edge produces the delivery log) does not. When evidence cannot settle the question, biasing toward the paying party aligns the publisher's incentive with retaining their delivery log — lose the log, lose the revenue. Operators with strong publisher relationships can flip to `evidence_required`.

**Edge log past SLA.** Treated as "no Edge log" under `agent_correct` (rows 5/8/11) → `RECONCILED_REFUNDED`. Publisher revenue is reversed alongside the platform fee.

**Retries and DEFERRED.** A `DEFERRED` outcome writes a row so the operator sees stuck transactions. After `EDGE_LOG_SLA` elapses past `expiry`, the next sweep flips the row to one of the past-SLA outcomes (5/8/11).

### D6 — Manual review surface and dispute enqueueing

`DisputeTransaction` writes a row to `dispute_queue` and returns `DISPUTE_STATUS_FILED` plus an `estimated_resolution`. The verdict is produced asynchronously by the next sweep tick. Going synchronous would couple the dispute hot path to Edge-log query latency.

```sql
CREATE TABLE dispute_queue (
    dispute_id              UUID PRIMARY KEY,            -- maps to DisputeResponse.dispute_id
    transaction_id          UUID NOT NULL,
    tenant_id               UUID NOT NULL,
    caller_agent_id         TEXT NOT NULL,               -- ADR-009 D5 global agent_id
    caller_role             TEXT NOT NULL,               -- CallerAgent | CallerBroker
    caller_verified_at      TIMESTAMPTZ NOT NULL,        -- identity-verification timestamp from resolveCaller
    report_id               UUID NOT NULL,               -- FK to usage_report (required per proto)
    reason                  dispute_reason_enum NOT NULL,
    description             TEXT,
    received_content_hash   TEXT,
    received_hash_method    TEXT,
    status                  dispute_queue_status NOT NULL,  -- QUEUED | IN_PROGRESS | RESOLVED | ESCALATED | REJECTED
    queued_at               TIMESTAMPTZ NOT NULL,
    picked_up_at            TIMESTAMPTZ,
    resolved_at             TIMESTAMPTZ,
    reconciliation_id       UUID,                        -- FK to reconciliation_log once verdict produced
    original_rate_snapshot  NUMERIC(8,6) NOT NULL,       -- per ADR-010 D4: fee rate at Record time
    audit_signature         BYTEA NOT NULL               -- Ed25519 over the queued row
);
CREATE INDEX disp_queue_status_queued_at ON dispute_queue (status, queued_at);
CREATE INDEX disp_queue_tenant ON dispute_queue (tenant_id, status);
```

The queue row carries the verified identity (ADR-009) and the original-rate snapshot (ADR-010 D4). The deferred reconciliation does NOT re-authenticate the caller — the verified identity at submission binds the outcome (an agent may rotate keys between submission and verdict).

Agents retrieve verdicts via `GetDisputeStatus(dispute_id)` (separate proto MR).

**Operator queue for FLAGGED_FOR_REVIEW.** Rows 3, 10, plus policy overrides sit in a queue. Admin vocabulary:

| Action | Effect on `reconciliation_log` | Effect on ledger |
|---|---|---|
| `Refund(full)` | New row, `outcome=OPERATOR_OVERRIDE`, `refund_amount=<full>`, `decided_by=operator`. Original FLAGGED row stays — append-only. | `billing.Refund(full, idempotencyKey=new_reconciliation_id)`; inverse postings per ADR-010. |
| `Refund(partial, fraction)` | New row, `outcome=OPERATOR_OVERRIDE`, `refund_amount=<fraction × original>`. | `billing.Refund(partial, ...)`; proportional inverse postings. |
| `NoRefund` | New row, `outcome=OPERATOR_OVERRIDE`, `refund_amount=NULL`. | None. Original `Record` stands. |
| `AbuseFlag` | New row, `outcome=OPERATOR_OVERRIDE`, `refund_amount=NULL`, `operator_note='abuse_flag: <reason>'`. Often combined with a refund variant. | None directly; downstream policy consumes the flag. |

**Append-only.** No row is updated or deleted. An override produces a NEW row at the same `transaction_id`; the latest-by-`decided_at` row is the effective verdict. The audit trail records every machine verdict the operator reviewed AND every override.

**v1 surface.** Connect-Go RPC `ResolveFlaggedReconciliation` + minimal CLI. Web UI is v2.

### D7 — Inverse-posting policy (partial refund)

The policy is defined by ADR-010. This ADR consumes it via `billing.Refund`. Minimum bar:

1. A partial refund reverses publisher revenue and platform fee in the same `refund_fraction`.
2. `refund_fraction` comes from the rule table — quantity reconciliation: `1 - bytes_served / bytes_authorized`; rows 5/7/8/11: `1.0`; rows 3/10: operator picks.
3. The adapter rejects over-refund (cumulative > original recorded) per the follow-up contract.
4. Refund idempotency keys derive from the reconciliation row, not the transaction. A second reconciliation of the same transaction issues a new key; the adapter rejects an over-refund. Dedup is on the decision, not the transaction.

### D8 — Conformance test surface

The reconciler ships a conformance suite parametrised over three ports — `BillingAdapter`, `EdgeLogReader`, `ReconciliationStore` — each with in-memory and production implementations. Same fixtures run against both tuples; in-memory in `make test-fast`, real-Postgres+TigerBeetle in `make test-integration`.

**Fixtures:**

- **Six rule-row fixtures** — a subset of D3's twelve rows end-to-end (the rest are deterministic compositions). Each asserts: outcome matches D3, `reconciliation_log` row with correct `sources_seen` and `decided_by=auto`, adapter call sequence, TigerBeetle stamp when applicable.
- **Two negative-space fixtures** — (1) Edge log query fails transiently within SLA → `DEFERRED`; second tick after recovery produces the real outcome. (2) Agent report arrives after sweep tick → second tick produces a new row, append-only.

Every fixture sets a deterministic clock so SLA-boundary tests are exact.

The fake `EdgeLogReader` returns ADR-012-schema records; it is the adapter boundary, not the Edge runtime (exercised in `make test-e2e`).

---

## Out of scope (with upgrade path)

- **`user_data_64` / `user_data_32` TigerBeetle fields** — additional indexed dimensions (decision timestamp, sweep_batch_id). Free additive change when needed.
- **Per-tenant batch budgeting / round-robin slicing** — add when log metrics show one tenant consuming >70% of sweep budget for two consecutive cycles. Additive WHERE filter; no schema change.
- **Property-based / exhaustive fuzz tests** — generated transactions over the rule-table-input space. Defer until a real bug escapes the table tests.
- **Dispute webhook delivery** — push verdict instead of poll. Defer until polling pressure becomes a concern.
- **Postgres LISTEN/NOTIFY for dispute queue** — poll drain is simpler at v1 scale.
- **`GetDisputeStatus` proto RPC** — required by the deferred shape; tracked in a separate proto MR.
- **Bitemporal `tenant_capability_history`** — full enable/disable audit for delivery logs. Single `delivery_log_enabled_from` column suffices for v1.
- **Reconciler horizontal scaling** — shard by `tenant_id % N`. `sweep.tick_duration_ms` is the scale-out signal.
- **Content-attestation reconciliation** — when offer carries `content_hash` AND Edge attests `content_hash_served`, rows 3/7/10 collapse to deterministic outcomes. Strict-subset optimization; doesn't change the table.
- **Settlement-completeness sweep (committed `transaction_log` row vs posted ledger transfer)** — this ADR's D3 rule table reconciles *delivered bytes vs recorded charge*; it assumes the money leg exists. It does NOT cover the crash window between the WAL commit and the best-effort `Record`: if the Exchange process dies there, a delivered transaction has a committed row but its TigerBeetle hold expires natively — a **bounded, one-sided under-charge** (deterministic ids prevent any double-charge). Accepted for v1: the loss is bounded and one-sided. The reconciliation sweep that would re-post such rows is filed as a post-v1 follow-up (deferred past v1). Additive: a periodic query over committed rows with no settled transfer, idempotently re-settling or flagging them.

---

## Consequences

### Positive

- The post-commit best-effort `Record` becomes auditable; "trust the eventual pass" stops being a hand-wave.
- Agent reports and Edge logs become routine auditable inputs, not just dispute inputs.
- Operator overrides are append-only and signed.
- Per-Exchange SLAs are configurable knobs; freshness/timing/evidence-policy are tuning, not architecture changes.
- The two-artifact shape (Postgres row + TigerBeetle posting) makes audit queries decomposable.

### Negative

- `reconciliation_log` grows monotonically. At thousands-of-TPS, the table is multi-million-row within a quarter. Partition by `decided_at` (month) for v1; cold-storage archival in v2.
- Three sources mean three ways to be unavailable. The conformance suite is correspondingly large.
- The `agent_correct` default moves money toward the agent on missing evidence. Misconfigured SLAs (e.g. `EDGE_LOG_SLA = 1h` against a publisher whose log infrastructure lags by 24h) refund every transaction.
- Operator queue depth is a new SRE surface. `FLAGGED_FOR_REVIEW` blocks settlement until the operator acts; per-tenant queue-depth alerts and `DISPUTE_SLA` escalation are the safety nets.
- Disputes are asynchronous. The wait is bounded by the sweep interval; operators who need sub-minute resolution dial the interval down.

### Rejected alternatives

- **Reconcile synchronously inside `ExecuteTransaction` / `ReportUsage`** — couples request path to Edge log availability; explodes latency budget. The whole point of post-commit `Record` is that reconciliation is OUT of the request path.
- **Synchronous `DisputeTransaction` RPC** — couples dispute hot path to Edge-log latency; the Edge log is a remote pull per ADR-012 D3.
- **Trust the agent's report unilaterally on disagreement** — discards the Edge's signed physical-truth record.
- **Trust the Edge log unilaterally on disagreement** — ignores the case where bytes were delivered but were the wrong content.
- **Single global SLA across Exchanges** — reconciliation timing is commercial; one Exchange's RTB-style traffic needs different SLAs than another's daily-batch agents.
- **One-shot reconciliation at expiry, never again** — conflates "expired" with "all we will ever learn." Disputes file after expiry; first Edge query may have failed; appeals re-open resolved cases. Append-only and re-entrant are required.
- **Hashing layer between `transaction_id` and `user_data_128`** — unnecessary; UUIDs are natively 16 bytes (Go: `uuid.UUID` IS `[16]byte`).

---

## Non-goals

- This ADR does not design the Edge delivery-log contract (ADR-012).
- It does not design publisher payout (ADR-010).
- It does not specify the dispute UX surface beyond the proto's RPC contract.
- It does not pick SLA values — it specifies the knobs.
- It does not specify the TigerBeetle adapter (the persisted-ledger ticket).
- It does not redesign the proto's `DisputeStatus` lifecycle (proto lines 2069–2104).
