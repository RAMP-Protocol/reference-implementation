-- name: CreateObligation :one
INSERT INTO ramp.reporting_obligations (
    obligation_id, transaction_id, state, window_seconds, deadline,
    required_fields, estimated_quantity, quantity_tolerance
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetObligationByTransaction :one
SELECT * FROM ramp.reporting_obligations
 WHERE transaction_id = $1
 ORDER BY created_at DESC
 LIMIT 1;

-- name: GetObligationWithTransaction :one
-- Loads the most-recent obligation for a transaction together with the
-- transaction + tenant fields required for protocol validation AND for the
-- caller-identity / broker-relay authorization checks. Single round-trip
-- for ReportUsage's pre-persist validation; the *ForUpdate variant below
-- locks the obligation row so concurrent reports cannot race the state
-- transition.
SELECT ro.obligation_id, ro.transaction_id, ro.state, ro.window_seconds, ro.deadline,
       ro.consumed_quantity, ro.received_at, ro.created_at, ro.required_fields,
       ro.estimated_quantity, ro.quantity_tolerance, ro.validation_outcome, ro.validated_at,
       ro.source_report_id, ro.issued_report_id,
       tl.created_at        AS tx_created_at,
       tl.billing_id        AS tx_billing_id,
       tl.tenant_id         AS tx_tenant_id,
       tl.agent_id          AS tx_agent_id,
       t.allow_broker_relay AS tenant_allow_broker_relay
  FROM ramp.reporting_obligations ro
  JOIN ramp.transaction_log tl ON tl.transaction_id = ro.transaction_id
  JOIN ramp.tenants          t ON t.tenant_id        = tl.tenant_id
 WHERE ro.transaction_id = $1
 ORDER BY ro.created_at DESC
 LIMIT 1;

-- name: GetObligationWithTransactionForUpdate :one
-- Same join as GetObligationWithTransaction but locks the obligation row for
-- the duration of the surrounding transaction. ReportUsage uses this inside
-- pgx.BeginFunc so the load/validate/write happens atomically against a held
-- row. The transaction_log + tenants rows are read-only
-- on this path and need no lock.
SELECT ro.obligation_id, ro.transaction_id, ro.state, ro.window_seconds, ro.deadline,
       ro.consumed_quantity, ro.received_at, ro.created_at, ro.required_fields,
       ro.estimated_quantity, ro.quantity_tolerance, ro.validation_outcome, ro.validated_at,
       ro.source_report_id, ro.issued_report_id,
       tl.created_at        AS tx_created_at,
       tl.billing_id        AS tx_billing_id,
       tl.tenant_id         AS tx_tenant_id,
       tl.agent_id          AS tx_agent_id,
       t.allow_broker_relay AS tenant_allow_broker_relay
  FROM ramp.reporting_obligations ro
  JOIN ramp.transaction_log tl ON tl.transaction_id = ro.transaction_id
  JOIN ramp.tenants          t ON t.tenant_id        = tl.tenant_id
 WHERE ro.transaction_id = $1
 ORDER BY ro.created_at DESC
 LIMIT 1
 FOR UPDATE OF ro;

-- name: FindObligationBySourceReportID :one
-- Idempotent-retry probe for ReportUsage: returns the obligation row whose
-- (transaction_id, source_report_id) pair was already recorded. A non-empty
-- hit means the caller is replaying a prior UsageReport and the service must
-- return the original issued_report_id without re-running validation.
SELECT * FROM ramp.reporting_obligations
 WHERE transaction_id = $1
   AND source_report_id = $2
 LIMIT 1;

-- name: MarkValidationValidated :one
-- Sets validation_outcome=VALIDATED, transitions state PENDING→RECEIVED, and
-- writes the consumed quantity + idempotency anchors. The state predicate is
-- the duplicate-report guard: a second report against an obligation already
-- in RECEIVED matches zero rows and the caller surfaces FailedPrecondition.
-- The partial unique index on (transaction_id, source_report_id) prevents
-- two concurrent "same-id" writes from both succeeding.
UPDATE ramp.reporting_obligations
   SET state              = 'RECEIVED',
       consumed_quantity  = $2,
       received_at        = NOW(),
       validation_outcome = 'VALIDATED',
       validated_at       = NOW(),
       source_report_id   = $3,
       issued_report_id   = $4
 WHERE obligation_id = $1
   AND state         = 'PENDING'
RETURNING *;

-- name: MarkValidationRejected :one
-- Records the rejection outcome without changing obligation state. The audit
-- row is written for every rejection so disputes have a trail, but the
-- obligation stays PENDING and the caller may retry with a corrected report
-- until the deadline expires.
UPDATE ramp.reporting_obligations
   SET validation_outcome = $2,
       validated_at       = NOW(),
       source_report_id   = COALESCE($3, source_report_id)
 WHERE obligation_id = $1
RETURNING *;

-- name: ListOutstandingObligations :many
-- Returns reporting obligations whose deadline has passed but which still
-- sit in PENDING for a specific (tenant_id, agent_id). Joins to
-- transaction_log because reporting_obligations does not carry tenant_id /
-- agent_id columns directly. The result drives the ExecuteTransaction
-- reporting-overdue refusal: a non-empty list refuses the agent's next
-- transaction with FailedPrecondition until it files the missing report.
SELECT ro.obligation_id, ro.transaction_id, ro.state, ro.window_seconds,
       ro.deadline, ro.consumed_quantity, ro.received_at, ro.created_at,
       ro.required_fields, ro.estimated_quantity, ro.quantity_tolerance,
       ro.validation_outcome, ro.validated_at,
       ro.source_report_id, ro.issued_report_id
  FROM ramp.reporting_obligations AS ro
  JOIN ramp.transaction_log AS tl ON tl.transaction_id = ro.transaction_id
 WHERE tl.tenant_id = $1
   AND tl.agent_id = $2
   AND ro.state = 'PENDING'
   AND ro.deadline < NOW()
 ORDER BY ro.deadline ASC;
