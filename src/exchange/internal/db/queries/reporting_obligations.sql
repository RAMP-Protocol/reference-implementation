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

-- name: FindAcceptedObligationBySourceReportID :one
-- Idempotent-retry probe for ReportUsage: returns the obligation row whose
-- (transaction_id, source_report_id) pair was already recorded AND ACCEPTED.
-- "Accepted" is in the name because it is in the predicate: a caller wanting the
-- row for a key that was only ever rejected will not find it here. A
-- hit means the caller is replaying a report this Exchange already validated,
-- so the service returns the original issued_report_id without re-running
-- validation.
--
-- issued_report_id IS NOT NULL is what makes "accepted" the condition rather
-- than "seen". A rejected report also persists source_report_id, so without
-- this predicate a retry carrying the same key would match, return 200 with an
-- empty report_id, and never re-validate -- the obligation would stay PENDING
-- while the agent believed it had reported. issued_report_id is written only on
-- acceptance, so it already means exactly "there is a result to replay".
SELECT * FROM ramp.reporting_obligations
 WHERE transaction_id = $1
   AND source_report_id = $2
   AND issued_report_id IS NOT NULL
 LIMIT 1;

-- name: MarkValidationValidated :one
-- Sets validation_outcome=VALIDATED, transitions state PENDING→RECEIVED, and
-- writes the consumed quantity + idempotency anchors. The state predicate is
-- the duplicate-report guard: a second report against an obligation already
-- in RECEIVED matches zero rows and the caller surfaces FailedPrecondition.
-- The partial unique index on (transaction_id, source_report_id) prevents
-- two concurrent "same-id" writes from both succeeding.
--
-- received_at and validated_at come from the caller, not NOW(). The deadline
-- they are compared against was written from the service clock, so reading the
-- database clock here would compare two different clocks: received_at > deadline
-- would not be a sound lateness check, and a test could not drive the comparison
-- deterministically.
UPDATE ramp.reporting_obligations
   SET state              = 'RECEIVED',
       consumed_quantity  = sqlc.arg(consumed_quantity),
       received_at        = sqlc.arg(now),
       validation_outcome = 'VALIDATED',
       validated_at       = sqlc.arg(now),
       source_report_id   = sqlc.arg(source_report_id),
       issued_report_id   = sqlc.arg(issued_report_id)
 WHERE obligation_id = sqlc.arg(obligation_id)
   AND state         = 'PENDING'
RETURNING *;

-- name: MarkValidationRejected :one
-- Records the rejection outcome for an obligation that is still PENDING. An
-- audit row is written for every rejection against a PENDING obligation, so
-- disputes have a trail; a report against an obligation that has already
-- settled matches zero rows and writes nothing, and the service logs the
-- refusal instead. The state is left alone so the caller may retry with a
-- corrected report. The
-- retry may reuse the same source_report_id: the replay probe above fires only
-- on an accepted result, so a corrected retry under the original key is
-- validated afresh rather than short-circuited.
--
-- The state predicate matches the accept statement above, and for a stronger
-- reason than symmetry. Without it a second, invalid report against an
-- obligation already in RECEIVED would commit over the settled row: the outcome
-- would walk back from VALIDATED to a rejection, and source_report_id would move
-- off the accepted key, so a later replay of that key would miss the probe and
-- be refused as already-reported. Zero rows updated means the obligation was not
-- PENDING, and the caller surfaces FailedPrecondition.
--
-- validated_at comes from the caller for the same reason as the accept
-- statement above: the obligation's three report timestamps all come from the
-- service clock, so they can be compared against the deadline written from it.
UPDATE ramp.reporting_obligations
   SET validation_outcome = sqlc.arg(validation_outcome),
       validated_at       = sqlc.arg(now),
       source_report_id   = COALESCE(sqlc.narg(source_report_id), source_report_id)
 WHERE obligation_id = sqlc.arg(obligation_id)
   AND state         = 'PENDING'
RETURNING *;

-- name: CountObligationsByStateAndDueness :many
-- The reporting-compliance fact table for one (tenant_id, agent_id): how many
-- obligations sit in each state, split by whether their deadline had already
-- passed at as_of. It returns at most four rows (two states x two dueness
-- values) whatever the agent's history, but that bounds the result, not the
-- work: the join is served by reporting_obligations_transaction_idx, so the
-- rows READ are the agent's own obligations rather than the whole table. Drop
-- that index and this becomes a sequential scan of every tenant's obligations,
-- once per executed item, in front of fund reservation.
--
-- It counts and classifies nothing. Which bucket means "overdue", which ones
-- form the denominator, and where the thresholds sit are the Exchange's
-- reporting policy, and that policy is applied in the service so a future
-- per-tenant rule reads these same numbers differently without a new query.
--
-- Joins to transaction_log because reporting_obligations carries no tenant_id /
-- agent_id column of its own. as_of is the service clock's instant: the deadline
-- it is compared against was written from that same clock.
--
-- The ::boolean cast pins the generated Go field to bool. deadline is NOT NULL,
-- so the comparison is never null.
SELECT ro.state,
       (ro.deadline < sqlc.arg(as_of))::boolean AS past_deadline,
       COUNT(*)                                 AS n
  FROM ramp.reporting_obligations AS ro
  JOIN ramp.transaction_log AS tl ON tl.transaction_id = ro.transaction_id
 WHERE tl.tenant_id = sqlc.arg(tenant_id)
   AND tl.agent_id  = sqlc.arg(agent_id)
 GROUP BY ro.state, past_deadline;
