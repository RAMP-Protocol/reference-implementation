-- name: CreateObligation :one
INSERT INTO ramp.reporting_obligations (
    obligation_id, transaction_id, state, window_seconds, deadline
) VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: MarkObligationReceived :one
UPDATE ramp.reporting_obligations
   SET state = 'RECEIVED',
       consumed_quantity = $2,
       received_at = NOW()
 WHERE obligation_id = $1
RETURNING *;

-- name: GetObligationByTransaction :one
SELECT * FROM ramp.reporting_obligations
 WHERE transaction_id = $1
 ORDER BY created_at DESC
 LIMIT 1;
