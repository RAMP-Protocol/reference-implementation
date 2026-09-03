-- name: InsertTransactionRequestClaim :execrows
INSERT INTO ramp.transaction_request_claims (agent_id, idempotency_key, items_digest)
VALUES ($1, $2, $3)
ON CONFLICT (agent_id, idempotency_key) DO NOTHING;

-- name: GetTransactionRequestClaim :one
SELECT * FROM ramp.transaction_request_claims
 WHERE agent_id = $1 AND idempotency_key = $2;

-- name: FinalizeTransactionRequestClaim :execrows
UPDATE ramp.transaction_request_claims
   SET response_payload = $3
 WHERE agent_id = $1 AND idempotency_key = $2 AND response_payload IS NULL;
