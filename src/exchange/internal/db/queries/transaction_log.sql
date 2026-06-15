-- name: CreateTransaction :one
-- Writes the full transaction row. The handler MUST await this commit before
-- returning the signed URL to the caller (write-before-sign invariant).
INSERT INTO ramp.transaction_log (
    transaction_id, tx_request_id, tenant_id, agent_id, resource_id,
    offer_id, agent_identity_hash, signed_url_hash, expiry,
    billing_id, unit_cost, currency, consumed_unit, denial_reason
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING *;

-- name: GetTransactionByRequestID :one
-- Idempotency lookup: return a prior transaction for the same tx_request_id.
SELECT * FROM ramp.transaction_log WHERE tx_request_id = $1;
