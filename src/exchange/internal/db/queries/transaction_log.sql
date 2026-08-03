-- name: CreateTransaction :one
-- Writes the full transaction row. The handler MUST await this commit before
-- returning the signed URL to the caller (write-before-sign invariant).
INSERT INTO ramp.transaction_log (
    transaction_id, idempotency_key, tenant_id, agent_id, resource_id,
    offer_id, agent_identity_hash, signed_url_hash, expiry,
    billing_id, unit_cost, currency, consumed_unit, denial_reason,
    result_payload
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: GetTransactionByIdempotencyKey :one
-- Idempotency lookup: return a prior transaction for the same idempotency_key.
SELECT * FROM ramp.transaction_log WHERE idempotency_key = $1;

-- name: GetTransactionByID :one
-- Read a transaction by its public transaction_id (the value the resolve /
-- ExecuteTransaction response returns). Unique-key audit read: like
-- GetTransactionByIdempotencyKey it is keyed on a globally-unique id and is not
-- tenant-filtered; the returned row carries tenant_id so callers scope/assert
-- the tenant binding themselves.
SELECT * FROM ramp.transaction_log WHERE transaction_id = $1;
