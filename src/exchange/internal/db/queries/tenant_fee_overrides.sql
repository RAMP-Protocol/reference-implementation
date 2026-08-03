-- name: GetResourceOwnerFeeOverride :one
-- Returns the per-(tenant, resource_owner) commission override in basis points,
-- or no row when none is configured (the caller falls back to the tenant default).
SELECT fee_rate_bps FROM ramp.tenant_resource_owner_fee
 WHERE tenant_id = $1 AND resource_owner_id = $2;

-- name: UpsertResourceOwnerFeeOverride :exec
-- Sets the override commission for one resource owner under one tenant. Admin /
-- fixture path; the CHECK (0 <= fee_rate_bps < 10000) rejects an out-of-range rate.
INSERT INTO ramp.tenant_resource_owner_fee (tenant_id, resource_owner_id, fee_rate_bps)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, resource_owner_id) DO UPDATE
    SET fee_rate_bps = EXCLUDED.fee_rate_bps,
        updated_at   = NOW();
