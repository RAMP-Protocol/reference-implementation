-- name: GetTenantByDomain :one
SELECT * FROM ramp.tenants WHERE domain = $1;

-- name: GetTenantByID :one
SELECT * FROM ramp.tenants WHERE tenant_id = $1;

-- name: InsertTenant :one
INSERT INTO ramp.tenants (
    tenant_id, domain, hmac_secret_ref, ed25519_key_ref, reporting_policy,
    signing_scheme, rsa_key_ref, cloudfront_key_pair_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: SetTenantAllowBrokerRelay :exec
-- Flips the broker-relay opt-in for a tenant. Admin / fixture path; the
-- column defaults to FALSE on insert so this is only needed when a tenant
-- explicitly opts into broker-on-behalf reporting.
UPDATE ramp.tenants
   SET allow_broker_relay = $2
 WHERE tenant_id = $1;

-- name: SetTenantReportingPolicy :exec
-- Replaces the reporting_policy JSONB for a tenant. Admin / fixture path
-- for tests that need to seed required_fields, quantity_tolerance, or
-- window_seconds defaults without bypassing the repo layer (review
-- finding 7 — no raw pool.Exec in tests).
UPDATE ramp.tenants
   SET reporting_policy = $2
 WHERE tenant_id = $1;
