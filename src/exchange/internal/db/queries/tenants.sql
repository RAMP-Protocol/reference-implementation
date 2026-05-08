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
