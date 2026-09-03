-- name: GetTenantByDomain :one
SELECT * FROM ramp.tenants WHERE domain = $1;

-- name: GetTenantByID :one
SELECT * FROM ramp.tenants WHERE tenant_id = $1;

-- name: InsertTenant :one
INSERT INTO ramp.tenants (
    tenant_id, domain, ed25519_key_ref, reporting_policy,
    signing_scheme, rsa_key_ref, cloudfront_key_pair_id
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: SetTenantAllowBrokerRelay :exec
-- Flips the broker-relay opt-in for a tenant. Admin / fixture path; the
-- column defaults to FALSE on insert so this is only needed when a tenant
-- explicitly opts into broker-on-behalf reporting.
UPDATE ramp.tenants
   SET allow_broker_relay = $2
 WHERE tenant_id = $1;

-- name: SetTenantReportingPolicy :execrows
-- Replaces the reporting_policy JSONB for a tenant. The admin SetReportingPolicy
-- RPC write path (also used by fixtures to seed required_fields,
-- quantity_tolerance, or window_seconds without bypassing the repo layer).
-- Returns rows-affected so the caller can tell a real update from a no-op on a
-- missing tenant.
UPDATE ramp.tenants
   SET reporting_policy = $2
 WHERE tenant_id = $1;

-- name: SetTenantActivateNewAgentsByDefault :execrows
-- Flips the per-tenant policy for whether a newly registered agent starts
-- active in the billing system-of-record. Admin / fixture path; the column
-- defaults to TRUE on insert, so this is only needed to opt a tenant out.
-- Mirrors SetTenantAllowBrokerRelay.
-- Returns rows-affected so a call for a missing tenant is a detectable no-op
-- rather than a silent success.
UPDATE ramp.tenants
   SET activate_new_agents_by_default = $2
 WHERE tenant_id = $1;

-- name: SetTenantDefaultAgentCredit :execrows
-- Replaces the per-tenant default credit granted to a newly registered agent
-- (deployment ledger currency; 0 disables the grant). Written by the boot-time
-- env seeding (EXCHANGE_DEFAULT_AGENT_CREDIT); otherwise set out of band like
-- activate_new_agents_by_default — there is no admin RPC.
-- Returns rows-affected so a call for a missing tenant is a detectable no-op
-- rather than a silent success.
UPDATE ramp.tenants
   SET default_agent_credit = $2
 WHERE tenant_id = $1;

-- name: SetTenantFeeRateBps :execrows
-- Replaces the tenant-level default commission rate (basis points) and the
-- operator note in one write. The admin SetTenantFeeRate RPC write path (also a
-- fixture mutator). Full replace: fee_rate_notes is set to $3, which is NULL
-- when the operator omits it. Returns rows-affected so a call for a missing
-- tenant is a detectable no-op rather than a silent success.
UPDATE ramp.tenants
   SET fee_rate_bps = $2,
       fee_rate_notes = $3
 WHERE tenant_id = $1;
