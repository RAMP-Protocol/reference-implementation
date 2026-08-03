-- name: AppendAuditLog :exec
-- Appends one admin control-plane change to the append-only audit log. Written
-- inside the setter's transaction, after the rows-affected check, so an
-- unknown-tenant no-op leaves no row.
INSERT INTO ramp.audit_log (
    log_id, actor, source_addr, action, detail, tenant_id, request_id
) VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: AuditLogByTenant :many
-- Returns the audit trail for a tenant, most recent first. Read path for admin
-- change reconstruction and the integration tests' side-effect assertions.
SELECT * FROM ramp.audit_log
 WHERE tenant_id = $1
 ORDER BY created_at DESC;
