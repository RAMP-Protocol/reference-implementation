-- name: CreateEvidence :exec
-- Writes the append-once evidence row for a successfully executed transaction
-- item: the full signed offer + both-party signatures + both verifying public
-- keys + the delivered URL. Written inside the same transaction as the
-- transaction_log + obligation rows, after the transaction_log row exists (the
-- transaction_id FK). The row is never updated or deleted (append-once triggers).
INSERT INTO ramp.transaction_evidence (
    transaction_id, tenant_id,
    offer_id, offer_json, offer_canonical_bytes,
    offer_signature, offer_signature_algorithm, exchange_signing_public_key,
    agent_acceptance_signature, agent_acceptance_canonical_bytes,
    agent_acceptance_signature_algorithm,
    requester_id, requester_domain, request_idempotency_key,
    agent_public_key, agent_discovery_url,
    signed_url_full, request_id, request_id_minted
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
);

-- name: GetEvidenceByTenantAndTransactionID :one
-- Reads one tenant's evidence row. This is the DEFAULT read: transaction_id is
-- globally unique, but the tenant predicate keeps Architecture Rule 4 structural
-- rather than a checked-by-convention property of every future call site. The
-- payload here — the full offer, both signatures, both keys and a delivered
-- signed URL — is materially more sensitive than transaction_log's.
SELECT * FROM ramp.transaction_evidence
WHERE tenant_id = $1 AND transaction_id = $2;

-- name: GetEvidenceByTransactionIDCrossTenant :one
-- admin:cross_tenant — DELIBERATELY not tenant-filtered, for the operator-facing
-- admin plane (which has no per-tenant scope, ADR-022) and the cross-tenant
-- reconciliation sweep (ADR-011 D2, whose eligibility scan carries the same
-- marker). Every call site must carry the marker too. Tenant-scoped callers use
-- GetEvidenceByTenantAndTransactionID; the returned row carries tenant_id so a
-- caller here can still assert the binding.
SELECT * FROM ramp.transaction_evidence WHERE transaction_id = $1;
