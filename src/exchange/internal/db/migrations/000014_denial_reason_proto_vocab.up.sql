-- Reconcile ramp.denial_reason with the canonical proto DenialReason vocabulary
-- (ADR-019: "the database denial enum stores the proto DenialReason - no
-- parallel vocabulary"). The legacy enum carried values that do not exist in
-- ramp.v1.DenialReason (INVALID_LICENSE, EXPIRED_LICENSE, FUNCTION_PROHIBITED,
-- GEO_RESTRICTED, DELEGATION_EXPIRED) and lacked ones that do
-- (BILLING_REF_INACTIVE, DELEGATION_INVALID, and the ENTITLEMENT_* /
-- SUBSCRIPTION_LAPSED family). PostgreSQL has no ALTER TYPE ... DROP VALUE, so
-- aligning the set requires rebuilding the type.
--
-- The denial_reason column is currently UNWRITTEN (denials abort before a
-- transaction_log row is recorded), so the USING cast only ever maps NULL->NULL
-- and carries no data migration. The enum values are the proto DenialReason
-- value names with the redundant DENIAL_REASON_ prefix stripped (protobuf's own
-- convention) - one vocabulary, value-for-value with the contract.
ALTER TYPE ramp.denial_reason RENAME TO denial_reason_legacy;

CREATE TYPE ramp.denial_reason AS ENUM (
    'BILLING_REF_INACTIVE',
    'INSUFFICIENT_BALANCE',
    'RATE_LIMITED',
    'CONTENT_UNAVAILABLE',
    'RESTRICTION_NOT_SATISFIED',
    'REPORTING_OVERDUE',
    'OFFER_EXPIRED',
    'SIGNATURE_INVALID',
    'QUOTA_EXCEEDED',
    'DELEGATION_INVALID',
    'SCOPE_INSUFFICIENT',
    'ENTITLEMENT_MISSING',
    'ENTITLEMENT_MALFORMED',
    'ENTITLEMENT_EXPIRED',
    'ENTITLEMENT_WRONG_BUYER',
    'SUBSCRIPTION_LAPSED',
    'ENTITLEMENT_NOT_GRANTED',
    'ENTITLEMENT_STALE_ATTENUATION'
);

ALTER TABLE ramp.transaction_log
    ALTER COLUMN denial_reason TYPE ramp.denial_reason
    USING denial_reason::text::ramp.denial_reason;

DROP TYPE ramp.denial_reason_legacy;
