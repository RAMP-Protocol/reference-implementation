-- Restore the pre-000014 legacy ramp.denial_reason enum (the 13 values from
-- 000001 plus RESTRICTION_NOT_SATISFIED added by 000013). The column is
-- unwritten, so the USING cast maps NULL->NULL with no data migration.
ALTER TYPE ramp.denial_reason RENAME TO denial_reason_proto;

CREATE TYPE ramp.denial_reason AS ENUM (
    'INVALID_LICENSE',
    'EXPIRED_LICENSE',
    'INSUFFICIENT_BALANCE',
    'RATE_LIMITED',
    'CONTENT_UNAVAILABLE',
    'FUNCTION_PROHIBITED',
    'GEO_RESTRICTED',
    'REPORTING_OVERDUE',
    'OFFER_EXPIRED',
    'SIGNATURE_INVALID',
    'QUOTA_EXCEEDED',
    'DELEGATION_EXPIRED',
    'SCOPE_INSUFFICIENT',
    'RESTRICTION_NOT_SATISFIED'
);

ALTER TABLE ramp.transaction_log
    ALTER COLUMN denial_reason TYPE ramp.denial_reason
    USING denial_reason::text::ramp.denial_reason;

DROP TYPE ramp.denial_reason_proto;
