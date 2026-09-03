-- Follow the proto DenialReason vocabulary through its account split.
--
-- ADR-019 binds the database enum to the proto vocabulary value-for-value ("The
-- database denial enum stores the proto DenialReason — no parallel vocabulary").
-- The protocol revision this Exchange now pins replaced BILLING_REF_INACTIVE
-- with two values that tell the agent different things to do:
--
--   ACCOUNT_NOT_REGISTERED  no account exists here — call Register
--   ACCOUNT_INACTIVE        the account exists and the operator has not
--                           activated it — waiting is the remedy, registering
--                           again is not
--
-- PostgreSQL has no ALTER TYPE ... DROP VALUE, so replacing a value means
-- rebuilding the type (the same shape as 000014 and 000022).
--
-- The denial_reason column is UNWRITTEN — a denial aborts before a
-- transaction_log row is recorded, and the reason travels on the response
-- message instead — so the USING cast maps NULL->NULL and carries no data
-- migration. That is why this can be a straight replacement rather than a
-- two-step migration through a period where both spellings are legal.

ALTER TYPE ramp.denial_reason RENAME TO denial_reason_billing_ref;

CREATE TYPE ramp.denial_reason AS ENUM (
    'ACCOUNT_INACTIVE',
    'ACCOUNT_NOT_REGISTERED',
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
    'ENTITLEMENT_NOT_GRANTED'
);

ALTER TABLE ramp.transaction_log
    ALTER COLUMN denial_reason TYPE ramp.denial_reason
    USING denial_reason::text::ramp.denial_reason;

DROP TYPE ramp.denial_reason_billing_ref;
