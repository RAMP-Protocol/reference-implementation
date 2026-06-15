-- Reverse of 000007: re-add the biscuit/subscription columns 000003 and 000004
-- introduced. Mirrors 000003_transaction_principal_identity.up.sql and
-- 000004_catalog_subscription_scopes.up.sql (without the subscription_id on
-- transaction_log half of 000004) in their original NULLable shape.

ALTER TABLE ramp.transaction_log
    ADD COLUMN identity_source TEXT,
    ADD COLUMN identity_sub    TEXT,
    ADD COLUMN subscription_id TEXT;

ALTER TABLE ramp.catalog
    ADD COLUMN subscription_id TEXT,
    ADD COLUMN required_scopes TEXT[];
