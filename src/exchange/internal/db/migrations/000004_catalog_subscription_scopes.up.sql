-- Extend catalog + transaction_log for Path F (subscription-priced offers).
--
-- catalog.subscription_id + catalog.required_scopes let an entry advertise a
-- subscription-priced variant (rate=0) and declare the scope set a caller's
-- Biscuit must cover. Both nullable: legacy rows remain public.
--
-- transaction_log.subscription_id records which subscription a transaction
-- was billed against (null = per-request, non-null = subscription path with
-- billing.Authorize skipped).

ALTER TABLE ramp.catalog
    ADD COLUMN subscription_id TEXT,      -- subscription-priced variant pointer; NULL means per-request only
    ADD COLUMN required_scopes TEXT[];    -- Biscuit scope set a caller's Delegation must cover; NULL means public access

ALTER TABLE ramp.transaction_log
    ADD COLUMN subscription_id TEXT;      -- which subscription this transaction was billed against; NULL = per-request path
