-- Drop biscuit/subscription scaffolding from Exchange (slice T7).
--
-- v1 obligations 00/03/04/05 do not exercise the subscription path or the
-- biscuit-derived principal-identity facts. Per the EPIC, "nothing and I
-- emphasize nothing anywhere" of that scaffolding survives in Exchange.
--
-- Columns removed:
--   ramp.catalog.subscription_id       (added by 000004) — subscription-priced
--                                       variant pointer, only consumed by the
--                                       subscription-coverage offer path.
--   ramp.catalog.required_scopes        (added by 000004) — Biscuit scope set
--                                       a caller's Delegation had to cover.
--   ramp.transaction_log.identity_source(added by 000003) — verified Biscuit
--                                       principal source (e.g. "google").
--   ramp.transaction_log.identity_sub   (added by 000003) — verified Biscuit
--                                       principal subject (e.g. user email).
--   ramp.transaction_log.subscription_id(added by 000004) — subscription this
--                                       transaction was billed against; only
--                                       non-null on the dropped subscription
--                                       path. The per-request path leaves it
--                                       empty, so the column has no surviving
--                                       reader.
--
-- The DOWN mirror re-adds the columns in their original NULLable shape so a
-- 7 -> 6 downgrade restores the schema 000003/000004 produced (without the
-- historical biscuit/subscription code paths).

ALTER TABLE ramp.catalog
    DROP COLUMN IF EXISTS subscription_id,
    DROP COLUMN IF EXISTS required_scopes;

ALTER TABLE ramp.transaction_log
    DROP COLUMN IF EXISTS identity_source,
    DROP COLUMN IF EXISTS identity_sub,
    DROP COLUMN IF EXISTS subscription_id;
