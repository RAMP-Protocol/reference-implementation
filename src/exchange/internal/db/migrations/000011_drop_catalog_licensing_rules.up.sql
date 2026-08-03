-- CONTRACT step of the LicenseTerm migration (Universal Licensing Core).
--
-- 000010 added ramp.catalog.terms (EXPAND). Now that the sqlc queries
-- and the repo/service layers no longer reference `licensing_rules` — the former
-- home of the removed AccessRestrictions structure — the column is dead weight.
-- Dropping it here keeps the tree green: no Go, sqlc, or Python path reads it.

ALTER TABLE ramp.catalog
    DROP COLUMN licensing_rules;
