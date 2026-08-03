-- Add LicenseTerm storage to the catalog (Universal Licensing Core).
--
-- `terms` holds the serialized repeated rampv1.LicenseTerm exactly as the
-- publisher pushed it via CatalogService.PushResources. It is persistence, not
-- a query surface: Validate/Select run in Go over rampv1.LicenseTerm, so the
-- column is a JSONB array — consistent with `pricing` and `licensing_rules`
-- already being JSONB. NOT NULL DEFAULT '[]' backfills existing rows online.
--
-- This is the EXPAND step. `licensing_rules` (former home of the removed
-- AccessRestrictions structure) is dropped in a later CONTRACT migration once
-- the sqlc queries and repo layer no longer reference
-- it — keeping the tree green between steps.

ALTER TABLE ramp.catalog
    ADD COLUMN terms JSONB NOT NULL DEFAULT '[]'::jsonb;
