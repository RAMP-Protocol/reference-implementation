-- Add the resource-owner payee identity to the catalog.
--
-- `resource_owner_id` is the owner-attested account that catalog revenue settles
-- to. It is read at push time from the owning manifest's authorized-exchange
-- entry and is distinct from the operational `tenant_id`: one owner may span many
-- domains (and tenants), so this column is deliberately NOT tenant-scoped — the
-- same value can appear on rows under different tenants (the grouping property).
-- The row itself stays tenant-scoped via `tenant_id`.
--
-- NOT NULL DEFAULT '' keeps the ALTER instant (a constant default, no table
-- rewrite). The push gate enforces a non-empty value for every new row; the empty
-- default only ever applies to rows that predate this column. Operators upgrading a
-- database that already held catalog rows must backfill resource_owner_id on those
-- pre-existing rows before enabling settlement — an empty value would settle revenue
-- to a shared owner:revenue: bucket.

ALTER TABLE ramp.catalog
    ADD COLUMN resource_owner_id TEXT NOT NULL DEFAULT '';
