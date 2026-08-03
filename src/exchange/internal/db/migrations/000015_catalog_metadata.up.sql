-- Add resource-metadata storage to the catalog (resource extension
-- round-trip).
--
-- `metadata` holds the serialized resource extension fields (content_id,
-- word_count, hashes, source/provenance, ext, ext_critical, attestations) that
-- a publisher pushes via CatalogService.PushResources, projected back onto the
-- Offer at discovery. It is persistence, not a query surface — Validate/Select
-- never touch it — so it is a single JSONB document, consistent with `terms`
-- and `pricing` already being JSONB.
--
-- NULLABLE with no DEFAULT: the column is purely additive, so the ALTER is
-- instant and existing rows are left as NULL (legacy resources carry no
-- metadata and are unaffected).

ALTER TABLE ramp.catalog
    ADD COLUMN metadata JSONB;
