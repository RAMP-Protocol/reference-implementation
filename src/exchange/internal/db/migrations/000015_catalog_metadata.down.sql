-- Reverse of 000014_catalog_metadata.up.sql.

ALTER TABLE ramp.catalog
    DROP COLUMN metadata;
