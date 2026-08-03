-- Reverse of 000018_catalog_resource_owner.up.sql.

ALTER TABLE ramp.catalog
    DROP COLUMN resource_owner_id;
