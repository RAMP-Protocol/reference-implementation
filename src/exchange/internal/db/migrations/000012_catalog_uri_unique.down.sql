-- Reverse of 000012_catalog_uri_unique.up.sql: drop the URI ownership constraint.

ALTER TABLE ramp.catalog
    DROP CONSTRAINT catalog_uri_key;
