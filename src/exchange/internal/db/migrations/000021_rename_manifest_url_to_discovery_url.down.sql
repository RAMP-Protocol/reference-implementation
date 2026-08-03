-- Reverse of 000018_rename_manifest_url_to_discovery_url.up.sql.

ALTER TABLE ramp.agents RENAME COLUMN discovery_url TO manifest_url;
