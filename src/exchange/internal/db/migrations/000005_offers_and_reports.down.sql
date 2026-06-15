DROP TABLE IF EXISTS ramp.transaction_reports;
DROP TABLE IF EXISTS ramp.report_tokens;
DROP TABLE IF EXISTS ramp.offers;
DROP INDEX IF EXISTS ramp.transaction_log_resource_id_idx;
ALTER TABLE ramp.transaction_log
    ADD CONSTRAINT transaction_log_resource_id_fkey
    FOREIGN KEY (resource_id) REFERENCES ramp.catalog (resource_id) ON DELETE RESTRICT;
ALTER TABLE ramp.transaction_log DROP COLUMN IF EXISTS lifecycle;
DROP TYPE IF EXISTS ramp.offer_type;
DROP TYPE IF EXISTS ramp.transaction_lifecycle;
