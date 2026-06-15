-- Mirror of 000008.up.sql in reverse order: drop the index, the obligation
-- columns, the tenant column, then the enum type.
--
-- NOTE: PostgreSQL has no ALTER TYPE … DROP VALUE; the BROKER label added to
-- ramp.requester_type by the up migration cannot be removed by this down
-- without rebuilding the type and rewriting every dependent column. Since
-- the value is additive and harmless (no rows reference it unless the
-- application chooses to), we deliberately leave it in place on rollback.

DROP INDEX IF EXISTS ramp.reporting_obligations_source_report_idx;

ALTER TABLE ramp.reporting_obligations
    DROP COLUMN IF EXISTS required_fields,
    DROP COLUMN IF EXISTS estimated_quantity,
    DROP COLUMN IF EXISTS quantity_tolerance,
    DROP COLUMN IF EXISTS validation_outcome,
    DROP COLUMN IF EXISTS validated_at,
    DROP COLUMN IF EXISTS source_report_id,
    DROP COLUMN IF EXISTS issued_report_id;

ALTER TABLE ramp.tenants
    DROP COLUMN IF EXISTS allow_broker_relay;

DROP TYPE IF EXISTS ramp.validation_outcome;
