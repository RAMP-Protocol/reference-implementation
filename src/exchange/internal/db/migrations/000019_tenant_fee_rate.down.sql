-- Reverse of 000019_tenant_fee_rate.up.sql.

ALTER TABLE ramp.tenants
    DROP COLUMN fee_rate_bps,
    DROP COLUMN fee_rate_notes;
