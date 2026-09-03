-- Reverse of 000026_tenant_default_credit.up.sql.

ALTER TABLE ramp.tenants
    DROP COLUMN default_agent_credit;
