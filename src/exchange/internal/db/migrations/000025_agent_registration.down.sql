-- Reverse of 000025_agent_registration.up.sql.

ALTER TABLE ramp.agents
    DROP COLUMN billing_ref;

ALTER TABLE ramp.tenants
    DROP COLUMN activate_new_agents_by_default;
