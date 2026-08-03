-- Agent registration columns for the Register RPC.
--
-- billing_ref is the Exchange-generated identifier that keys the agent's
-- account in the billing system-of-record. Nullable with no default: NULL
-- means "not registered for paid content yet" (ADR-021 D3). It is written
-- once by the guarded SetAgentBillingRef and never overwritten — UpsertAgent
-- deliberately does not touch it, so key rotation re-upserts leave it intact.
ALTER TABLE ramp.agents
    ADD COLUMN billing_ref TEXT;

-- activate_new_agents_by_default is the per-tenant policy for whether a newly
-- registered agent starts active in the system-of-record. Constant default,
-- so the ALTER is instant (no table rewrite); "on" by default.
ALTER TABLE ramp.tenants
    ADD COLUMN activate_new_agents_by_default BOOLEAN NOT NULL DEFAULT TRUE;
