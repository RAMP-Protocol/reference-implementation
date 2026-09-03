-- Add the per-tenant default credit granted to a newly registered agent.
--
-- default_agent_credit is the one-time credit the Register flow grants a
-- freshly registered agent, denominated in the deployment ledger currency.
-- NUMERIC(20,8) matches the ledger's asset scale of 8: any representable
-- credit is an exact integer amount of minor units, so the grant never needs
-- rounding. 0 disables the feature and is the default — an unconfigured
-- tenant keeps the strictly prepaid behavior where a new agent cannot
-- transact until an operator funds it. Server-side commercial term, never on
-- the wire.
--
-- The CHECK enforces the lower bound and excludes NaN explicitly: Postgres
-- accepts NaN into a NUMERIC column, and NaN sorts greater than every number,
-- so "NaN >= 0" alone would pass. The repo layer additionally rejects values
-- finer than 8 fraction digits, because NUMERIC(20,8) rounds an over-precise
-- value instead of rejecting it.
--
-- NOT NULL DEFAULT 0 keeps the ALTER instant (a constant default, no table
-- rewrite).

ALTER TABLE ramp.tenants
    ADD COLUMN default_agent_credit NUMERIC(20,8) NOT NULL DEFAULT 0
        CHECK (default_agent_credit >= 0 AND default_agent_credit <> 'NaN'::numeric);
