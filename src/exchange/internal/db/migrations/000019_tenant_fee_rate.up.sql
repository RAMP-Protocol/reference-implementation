-- Add the platform commission rate to the tenant record.
--
-- fee_rate_bps is the tenant-level DEFAULT commission, in integer basis points
-- (1 bp = 0.01%); a per-(tenant, resource_owner) override may supersede it (see
-- the tenant_resource_owner_fee table). It is a server-side commercial term,
-- never on the wire. The settlement split charges fee = floor(gross * bps /
-- 10000); the bound 0 <= bps < 10000 keeps the fee strictly under 100% and
-- integer basis points avoid float drift when aggregating many charges.
-- fee_rate_notes is free-form operator commentary.
--
-- NOT NULL DEFAULT 0 keeps the ALTER instant (a constant default, no table
-- rewrite): an unconfigured tenant takes nothing until a rate is set.

ALTER TABLE ramp.tenants
    ADD COLUMN fee_rate_bps   INTEGER NOT NULL DEFAULT 0
        CHECK (fee_rate_bps >= 0 AND fee_rate_bps < 10000), -- basis points, < 100%
    ADD COLUMN fee_rate_notes TEXT;                          -- operator commentary, nullable
