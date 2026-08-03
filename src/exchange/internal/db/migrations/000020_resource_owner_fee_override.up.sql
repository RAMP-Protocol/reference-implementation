-- Per-(tenant, resource_owner) commission override.
--
-- The tenant-level ramp.tenants.fee_rate_bps is the default; a row here overrides
-- it for one resource owner under one tenant, so an aggregator tenant can charge a
-- different commission per owner it represents. resource_owner_id is the owner-
-- attested payee key (also carried on ramp.catalog), shared across an owner's many
-- domains and deliberately NOT its own table, so it is not foreign-keyed here. The
-- basis-point semantics and bound match the tenant default. The effective rate is
-- resolved at Authorize and frozen on the billing hold; this table is the source of
-- the override, never read on the wire.

CREATE TABLE ramp.tenant_resource_owner_fee (
    tenant_id         TEXT    NOT NULL REFERENCES ramp.tenants (tenant_id) ON DELETE CASCADE,
    resource_owner_id TEXT    NOT NULL,  -- owner-attested payee key; not a tenant, no FK
    fee_rate_bps      INTEGER NOT NULL CHECK (fee_rate_bps >= 0 AND fee_rate_bps < 10000),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, resource_owner_id)
);
