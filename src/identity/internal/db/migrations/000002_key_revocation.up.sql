-- Per-subdomain key revocation state for each agent. One row per agent holds the
-- registry-owned monotonic as_of counter (the generation stand-in the consumer's
-- rollback guard compares against) and the complete set of revoked key thumbprints;
-- the served KeyRevocationList is assembled from this row.
--
-- One row per subdomain, NOT a row per thumbprint, so a revocation is a single
-- atomic upsert: the row lock serializes concurrent revokes of the same subdomain
-- and keeps as_of strictly increasing without an explicit transaction. Keyed on
-- subdomain like the rest of the identity schema; the keys themselves live in the
-- KeyStore (Vault), never here.
CREATE TABLE identity.key_revocation (
    subdomain text   PRIMARY KEY,
    as_of     bigint NOT NULL,
    revoked   text[] NOT NULL DEFAULT '{}'
);
