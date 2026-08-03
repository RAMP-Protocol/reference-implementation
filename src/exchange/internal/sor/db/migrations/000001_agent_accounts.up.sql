-- System of Record (SoR) schema. Lives in its own logical database
-- (EXCHANGE_SOR_DSN) with its own migration sequence and tracking table
-- (schema_migrations_sor); the schema namespace keeps the SoR's tables
-- self-identifying wherever the operator points that DSN.

CREATE SCHEMA IF NOT EXISTS sor;

-- agent_accounts is the SoR's account book for registered agents.
--
-- No tenant_id: this is a per-exchange global identity table, the same
-- category as ramp.agents. An account belongs to the agent (keyed on its
-- durable Web Bot Auth subdomain identity), not to any publisher tenant, so
-- Architecture Rule 4's "filter by tenant_id" does not apply here — there is
-- no tenant axis to filter on.
--
-- Nullability: only structural columns are NOT NULL — billing_ref (PK),
-- subdomain (identity backstop; the caller derives it from the verified
-- signature, never the payload), active (a boolean must be decided), and
-- extra (defaulted). Every licensing-deal column stays nullable: the
-- registration form — not the Exchange — is the mandatory-fields gate, and
-- Register is a public RPC that self-hosted agents call directly with
-- arbitrary registration_data. Completeness is enforced operationally via
-- active (the operator does not activate an incomplete account); a NULL
-- column is the "registration incomplete" signal. No format CHECKs either —
-- the SoR is a dumb store.
CREATE TABLE sor.agent_accounts (
    -- Random UUID minted by the Exchange and passed in (ADR-021 D1/D2).
    billing_ref              TEXT PRIMARY KEY,
    -- Durable identity and idempotency anchor; UNIQUE makes repeat
    -- registration a detectable conflict rather than a duplicate account.
    subdomain                TEXT NOT NULL UNIQUE,
    email                    TEXT,
    -- SoR-owned status; the Exchange only ever reads it (pull via IsActive).
    active                   BOOLEAN NOT NULL,
    -- Licensing-deal profile (all optional; see nullability note above).
    legal_entity             TEXT,
    jurisdiction_country     TEXT,
    jurisdiction_subdivision TEXT,
    address_line1            TEXT,
    address_line2            TEXT,
    address_city             TEXT,
    address_region           TEXT,
    address_postal_code      TEXT,
    address_country          TEXT,
    -- Registration keys not (yet) promoted to a typed column. Lets storage be
    -- built ahead of the registration_data field set being fixed.
    extra                    JSONB NOT NULL DEFAULT '{}'
);
