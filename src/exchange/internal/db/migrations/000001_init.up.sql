-- Exchange schema. All tables live under "ramp".
--
-- Conventions:
--   * Enum types are native PostgreSQL ENUMs (sqlc generates typed Go strings).
--   * Foreign keys are fully-qualified with schema name (CLAUDE.md rule).
--   * Timestamps use TIMESTAMPTZ.
--   * IDs are TEXT (externally generated, e.g. UUIDv7 / ULID) for portability.

CREATE SCHEMA IF NOT EXISTS ramp;

-- ---------------------------------------------------------------------------
-- Enums (values mirror proto enums, minus the *_UNSPECIFIED sentinel).
-- ---------------------------------------------------------------------------

CREATE TYPE ramp.obligation_state AS ENUM (
    'PENDING',
    'RECEIVED',
    'ACCEPTED',
    'CHALLENGED',
    'EXPIRED'
);

CREATE TYPE ramp.denial_reason AS ENUM (
    'INVALID_LICENSE',
    'EXPIRED_LICENSE',
    'INSUFFICIENT_BALANCE',
    'RATE_LIMITED',
    'CONTENT_UNAVAILABLE',
    'FUNCTION_PROHIBITED',
    'GEO_RESTRICTED',
    'REPORTING_OVERDUE',
    'OFFER_EXPIRED',
    'SIGNATURE_INVALID',
    'QUOTA_EXCEEDED',
    'DELEGATION_EXPIRED',
    'SCOPE_INSUFFICIENT'
);

CREATE TYPE ramp.delivery_method AS ENUM (
    'DIRECT',
    'INSTRUCTIONS',
    'STREAMING'
);

CREATE TYPE ramp.requester_type AS ENUM (
    'AGENT',
    'HUMAN_TOOL',
    'SERVICE',
    'DELEGATED',
    'RESEARCH'
);

-- ---------------------------------------------------------------------------
-- Tables (in FK dependency order).
-- ---------------------------------------------------------------------------

-- Tenants own publishers and their signing material.
CREATE TABLE ramp.tenants (
    tenant_id            TEXT PRIMARY KEY,
    domain               TEXT NOT NULL UNIQUE,
    hmac_secret_ref      TEXT NOT NULL,          -- pointer to secret store; never the secret itself
    ed25519_key_ref      TEXT NOT NULL,          -- pointer to signing key
    reporting_policy     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Agents (requesters) registered with this Exchange.
CREATE TABLE ramp.agents (
    agent_id             TEXT PRIMARY KEY,
    public_key           BYTEA NOT NULL,
    manifest_url         TEXT,
    requester_type       ramp.requester_type NOT NULL DEFAULT 'AGENT',
    registered_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Catalog: the tenant-scoped resource inventory. Loaded into an in-process
-- radix trie at startup; mutated via CatalogService.PushResources.
CREATE TABLE ramp.catalog (
    resource_id          TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL REFERENCES ramp.tenants (tenant_id) ON DELETE CASCADE,
    uri                  TEXT NOT NULL,
    uri_prefix           TEXT NOT NULL,          -- normalized prefix for radix lookup
    pricing              JSONB NOT NULL,         -- PricingModel + unit_cost + currency
    licensing_rules      JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_method      ramp.delivery_method NOT NULL DEFAULT 'DIRECT',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX catalog_tenant_prefix_idx ON ramp.catalog (tenant_id, uri_prefix);

-- Transaction log. Append-only. signed_url_hash is NOT NULL and length-checked
-- so a row cannot exist without a fully formed signature. The write-before-sign
-- ordering (the row must commit before the response is returned to the caller)
-- is enforced in the ExecuteTransaction handler (step 3).
--
-- tx_request_id UNIQUE makes TransactionRequest.id a real idempotency key.
CREATE TABLE ramp.transaction_log (
    transaction_id       TEXT PRIMARY KEY,
    tx_request_id        TEXT NOT NULL UNIQUE,
    tenant_id            TEXT NOT NULL REFERENCES ramp.tenants (tenant_id) ON DELETE RESTRICT,
    agent_id             TEXT NOT NULL REFERENCES ramp.agents (agent_id) ON DELETE RESTRICT,
    resource_id          TEXT NOT NULL REFERENCES ramp.catalog (resource_id) ON DELETE RESTRICT,
    offer_id             TEXT NOT NULL,
    agent_identity_hash  BYTEA NOT NULL,
    signed_url_hash      BYTEA NOT NULL CHECK (octet_length(signed_url_hash) = 32),
    expiry               TIMESTAMPTZ NOT NULL,
    billing_id           TEXT,
    unit_cost            NUMERIC(20, 8) NOT NULL,
    currency             TEXT NOT NULL,
    consumed_unit        TEXT,                   -- CoMP metering unit, populated on report
    denial_reason        ramp.denial_reason,     -- non-null only if transaction denied
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX transaction_log_agent_idx ON ramp.transaction_log (agent_id, created_at DESC);
CREATE INDEX transaction_log_tenant_idx ON ramp.transaction_log (tenant_id, created_at DESC);

-- Reporting obligations track usage reports expected from agents.
CREATE TABLE ramp.reporting_obligations (
    obligation_id        TEXT PRIMARY KEY,
    transaction_id       TEXT NOT NULL REFERENCES ramp.transaction_log (transaction_id) ON DELETE CASCADE,
    state                ramp.obligation_state NOT NULL DEFAULT 'PENDING',
    window_seconds       INTEGER,                -- reporting window from proto
    deadline             TIMESTAMPTZ NOT NULL,
    consumed_quantity    NUMERIC(20, 8),
    received_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX reporting_obligations_state_deadline_idx
    ON ramp.reporting_obligations (state, deadline);
