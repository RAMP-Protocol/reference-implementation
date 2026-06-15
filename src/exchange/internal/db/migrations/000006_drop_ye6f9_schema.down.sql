-- Reverse 000006_drop_ye6f9_schema.up.sql by re-creating the 000005 schema
-- additions verbatim. Order mirrors 000005_offers_and_reports.up.sql so the
-- enum types exist before the columns and tables that reference them.

CREATE TYPE ramp.transaction_lifecycle AS ENUM (
    'LISTED',
    'ACCEPTED',
    'DELIVERED',
    'REPORTED'
);

ALTER TABLE ramp.transaction_log
    ADD COLUMN lifecycle ramp.transaction_lifecycle NOT NULL DEFAULT 'ACCEPTED';

-- Re-relax the resource_id FK (replace the constraint 000006.up restored
-- with the lookup-performance index 000005 added).
ALTER TABLE ramp.transaction_log
    DROP CONSTRAINT IF EXISTS transaction_log_resource_id_fkey;
CREATE INDEX IF NOT EXISTS transaction_log_resource_id_idx
    ON ramp.transaction_log (resource_id);

CREATE TYPE ramp.offer_type AS ENUM (
    'SPOT',
    'SUBSCRIPTION',
    'FREE'
);

CREATE TABLE ramp.offers (
    offer_id          TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL REFERENCES ramp.tenants (tenant_id) ON DELETE CASCADE,
    resource_url      TEXT NOT NULL,
    type              ramp.offer_type NOT NULL,
    price_minor       BIGINT NOT NULL DEFAULT 0,
    currency          VARCHAR(3) NOT NULL DEFAULT 'USD',
    terms             TEXT NOT NULL DEFAULT '',
    publisher_slug    TEXT NOT NULL DEFAULT '',
    required_scope    TEXT NOT NULL DEFAULT '',
    valid_from        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until       TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX offers_tenant_resource_idx ON ramp.offers (tenant_id, resource_url);

CREATE TABLE ramp.report_tokens (
    token_hash        BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    tenant_id         TEXT NOT NULL REFERENCES ramp.tenants (tenant_id) ON DELETE CASCADE,
    transaction_id    TEXT NOT NULL REFERENCES ramp.transaction_log (transaction_id) ON DELETE CASCADE,
    offer_id          TEXT NOT NULL,
    required_fields   TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    deadline          TIMESTAMPTZ NOT NULL,
    report_endpoint   TEXT NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX report_tokens_txid_idx ON ramp.report_tokens (transaction_id);

CREATE TABLE ramp.transaction_reports (
    report_id             TEXT PRIMARY KEY,
    reporting_token_hash  BYTEA NOT NULL UNIQUE REFERENCES ramp.report_tokens (token_hash) ON DELETE CASCADE,
    tenant_id             TEXT NOT NULL REFERENCES ramp.tenants (tenant_id) ON DELETE CASCADE,
    transaction_id        TEXT NOT NULL REFERENCES ramp.transaction_log (transaction_id) ON DELETE CASCADE,
    bytes_served          BIGINT NOT NULL DEFAULT 0,
    completed_at          TIMESTAMPTZ NOT NULL,
    http_status           INTEGER NOT NULL DEFAULT 0,
    extras                JSONB NOT NULL DEFAULT '{}'::jsonb,
    ledger_entry_id       TEXT NOT NULL,
    received_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX transaction_reports_tx_idx ON ramp.transaction_reports (transaction_id);
