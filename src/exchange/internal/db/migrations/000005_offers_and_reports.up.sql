-- Offer negotiation + explicit reporting obligations.
--
-- The existing catalog + reporting_obligations model supports discover-and-
-- execute where every resource has an implicit per-request offer plus a
-- matching subscription-priced offer. The offer-negotiation flow adds explicit, tenant-
-- scoped offer rows so the Exchange can enumerate SPOT / SUBSCRIPTION / FREE
-- offers independently of the catalog pricing blob.
--
-- report_tokens + transaction_reports materialize the reporting obligation
-- minted by AcceptOffer. token_hash is stored (never the raw token) so a
-- leaked DB row cannot be replayed; the HMAC key lives in RAMP_REPORT_HMAC_KEY.

-- ---------------------------------------------------------------------------
-- Lifecycle of a ListOffers-issued transaction.
-- ---------------------------------------------------------------------------

CREATE TYPE ramp.transaction_lifecycle AS ENUM (
    'LISTED',
    'ACCEPTED',
    'DELIVERED',
    'REPORTED'
);

ALTER TABLE ramp.transaction_log
    ADD COLUMN lifecycle ramp.transaction_lifecycle NOT NULL DEFAULT 'ACCEPTED'; -- LISTED→ACCEPTED→DELIVERED→REPORTED progression for offer-negotiation rows

-- Relax resource_id FK so the legacy AcceptOffer path can write transaction_log rows
-- referencing ramp.offers rather than ramp.catalog. Legacy catalog-driven
-- rows keep referential integrity via service-layer assertions; the FK is
-- replaced by an index to preserve lookup performance.
ALTER TABLE ramp.transaction_log
    DROP CONSTRAINT transaction_log_resource_id_fkey;
CREATE INDEX transaction_log_resource_id_idx ON ramp.transaction_log (resource_id);

CREATE TYPE ramp.offer_type AS ENUM (
    'SPOT',
    'SUBSCRIPTION',
    'FREE'
);

-- ---------------------------------------------------------------------------
-- Offers — explicit offer rows for the offer-negotiation flow.
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- report_tokens — HMAC-hashed reporting tickets issued by AcceptOffer.
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- transaction_reports — one row per successful Report call, idempotent on
-- reporting_token_hash.
-- ---------------------------------------------------------------------------

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
