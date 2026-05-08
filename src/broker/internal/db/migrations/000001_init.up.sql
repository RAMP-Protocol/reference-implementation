-- Broker schema. All tables live under "broker".

CREATE SCHEMA IF NOT EXISTS broker;

CREATE TYPE broker.trust_level AS ENUM (
    'DISCOVERED',
    'VERIFIED',
    'PREFERRED',
    'BLOCKED'
);

-- Marketplaces the Broker knows about. Seeded from YAML/env at startup,
-- refreshed via admin endpoints or health probes.
CREATE TABLE broker.marketplaces (
    marketplace_id       TEXT PRIMARY KEY,
    domain               TEXT NOT NULL UNIQUE,
    endpoint             TEXT NOT NULL,
    trust_level          broker.trust_level NOT NULL DEFAULT 'DISCOVERED',
    healthy              BOOLEAN NOT NULL DEFAULT TRUE,
    supported_profiles   JSONB NOT NULL DEFAULT '[]'::jsonb,
    priority             INTEGER NOT NULL DEFAULT 0,
    last_health_check    TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX marketplaces_priority_idx ON broker.marketplaces (priority DESC, trust_level);

-- Selection audit log. Append-only.
CREATE TABLE broker.selection_log (
    log_id               TEXT PRIMARY KEY,
    request_id           TEXT NOT NULL,
    agent_id             TEXT NOT NULL,
    query                TEXT NOT NULL,
    candidate_offers     JSONB NOT NULL,
    winner_offer_id      TEXT,
    winner_marketplace   TEXT,
    rationale            JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX selection_log_request_idx ON broker.selection_log (request_id, created_at DESC);
CREATE INDEX selection_log_agent_idx ON broker.selection_log (agent_id, created_at DESC);
