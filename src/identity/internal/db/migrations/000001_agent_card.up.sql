-- The Identity Service shares a database with the other services (each keeps its
-- own migrations table), so its objects live in a named schema rather than public,
-- matching exchange (ramp), broker (broker), and sor (sor).
CREATE SCHEMA IF NOT EXISTS identity;

-- The Signature Agent Card metadata for each agent, keyed on the agent's durable
-- WBA identity (its subdomain). Written by developer sign-up, read by
-- the card-serving handler. Public data only: private keys live in the KeyStore
-- (Vault), never here.
CREATE TABLE identity.agent_card (
    subdomain   text PRIMARY KEY,
    client_name text        NOT NULL,
    client_uri  text        NOT NULL,
    contacts    text[]      NOT NULL DEFAULT '{}',
    purpose     text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
