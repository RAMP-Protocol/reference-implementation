-- The developer account behind an agent identity: the durable link between the
-- OIDC subject a developer signs in as and the agent subdomain the registry mints
-- for them, plus the three licensing-deal fields a licensing agreement needs and
-- the WBA card cannot carry (legal entity, address, jurisdiction). Written by
-- developer sign-up; read back by subdomain when the agent later
-- Registers so those fields ride along as registration_data.
--
-- Keyed on (oidc_issuer, oidc_subject): a `sub` is unique only within its issuer,
-- so the pair is the identity, not the subject alone. subdomain carries its own
-- UNIQUE so the slug the registry mints cannot be handed to two developers — that
-- constraint, not an enumeration, is the collision backstop the sign-up retries
-- against.
--
-- The three licensing fields live ONLY here, never on identity.agent_card: the
-- card is world-readable on the agent's subdomain, and legal entity / address /
-- jurisdiction are private licensing data. registration_complete is the gate the
-- form enforces — false until all three are present, which is the "sign-up started
-- but the mandatory form is unfilled" state.
CREATE TABLE identity.developer_account (
    oidc_issuer           text        NOT NULL,
    oidc_subject          text        NOT NULL,
    email                 text        NOT NULL DEFAULT '',
    subdomain             text        NOT NULL,
    legal_entity          text        NOT NULL DEFAULT '',
    address               text        NOT NULL DEFAULT '',
    jurisdiction_country  text        NOT NULL DEFAULT '',
    registration_complete boolean     NOT NULL DEFAULT false,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT developer_account_pkey PRIMARY KEY (oidc_issuer, oidc_subject),
    CONSTRAINT developer_account_subdomain_unique UNIQUE (subdomain)
);
