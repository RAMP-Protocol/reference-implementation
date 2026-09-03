-- The developer account behind an agent identity: the durable link between the
-- OIDC subject a developer signs in as and the agent subdomain the registry mints
-- for them. Written by developer sign-up, and read by sign-up, which resolves a
-- returning developer to the account already provisioned for them.
--
-- Keyed on (oidc_issuer, oidc_subject): a `sub` is unique only within its issuer,
-- so the pair is the identity, not the subject alone. subdomain carries its own
-- UNIQUE so the slug the registry mints cannot be handed to two developers — that
-- constraint, not an enumeration, is the collision backstop the sign-up retries
-- against.
--
-- Five of the columns this statement also created are dropped by migration 000006,
-- which says why. Four of them — legal_entity, address, jurisdiction_country and
-- registration_complete — held the operator business data the sign-up form
-- collected, and this service stopped collecting it. The fifth is updated_at: the
-- form's UPDATE was its only writer, so once the form went the column could never
-- move again.
--
-- All five are left in the statement below because a migration that has been
-- applied is a record of what ran, not a description of the table as it stands now.
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
