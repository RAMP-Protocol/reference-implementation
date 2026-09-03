-- The OAuth authorization-server state the Identity Service keeps so it can front
-- an MCP client's sign-in flow. The service is its own authorization
-- server: it federates authentication to Zitadel upstream but issues its own
-- authorization codes and tokens downstream, which is what lets it hold the flow
-- open across a browser hop and ask the developer to approve the requesting client
-- before releasing a code. Two pieces of that state are durable.

-- A downstream client registered via RFC 7591 Dynamic Client Registration. MCP
-- clients (e.g. Claude Code) self-register at runtime rather than being created by
-- hand, so the client_id is minted here and its redirect-URI allowlist is stored:
-- /authorize accepts a redirect_uri only if it appears in this list, which is what
-- stops an open redirect. These are public clients (PKCE, no secret).
CREATE TABLE identity.oauth_client (
    client_id     text        NOT NULL,
    redirect_uris text[]      NOT NULL DEFAULT '{}',
    client_name   text        NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oauth_client_pkey PRIMARY KEY (client_id)
);

-- A one-time authorization code, stored as the SHA-256 of the opaque code so a
-- database read cannot replay it. The code is bound to the client, the exact
-- redirect_uri, the downstream client's PKCE challenge, and the developer subject
-- (the minted subdomain) it authenticates — /token re-checks all four before
-- issuing an access token. consumed makes redemption single-use; expires_at bounds
-- the code's life (checked by the caller against its clock, so a code minted under
-- a test clock expires on that clock, not the database wall clock).
CREATE TABLE identity.oauth_authz_code (
    code_hash      text        NOT NULL,
    client_id      text        NOT NULL,
    redirect_uri   text        NOT NULL,
    pkce_challenge text        NOT NULL,
    subject        text        NOT NULL,
    expires_at     timestamptz NOT NULL,
    consumed       boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oauth_authz_code_pkey PRIMARY KEY (code_hash)
);
