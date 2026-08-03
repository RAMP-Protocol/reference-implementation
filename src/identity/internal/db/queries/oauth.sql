-- name: RegisterOAuthClient :one
INSERT INTO identity.oauth_client (client_id, redirect_uris, client_name)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetOAuthClient :one
SELECT * FROM identity.oauth_client
WHERE client_id = $1;

-- name: IssueAuthzCode :one
INSERT INTO identity.oauth_authz_code (
    code_hash, client_id, redirect_uri, pkce_challenge, subject, expires_at
)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetAuthzCode :one
-- Peek at a code without consuming it, so /token can validate every binding
-- (expiry, client_id, redirect_uri, PKCE) BEFORE it burns the code. A row is
-- returned whether or not it is already consumed; an unknown code yields
-- pgx.ErrNoRows. The atomic burn is ConsumeAuthzCode, run only once validation
-- passes — so a stolen code presented with a wrong verifier cannot spend the
-- legitimate client's code.
SELECT * FROM identity.oauth_authz_code
WHERE code_hash = $1;

-- name: ConsumeAuthzCode :one
-- Single-use redemption: flips consumed atomically and returns the row only on the
-- first redemption. A second attempt matches no row (NOT consumed is false) and
-- yields pgx.ErrNoRows. Expiry is returned, not enforced here, so the caller checks
-- it against the same clock that minted expires_at.
UPDATE identity.oauth_authz_code
SET consumed = true
WHERE code_hash = $1 AND NOT consumed
RETURNING *;
