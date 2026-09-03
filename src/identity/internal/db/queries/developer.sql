-- name: GetDeveloperBySubject :one
SELECT * FROM identity.developer_account
WHERE oidc_issuer = $1 AND oidc_subject = $2;

-- name: GetDeveloperBySubdomain :one
SELECT * FROM identity.developer_account
WHERE subdomain = $1;

-- name: ReserveDeveloper :one
INSERT INTO identity.developer_account (oidc_issuer, oidc_subject, email, subdomain)
VALUES ($1, $2, $3, $4)
RETURNING *;
