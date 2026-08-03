-- name: GetCardBySubdomain :one
SELECT subdomain, client_name, client_uri, contacts, purpose, created_at, updated_at
FROM identity.agent_card
WHERE subdomain = $1;

-- name: UpsertCard :one
INSERT INTO identity.agent_card (subdomain, client_name, client_uri, contacts, purpose)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (subdomain) DO UPDATE SET
    client_name = EXCLUDED.client_name,
    client_uri  = EXCLUDED.client_uri,
    contacts    = EXCLUDED.contacts,
    purpose     = EXCLUDED.purpose,
    updated_at  = now()
RETURNING subdomain, client_name, client_uri, contacts, purpose, created_at, updated_at;
