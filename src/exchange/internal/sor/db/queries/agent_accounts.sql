-- name: InsertAgentAccountIfAbsent :one
-- Inserts a new account, or does NOTHING when one already exists for the
-- subdomain (never DO UPDATE: a repeat registration must have zero side
-- effects, per ADR-021 D4). When the conflict fires, RETURNING yields zero
-- rows, so the caller sees pgx.ErrNoRows — the repo maps that to the
-- "already exists" success signal, not an error.
INSERT INTO sor.agent_accounts (
    billing_ref, subdomain, email, active,
    legal_entity, jurisdiction_country, jurisdiction_subdivision,
    address_line1, address_line2, address_city, address_region,
    address_postal_code, address_country, extra
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
)
ON CONFLICT (subdomain) DO NOTHING
RETURNING *;

-- name: GetAgentAccountBySubdomain :one
SELECT * FROM sor.agent_accounts WHERE subdomain = $1;

-- name: GetAgentAccountActive :one
SELECT active FROM sor.agent_accounts WHERE billing_ref = $1;
