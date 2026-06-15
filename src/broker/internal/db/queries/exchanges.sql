-- name: ListActiveExchanges :many
SELECT * FROM broker.exchanges
 WHERE healthy = TRUE AND trust_level != 'BLOCKED'
 ORDER BY priority DESC, trust_level;

-- name: UpsertExchange :one
INSERT INTO broker.exchanges (
    exchange_id, domain, endpoint, trust_level, supported_profiles, priority
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (exchange_id) DO UPDATE
    SET domain = EXCLUDED.domain,
        endpoint = EXCLUDED.endpoint,
        trust_level = EXCLUDED.trust_level,
        supported_profiles = EXCLUDED.supported_profiles,
        priority = EXCLUDED.priority,
        updated_at = NOW()
RETURNING *;
