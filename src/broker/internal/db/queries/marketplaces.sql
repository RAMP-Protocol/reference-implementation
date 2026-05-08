-- name: ListActiveMarketplaces :many
SELECT * FROM broker.marketplaces
 WHERE healthy = TRUE AND trust_level != 'BLOCKED'
 ORDER BY priority DESC, trust_level;

-- name: UpsertMarketplace :one
INSERT INTO broker.marketplaces (
    marketplace_id, domain, endpoint, trust_level, supported_profiles, priority
) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (marketplace_id) DO UPDATE
    SET domain = EXCLUDED.domain,
        endpoint = EXCLUDED.endpoint,
        trust_level = EXCLUDED.trust_level,
        supported_profiles = EXCLUDED.supported_profiles,
        priority = EXCLUDED.priority,
        updated_at = NOW()
RETURNING *;
