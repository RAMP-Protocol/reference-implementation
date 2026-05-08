-- name: ListCatalogByTenant :many
SELECT * FROM ramp.catalog WHERE tenant_id = $1 ORDER BY uri_prefix;

-- name: ListAllCatalog :many
SELECT * FROM ramp.catalog ORDER BY tenant_id, uri_prefix;

-- name: GetCatalogEntry :one
SELECT * FROM ramp.catalog WHERE resource_id = $1;

-- name: UpsertCatalogEntry :one
INSERT INTO ramp.catalog (
    resource_id, tenant_id, uri, uri_prefix, pricing, licensing_rules, delivery_method
) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (resource_id) DO UPDATE
   SET tenant_id = EXCLUDED.tenant_id,
       uri = EXCLUDED.uri,
       uri_prefix = EXCLUDED.uri_prefix,
       pricing = EXCLUDED.pricing,
       licensing_rules = EXCLUDED.licensing_rules,
       delivery_method = EXCLUDED.delivery_method,
       updated_at = NOW()
RETURNING *;

-- name: InsertCatalogEntry :one
INSERT INTO ramp.catalog (resource_id, tenant_id, uri, uri_prefix, pricing, licensing_rules, delivery_method)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;
