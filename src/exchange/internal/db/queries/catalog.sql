-- name: ListCatalogByTenant :many
SELECT * FROM ramp.catalog WHERE tenant_id = $1 ORDER BY uri_prefix;

-- name: ListAllCatalog :many
SELECT * FROM ramp.catalog ORDER BY tenant_id, uri_prefix;

-- name: GetCatalogEntry :one
SELECT * FROM ramp.catalog WHERE resource_id = $1;

-- name: UpsertCatalogEntry :one
INSERT INTO ramp.catalog (
    resource_id, tenant_id, uri, uri_prefix, pricing, terms,
    delivery_method, metadata, resource_owner_id
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (resource_id) DO UPDATE
   SET tenant_id = EXCLUDED.tenant_id,
       uri = EXCLUDED.uri,
       uri_prefix = EXCLUDED.uri_prefix,
       pricing = EXCLUDED.pricing,
       terms = EXCLUDED.terms,
       delivery_method = EXCLUDED.delivery_method,
       metadata = EXCLUDED.metadata,
       resource_owner_id = EXCLUDED.resource_owner_id,
       updated_at = NOW()
RETURNING *;

-- name: InsertCatalogEntry :one
INSERT INTO ramp.catalog (
    resource_id, tenant_id, uri, uri_prefix, pricing, terms,
    delivery_method, metadata, resource_owner_id
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;
