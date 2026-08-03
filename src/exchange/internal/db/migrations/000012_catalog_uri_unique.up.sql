-- Enforce catalog URI ownership.
--
-- A catalog URI is materialized server-side as scheme://domain + path, and the
-- publisher domain pins the URI to exactly one tenant (tenants.domain is UNIQUE,
-- tenant.) The discovery trie does a global longest-prefix lookup that must
-- resolve a URI to exactly one owning row; without this constraint a SAME-tenant
-- push of the same (domain, path) under a different content_id (hence a different
-- resource_id) would INSERT a second row carrying the same URI and shadow the
-- first. UNIQUE(uri) makes a URI belong to exactly one row globally — the tighter
-- constraint that matches the global trie's read model. (tenant_id, uri) is NOT
-- used: it would permit two tenants to share a URI, which domain-derivation
-- already forbids at the source, so the column-pair would be looser than reality.
--
-- The repo's upsert conflict target stays ON CONFLICT (resource_id) so a re-push
-- of the same resource updates in place; a colliding-URI/different-resource_id
-- push is rejected per-entry by the service before the batch transaction, with
-- this constraint as the concurrency backstop.

ALTER TABLE ramp.catalog
    ADD CONSTRAINT catalog_uri_key UNIQUE (uri);
