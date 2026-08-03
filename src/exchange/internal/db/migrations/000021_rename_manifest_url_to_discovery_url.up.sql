-- Rename the stale agents column manifest_url -> discovery_url. The column now
-- stores the canonicalized WBA directory URL (agentreg.registry populates it via
-- rampwellknown.WBAURL), not the raw /.well-known/ramp.json manifest URL a caller
-- originally POSTed, so the name drifted from the value it holds.
--
-- RENAME COLUMN is metadata-only (no rows rewritten). The public agents/register
-- HTTP request field is discovery_url too, so wire field, DB column, and the
-- RegisterFromDirectory method share one vocabulary end to end; the registry
-- still canonicalizes the submitted URL into this column via rampwellknown.WBAURL.

ALTER TABLE ramp.agents RENAME COLUMN manifest_url TO discovery_url;
