-- Writes the note and, in the same statement, drops this agent's oldest notes
-- past the cap.
--
-- The exchange is a value an authenticated agent chooses per call, and with no
-- allowlist configured the key space is the whole DNS namespace. So the note set
-- is somewhere a caller can make this table grow, and it is bounded the same way
-- every caller-influenced store in this service is: keep the most recent, drop
-- the rest.
--
-- One statement, so there is no read-then-write to make atomic. The two halves
-- need care about visibility: a data-modifying CTE runs against the snapshot
-- taken at the start of the statement, so the DELETE cannot see the row the
-- INSERT just wrote. That is why `keep` selects the cap MINUS ONE most recent
-- OTHER notes and the DELETE excludes this exchange outright — the row being
-- written is kept by construction rather than by being found.
--
-- name: RecordExchangeRegistration :exec
WITH upserted AS (
    INSERT INTO identity.exchange_registration (subdomain, exchange, registered_at)
    VALUES (@subdomain, @exchange, @registered_at)
    ON CONFLICT (subdomain, exchange) DO UPDATE SET registered_at = EXCLUDED.registered_at
), keep AS (
    SELECT exchange FROM identity.exchange_registration
    WHERE subdomain = @subdomain AND exchange <> @exchange
    ORDER BY registered_at DESC, exchange
    LIMIT @keep_others::int
)
DELETE FROM identity.exchange_registration AS note
WHERE note.subdomain = @subdomain
  AND note.exchange <> @exchange
  AND note.exchange NOT IN (SELECT keep.exchange FROM keep);

-- name: ForgetExchangeRegistration :exec
DELETE FROM identity.exchange_registration
WHERE subdomain = $1 AND exchange = $2;

-- Ordered by domain because that is how the list is presented, and capped by the
-- same number the write path enforces.
--
-- The cap is a backstop rather than the bound: RecordExchangeRegistration keeps
-- the set at or under it, so this LIMIT never truncates a set that path produced.
-- It is here so the read cannot become unbounded if rows ever arrive by another
-- route.
--
-- name: ListExchangeRegistrations :many
SELECT exchange, registered_at FROM identity.exchange_registration
WHERE subdomain = @subdomain
ORDER BY exchange
LIMIT @max_notes::int;
