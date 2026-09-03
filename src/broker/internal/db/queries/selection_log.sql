-- name: RecordSelection :one
INSERT INTO broker.selection_log (
    log_id, request_id, agent_id, query, candidate_offers, rationale
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: SelectionsByRequestID :many
SELECT * FROM broker.selection_log
WHERE request_id = $1
ORDER BY created_at DESC;

-- Selections that offered one particular offer to one agent, most recent
-- first. The caller wants the newest row in a bounded window, so the window
-- bounds are parameters and the LIMIT is the caller's, not this query's.
--
-- The offer test is JSONB containment against a one-element array, which is
-- how a `[{"offer_id": ...}, ...]` array is asked "does it hold this member".
-- Equality against the whole column would require reproducing every candidate
-- the broker returned, which the caller does not know.
--
-- selection_log_agent_idx (agent_id, created_at DESC) serves the agent and
-- range predicates; the containment test filters the rows that survive them.
-- Offered-in-window is a handful of rows per agent, so no JSONB index is
-- needed to keep this cheap.
-- name: SelectionsOfferingOffer :many
SELECT * FROM broker.selection_log
WHERE agent_id = sqlc.arg(agent_id)
  AND candidate_offers @> sqlc.arg(offer_member)::jsonb
  AND created_at <= sqlc.arg(not_after)
  AND created_at >= sqlc.arg(not_before)
ORDER BY created_at DESC
LIMIT sqlc.arg(max_rows);
