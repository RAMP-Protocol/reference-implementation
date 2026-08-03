-- name: RecordSelection :one
INSERT INTO broker.selection_log (
    log_id, request_id, agent_id, query, candidate_offers, rationale
) VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: SelectionsByRequestID :many
SELECT * FROM broker.selection_log
WHERE request_id = $1
ORDER BY created_at DESC;
