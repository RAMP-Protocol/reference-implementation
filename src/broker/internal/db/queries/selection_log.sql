-- name: RecordSelection :one
INSERT INTO broker.selection_log (
    log_id, request_id, agent_id, query, candidate_offers,
    winner_offer_id, winner_exchange, rationale
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;
