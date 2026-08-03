-- name: GetAgent :one
SELECT * FROM ramp.agents WHERE agent_id = $1;

-- name: UpsertAgent :one
INSERT INTO ramp.agents (agent_id, public_key, discovery_url, requester_type)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_id) DO UPDATE
    SET public_key = EXCLUDED.public_key,
        discovery_url = EXCLUDED.discovery_url,
        requester_type = EXCLUDED.requester_type
RETURNING *;

-- name: SetAgentBillingRef :one
-- Stores the billing account id for an agent, first write wins. The
-- billing_ref IS NULL guard makes a repeat call a no-op (zero rows →
-- pgx.ErrNoRows), so a stored ref is never overwritten (ADR-021 D4). The
-- column is deliberately absent from UpsertAgent's update list: a key
-- rotation re-upsert must leave billing_ref intact (ADR-021 D3).
UPDATE ramp.agents
   SET billing_ref = $2
 WHERE agent_id = $1
   AND billing_ref IS NULL
RETURNING *;
