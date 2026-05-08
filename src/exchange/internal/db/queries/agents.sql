-- name: GetAgent :one
SELECT * FROM ramp.agents WHERE agent_id = $1;

-- name: UpsertAgent :one
INSERT INTO ramp.agents (agent_id, public_key, manifest_url, requester_type)
VALUES ($1, $2, $3, $4)
ON CONFLICT (agent_id) DO UPDATE
    SET public_key = EXCLUDED.public_key,
        manifest_url = EXCLUDED.manifest_url,
        requester_type = EXCLUDED.requester_type
RETURNING *;
