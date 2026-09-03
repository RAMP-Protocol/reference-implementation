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
-- Stores the billing account id for an agent, plus the digest of the licensing
-- terms the registration accepted, first write wins. The billing_ref IS NULL
-- guard makes a repeat call a no-op (zero rows → pgx.ErrNoRows), so a stored ref
-- is never overwritten (ADR-021 D4).
--
-- Both columns are written by this ONE guarded statement, so first-write-wins
-- covers them together and the account can never end up carrying a billing_ref
-- from one registration and an accepted digest from another. The digest is NULL
-- when the Exchange published none at the time.
--
-- Neither column appears in UpsertAgent's update list: a key rotation re-upsert
-- must leave both intact (ADR-021 D3).
UPDATE ramp.agents
   SET billing_ref = $2,
       accepted_terms_digest = $3
 WHERE agent_id = $1
   AND billing_ref IS NULL
RETURNING *;
