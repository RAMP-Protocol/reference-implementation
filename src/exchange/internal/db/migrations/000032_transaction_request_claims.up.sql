-- Request-level idempotency claims for ExecuteTransaction.
--
-- transaction_log's UNIQUE idempotency_key holds the DERIVED per-item key
-- (request idempotency_key + ':' + offer_id). offer_id is a random per-offer
-- UUID, so a caller that reuses one request key with a NEWLY DISCOVERED offer
-- for the same resource produces derived keys that miss every existing row —
-- nothing at the persistence layer ties the second request to the first, and
-- billing and persistence would run again. This table is that tie: one row per
-- (authenticated agent, request idempotency_key), claimed before any item
-- bills or persists. An exact retry (same items_digest) replays the original
-- result off transaction_log; reuse of the key with a different item set is
-- refused before side effects.
--
-- agent_id is the caller identity resolved from the wire requester.id AND
-- authenticated before this row is written: admission verifies possession of
-- that identity's registered key (a body offer-acceptance signature) before
-- any claim insert, so a caller cannot reserve a key under an identity it does
-- not hold. The protocol scopes idempotency_key to the caller, so two
-- different agents may use the same key value independently — hence the
-- composite primary key. That independence holds for each agent's OWN offers.
-- An agent presenting ANOTHER agent's exact (key, offer) pair still lands on
-- that agent's globally-keyed transaction_log rows and is refused by the
-- replay ownership gate — an intentional v1 limitation (chosen on cost/benefit
-- over caller-scoping the item rows), not the only secure design.
CREATE TABLE ramp.transaction_request_claims (
    agent_id        TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    -- SHA-256 over the request's offer_ids in request order: the exact-retry
    -- vs changed-item-set discriminator.
    items_digest    BYTEA NOT NULL CHECK (octet_length(items_digest) = 32),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, idempotency_key)
);
