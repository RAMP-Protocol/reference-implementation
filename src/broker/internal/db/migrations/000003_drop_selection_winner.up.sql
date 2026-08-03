-- Drop the broker selection_log "winner" columns. They are a vestige of the
-- earlier broker-authored model, when the broker minted the transaction and
-- therefore WAS the decider. Under the current model the broker only discovers + ranks +
-- relays; the AGENT selects at execute, and that decision is audited
-- authoritatively by the exchange's ramp.transaction_log.offer_id. Recording a
-- "winner" here conflated RANKING (the broker's recommendation) with SELECTION
-- (the agent's decision) and was the source of the global-vs-first-group
-- offer/exchange disagreement. The broker keeps recording what it actually did:
-- the request, the discovered+ranked candidate_offers set, and the rationale.

ALTER TABLE broker.selection_log DROP COLUMN winner_offer_id;
ALTER TABLE broker.selection_log DROP COLUMN winner_exchange;
