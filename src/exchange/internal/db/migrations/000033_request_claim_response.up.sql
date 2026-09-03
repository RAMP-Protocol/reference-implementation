-- The finalized request-level TransactionResponse, serialized protobuf,
-- written ONCE when the batch loop completes and BEFORE the RPC returns.
--
-- transaction_log rows carry a result_payload only for SUCCESSFUL items:
-- denied items persist no row of their own, so an all-denied request left
-- zero durable rows (a resent key re-executed — and could charge once
-- conditions changed) and a mixed success/denial request left a partial set
-- (a resent key was refused instead of answered). Storing the complete
-- response on the request claim closes both: an exact retry is served this
-- payload verbatim, denials included.
--
-- Write-once: the application UPDATE is guarded on response_payload IS NULL,
-- so a finalized response is immutable. NULL means the request never
-- finalized (in flight, or crashed mid-batch) — the reader falls back to the
-- per-item replay probe. Claims created before this migration stay NULL and
-- keep the per-item replay semantics.
ALTER TABLE ramp.transaction_request_claims
    ADD COLUMN response_payload BYTEA;
