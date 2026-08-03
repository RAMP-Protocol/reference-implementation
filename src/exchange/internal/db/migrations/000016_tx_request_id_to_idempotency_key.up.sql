-- Rename the stale transaction_log column tx_request_id -> idempotency_key so
-- the persisted dedup/double-charge backstop names the ONE concept by its wire
-- name (TransactionRequest.idempotency_key). The column was originally named
-- after the OLD proto field TransactionRequest.id, which the protocol
-- normalization renamed to idempotency_key; the column name never followed.
--
-- RENAME COLUMN is metadata-only (no rows rewritten) and auto-carries the
-- inline UNIQUE constraint and its indexes — nothing in Go keys off the
-- constraint name, so the constraint is intentionally NOT renamed (keeps the
-- down migration a trivial single inverse). The UNIQUE double-charge backstop
-- is unchanged, only the column it sits on is renamed.

ALTER TABLE ramp.transaction_log RENAME COLUMN tx_request_id TO idempotency_key;
