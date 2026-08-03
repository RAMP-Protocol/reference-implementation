-- Reverse of 000015_tx_request_id_to_idempotency_key.up.sql.

ALTER TABLE ramp.transaction_log RENAME COLUMN idempotency_key TO tx_request_id;
