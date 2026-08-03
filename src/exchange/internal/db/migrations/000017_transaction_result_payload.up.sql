-- Persist the full per-item ExecuteTransaction result so a replayed
-- idempotency_key can return the ORIGINAL TransactionResponse verbatim
-- (ramp.proto: "a replay returns the original result rather than re-executing")
-- instead of erroring with AlreadyExists.
--
-- result_payload stores the serialized rampv1.TransactionResultItem built for the
-- response (full fidelity — retrieval_endpoint, reporting_obligation,
-- delivery_method, cost, expiry — not all of which are columns). It is written on
-- the SAME INSERT as the rest of the row, inside the existing per-item
-- transaction, so a committed transaction_log row always carries its result for
-- rows created after this migration. Nullable so pre-migration (legacy) rows are
-- tolerated; tenant isolation is inherited from the row (already tenant-scoped).

ALTER TABLE ramp.transaction_log ADD COLUMN result_payload BYTEA;
