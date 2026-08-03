-- Reverse of 000024_transaction_evidence.up.sql.
-- DROP TABLE is DDL, so the append-once row/truncate triggers do not block it.

DROP TRIGGER IF EXISTS trg_transaction_evidence_no_truncate ON ramp.transaction_evidence;
DROP TRIGGER IF EXISTS trg_transaction_evidence_no_row_mutation ON ramp.transaction_evidence;
DROP TABLE IF EXISTS ramp.transaction_evidence;
DROP FUNCTION IF EXISTS ramp.prevent_evidence_mutation();
