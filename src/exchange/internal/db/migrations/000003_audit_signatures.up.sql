-- Audit-grade signature persistence on transaction_log.
--
-- Pre-this migration the row carries only `signed_url_hash` (SHA-256 of the
-- full signed URL). That is sufficient to prove "the URL the agent fetched
-- matches this row" by re-hashing, but it does not let an operator show
-- side-by-side the actual signature bytes the agent presented (offer
-- signature) or the URL signature embedded in the issued URL.
--
-- The `make ledger` demo command needs both bytes verbatim so it can
-- (a) display them next to the corresponding access-log entry and
-- (b) re-verify them against the published Exchange public keys, asserting
-- "the agent presented THIS sig, the Exchange minted THIS sig, and both
-- still verify under THIS public key."
--
-- Both columns are nullable and default NULL so this migration is safe to
-- run before the writers (Exchange persistTransaction) are taught to
-- populate them. Existing rows stay valid; new rows after the writer
-- update will carry the new evidence.

ALTER TABLE ramp.transaction_log
    ADD COLUMN offer_signature      TEXT,
    ADD COLUMN signed_url_signature TEXT;

COMMENT ON COLUMN ramp.transaction_log.offer_signature IS
    'Base64url Ed25519 signature the agent presented in TransactionRequest.offer_signature, retained verbatim for /admin/ledger forensics.';
COMMENT ON COLUMN ramp.transaction_log.signed_url_signature IS
    'Signature substring extracted from the issued signed URL (CloudFront RSA Signature= or Ed25519 sig= query parameter), retained verbatim for /admin/ledger forensics.';
