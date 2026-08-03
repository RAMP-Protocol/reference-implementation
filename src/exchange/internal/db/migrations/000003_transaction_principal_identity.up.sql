-- Add principal-identity columns to transaction_log so ExecuteTransaction can
-- persist the identity facts extracted from a verified Biscuit delegation.
-- Both columns are NULLable: wholesale requests (no Delegation) leave them
-- empty; end-user-delegated requests fill them in from delegation.Verified.

ALTER TABLE ramp.transaction_log
    ADD COLUMN identity_source TEXT, -- verified Biscuit principal source (e.g. "google", "github"); NULL for non-delegated requests
    ADD COLUMN identity_sub    TEXT; -- verified Biscuit principal subject (e.g. user email); NULL for non-delegated requests
