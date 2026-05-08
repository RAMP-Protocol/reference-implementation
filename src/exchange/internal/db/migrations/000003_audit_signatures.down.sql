ALTER TABLE ramp.transaction_log
    DROP COLUMN IF EXISTS signed_url_signature,
    DROP COLUMN IF EXISTS offer_signature;
