ALTER TABLE ramp.transaction_log
    DROP COLUMN subscription_id;

ALTER TABLE ramp.catalog
    DROP COLUMN required_scopes,
    DROP COLUMN subscription_id;
