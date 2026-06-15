-- Reverse of 000009_validation_outcome_marketplace_to_exchange.up.sql.

ALTER TYPE ramp.validation_outcome RENAME VALUE 'REJECTED_EXCHANGE' TO 'REJECTED_MARKETPLACE';
