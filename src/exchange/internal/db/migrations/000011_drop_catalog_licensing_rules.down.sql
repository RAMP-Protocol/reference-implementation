-- Reverse of 000011: re-add the licensing_rules column in its original 000001
-- shape (JSONB NOT NULL DEFAULT '{}'). Mirrors 000001_init.up.sql so a down
-- migration restores the pre-CONTRACT schema exactly.

ALTER TABLE ramp.catalog
    ADD COLUMN licensing_rules JSONB NOT NULL DEFAULT '{}'::jsonb;
