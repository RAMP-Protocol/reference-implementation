-- Reverse of 000003_drop_selection_winner.up.sql. Re-adds the columns as
-- nullable TEXT (the post-000002 shape). Historical winner data is not restored
-- — it was the self-inconsistent value this migration removed.

ALTER TABLE broker.selection_log ADD COLUMN winner_offer_id TEXT;
ALTER TABLE broker.selection_log ADD COLUMN winner_exchange TEXT;
