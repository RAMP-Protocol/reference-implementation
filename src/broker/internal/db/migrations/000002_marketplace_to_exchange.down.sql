-- Reverse of 000002_marketplace_to_exchange.up.sql.

ALTER TABLE broker.selection_log RENAME COLUMN winner_exchange TO winner_marketplace;

ALTER INDEX broker.exchanges_priority_idx RENAME TO marketplaces_priority_idx;
ALTER INDEX broker.exchanges_domain_key RENAME TO marketplaces_domain_key;
ALTER INDEX broker.exchanges_pkey RENAME TO marketplaces_pkey;

ALTER TABLE broker.exchanges RENAME COLUMN exchange_id TO marketplace_id;
ALTER TABLE broker.exchanges RENAME TO marketplaces;
