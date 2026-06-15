-- Rename the broker's "marketplaces" concept to "exchanges" to align with the
-- RAMP protocol, which carries an "exchange" field on ResourceResponse and
-- UsageReport. Pure structural rename: table, primary-key column, the explicit
-- priority index, the implicit PK/UNIQUE backing indexes, and the
-- selection_log winner column. No data semantics change.

ALTER TABLE broker.marketplaces RENAME TO exchanges;
ALTER TABLE broker.exchanges RENAME COLUMN marketplace_id TO exchange_id;

ALTER INDEX broker.marketplaces_pkey RENAME TO exchanges_pkey;
ALTER INDEX broker.marketplaces_domain_key RENAME TO exchanges_domain_key;
ALTER INDEX broker.marketplaces_priority_idx RENAME TO exchanges_priority_idx;

ALTER TABLE broker.selection_log RENAME COLUMN winner_marketplace TO winner_exchange;
