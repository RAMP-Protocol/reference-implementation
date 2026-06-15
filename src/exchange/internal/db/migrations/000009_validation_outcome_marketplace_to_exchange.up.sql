-- Rename the validation-outcome enum value REJECTED_MARKETPLACE to
-- REJECTED_EXCHANGE so the persisted audit value aligns with the RAMP
-- "exchange" field (renamed upstream from "marketplace"). The repo-layer
-- domain enum (repo.ValidationOutcomeRejectedExchange) keeps its literal 1:1
-- with this PG enum string, so the domain → sqlc translation stays a plain
-- cast. Pure value rename: no rows are rewritten and no column changes.

ALTER TYPE ramp.validation_outcome RENAME VALUE 'REJECTED_MARKETPLACE' TO 'REJECTED_EXCHANGE';
