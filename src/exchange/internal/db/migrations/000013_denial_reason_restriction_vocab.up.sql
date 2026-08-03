-- Reconcile ramp.denial_reason with the Universal Licensing Core proto overhaul
-- (b9c0735), which unified the restriction vocabulary: the per-axis denial
-- reasons FUNCTION_PROHIBITED and GEO_RESTRICTED collapsed into a single
-- RESTRICTION_NOT_SATISFIED reason (the matching OfferAbsenceReason values
-- collapsed into RESTRICTION_FILTERED on the discovery side).
--
-- This is a forward-compatibility add ONLY. The Exchange does not yet EMIT the
-- new reason — Select stays scope-only and does not enforce restrictions
-- (ADR-014) — so no row writes this value today; the migration simply lets the
-- column persist it once an enforcing path exists. ALTER TYPE ... ADD VALUE is
-- atomic in PG12+ and idempotent under IF NOT EXISTS (see migration 000008).
--
-- The removed proto values FUNCTION_PROHIBITED and GEO_RESTRICTED are
-- DELIBERATELY retained in the enum: PostgreSQL has no ALTER TYPE ... DROP
-- VALUE, the generated sqlc models still reference both constants, and the
-- values are harmless legacy (no new code emits them). Retiring them would
-- require rebuilding the type and rewriting every dependent column for no
-- behavioral gain.

ALTER TYPE ramp.denial_reason ADD VALUE IF NOT EXISTS 'RESTRICTION_NOT_SATISFIED';
