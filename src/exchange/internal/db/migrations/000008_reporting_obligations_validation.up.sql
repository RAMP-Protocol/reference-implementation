-- Protocol-validation surface for ReportUsage (RAMP §3.2 #4) plus the trust
-- and idempotency columns needed to make the four-check enforcement honest.
--
-- This migration is a single atomic add: the validation enum, the obligation
-- columns the validator and audit trail read, the report-idempotency anchor
-- pair, and the tenant-level broker-relay opt-in. Down mirror drops every
-- addition in reverse order.
--
-- Per the L3 finding from the validation doc, every column carries an inline
-- annotation explaining what it persists; matches the style of migrations
-- 000001 and 000007.

-- ---------------------------------------------------------------------------
-- Validation-outcome enum (replaces the TEXT+CHECK form the first cut shipped
-- with). Native ENUM gives sqlc a typed Go string instead of pgtype.Text and
-- restores compile-time safety at every comparison site. See review finding 6.
-- ---------------------------------------------------------------------------

CREATE TYPE ramp.validation_outcome AS ENUM (
    -- The four canonical outcomes from RAMP §3.2 #4 plus the two L6-remainder
    -- outcomes for timestamp and exchange mismatches. Audit consumers
    -- discriminate purely on this enum.
    'VALIDATED',
    'REJECTED_FIELDS',
    'REJECTED_WINDOW',
    'REJECTED_TOLERANCE',
    'REJECTED_BILLING_ID',
    'REJECTED_TIMESTAMP',
    'REJECTED_MARKETPLACE'
);

-- ---------------------------------------------------------------------------
-- Add BROKER to the requester_type enum. The trust model (implementation
-- plan Q1+Q2) distinguishes self-acting agents from brokers that report on
-- behalf — the discriminator lives on the agents row and the value space
-- has to carry "BROKER" explicitly. ALTER TYPE ... ADD VALUE is atomic in
-- PG12+ and idempotent under the IF NOT EXISTS clause.
-- ---------------------------------------------------------------------------

ALTER TYPE ramp.requester_type ADD VALUE IF NOT EXISTS 'BROKER';

-- ---------------------------------------------------------------------------
-- Tenant-level broker-relay opt-in. A tenant that wants Broker components to
-- file UsageReports on behalf of agents flips this flag; with the flag off
-- (default) every report MUST come from a verified caller whose keyID equals
-- the obligation's agent_id (Q1+Q2 decisions in the implementation plan).
-- ---------------------------------------------------------------------------

ALTER TABLE ramp.tenants
    ADD COLUMN allow_broker_relay BOOLEAN NOT NULL DEFAULT FALSE; -- broker-on-behalf authorization toggle

-- ---------------------------------------------------------------------------
-- Reporting-obligation additions. All NOT NULL with sensible defaults so the
-- migration is non-blocking on a populated table.
-- ---------------------------------------------------------------------------

ALTER TABLE ramp.reporting_obligations
    ADD COLUMN required_fields    TEXT[]                       NOT NULL DEFAULT '{}'::TEXT[],          -- fields the caller must include in the report; sourced from tenants.reporting_policy at obligation creation
    ADD COLUMN estimated_quantity BIGINT                       NOT NULL DEFAULT 0,                    -- pricing.estimated_quantity captured at transaction time for the tolerance check
    ADD COLUMN quantity_tolerance NUMERIC(5,4)                 NOT NULL DEFAULT 0.20,                 -- per-obligation fractional tolerance (0.20 = ±20%); see service.defaultQuantityTolerance
    ADD COLUMN validation_outcome ramp.validation_outcome,                                            -- audit enum; set on every ReportUsage attempt (NULL until first attempt)
    ADD COLUMN validated_at       TIMESTAMPTZ,                                                        -- wall-clock timestamp of the validation attempt
    ADD COLUMN source_report_id   TEXT,                                                               -- UsageReport.id supplied by the caller; idempotency anchor (NULL pre-report)
    ADD COLUMN issued_report_id   TEXT;                                                               -- UsageReportResponse.report_id returned by Exchange; dispute-chain anchor (NULL pre-report)

-- Partial unique index makes (transaction_id, source_report_id) the structural
-- idempotency key for ReportUsage retries. A second call carrying the same
-- UsageReport.id collides at the DB layer regardless of application logic;
-- the service uses this to return the original issued_report_id on retry.
CREATE UNIQUE INDEX reporting_obligations_source_report_idx
    ON ramp.reporting_obligations (transaction_id, source_report_id)
    WHERE source_report_id IS NOT NULL;
