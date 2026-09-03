-- Append-only audit log for admin control-plane changes.
--
-- The admin RPCs (SetTenantFeeRate, SetReportingPolicy) change money and policy
-- on a plane with no per-operator identity in v1 — the network allowlist is the
-- only gate. This table is therefore the sole detection / reconstruction path:
-- with last-writer-wins setters (the messages carry no revision / applied_at), a
-- concurrent overwrite is only recoverable from here. One row is written inside
-- the same transaction as each successful setter, after the rows-affected check,
-- so a no-op / unknown-tenant call leaves no row.
--
-- Agent registration writes here too. It is a control-plane event that creates an
-- account and records which licensing terms were accepted, it happens once per
-- account, and nothing else keeps a dated record of it. Unlike the admin plane it
-- has an authenticated caller, so those rows carry an actor.
--
-- actor is nullable and coarse (the admin plane has no operator identity yet);
-- source_addr is the caller's peer address; action names the RPC; detail is the
-- JSONB of applied values; request_id correlates with the X-Request-ID logs. No
-- FK on tenant_id: the log is an independent append-only record of the id, not a
-- relationship, and must survive tenant deletion.

CREATE TABLE ramp.audit_log (
    log_id      TEXT PRIMARY KEY,
    actor       TEXT,                                    -- nullable/coarse: no per-operator identity in v1
    source_addr TEXT        NOT NULL,
    action      TEXT        NOT NULL,                     -- which admin RPC
    detail      JSONB       NOT NULL DEFAULT '{}'::jsonb, -- applied values
    tenant_id   TEXT        NOT NULL,                     -- subject of the change; recorded, not FK'd
    request_id  TEXT,                                     -- X-Request-ID correlation
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX audit_log_tenant_idx  ON ramp.audit_log (tenant_id, created_at DESC);
CREATE INDEX audit_log_request_idx ON ramp.audit_log (request_id, created_at DESC);
