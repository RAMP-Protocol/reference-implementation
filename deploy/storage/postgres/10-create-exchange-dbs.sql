-- NOT A DEPLOYMENT STEP. This file sits beside the PostgreSQL operator documents
-- but is not part of them: it exists only for the automated end-to-end test stack,
-- which runs three Exchanges at once. Do not run it against a deployment — see
-- CONFIGURATION.md §3 for the databases a real deployment does need.
--
-- How it runs: docker-compose.e2e.yml bind-mounts this file into
-- /docker-entrypoint-initdb.d/, so postgres executes it ONCE while initialising the
-- data directory — before the TCP socket opens for application connections. That is
-- why the services below, which wait for `depends_on: postgres condition:
-- service_healthy`, never find a missing database. `make e2e-down -v` wipes the
-- volume, so the next `up` re-runs it. Nothing here is created later, on demand:
-- every service that uses one of these databases runs its own migrations at boot but
-- never issues CREATE DATABASE, so the database has to exist before it connects.

-- Catalog databases. Each Exchange instance owns a SEPARATE catalog database, so
-- DiscoverResources (which reads the whole catalog without filtering by tenant —
-- exchange/internal/service/catalog.go) cannot expose one publisher's catalog on
-- another Exchange. exchange-a uses the default POSTGRES_DB (ramp); exchange-b and
-- exchange-c need their own.
CREATE DATABASE ramp_b;
CREATE DATABASE ramp_c;

-- System-of-Record (SoR) databases. Each Exchange keeps its account registry
-- (schema `sor`, table `sor.agent_accounts`) in a SEPARATE logical database from its
-- catalog DB above: the Postgres SoR adapter opens a SECOND pool via
-- EXCHANGE_SOR_DSN and runs its own migrations at boot. billing_ref is
-- one-per-Exchange (ADR-021), so the registry is per-exchange, mirroring the
-- per-exchange catalog split above.
CREATE DATABASE ramp_sor;
CREATE DATABASE ramp_sor_b;
CREATE DATABASE ramp_sor_c;

-- Identity Service (registry / MCP adapter). It migrates at boot against
-- IDENTITY_DSN, so its database is created here alongside the exchange/SoR ones.
CREATE DATABASE identity;
