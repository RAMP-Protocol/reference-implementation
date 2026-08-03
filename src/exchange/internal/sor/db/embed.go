// Package db embeds the SoR migrations for execution on startup. The SoR runs
// its own migration sequence against its own logical database
// (EXCHANGE_SOR_DSN), tracked separately from the Exchange's main schema.
package db

import "embed"

// Migrations holds the embedded SoR schema migration files.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// MigrationsDir is the subdirectory inside Migrations containing .sql files.
const MigrationsDir = "migrations"

// MigrationsTable names the golang-migrate tracking table (lives in public
// schema). Distinct from the Exchange's schema_migrations_ramp so the two
// sequences never collide even if an operator points both DSNs at one database.
const MigrationsTable = "schema_migrations_sor"
