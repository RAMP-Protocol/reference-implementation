// Package db embeds Broker migrations for execution on startup.
package db

import "embed"

// Migrations holds the embedded Broker schema migration files.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// MigrationsDir is the subdirectory inside Migrations containing .sql files.
const MigrationsDir = "migrations"

// MigrationsTable names the golang-migrate tracking table (lives in public schema).
const MigrationsTable = "schema_migrations_broker"
