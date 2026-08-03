// Package db embeds Identity Service migrations for execution on startup.
package db

import "embed"

// Migrations holds the embedded Identity schema migration files.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// MigrationsDir is the subdirectory inside Migrations containing .sql files.
const MigrationsDir = "migrations"

// MigrationsTable names the golang-migrate tracking table (lives in public schema).
const MigrationsTable = "schema_migrations_identity"
