// Package idconfig builds the Identity Service's backend clients from the
// environment — the Vault-backed KeyStore and the migrated Postgres pool — so the
// server and the operator CLI wire the same backends the same way from one place,
// rather than each hand-rolling (and drifting on) the construction.
package idconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	identitydb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// NewKeyStore builds the Vault-backed KeyStore from the environment. Choosing how the
// service authenticates to Vault (a token today; AppRole/Kubernetes/AWS IAM later) is
// the composition root's job, not custody's — so the client is built and authenticated
// here and handed in already-ready.
func NewKeyStore() (*keystore.VaultStore, error) {
	cfg := vaultapi.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	if tok := runhttp.EnvOr("VAULT_TOKEN", ""); tok != "" {
		client.SetToken(tok)
	}
	return keystore.NewVaultStore(keystore.Config{
		Client: client,
		Mount:  runhttp.EnvOr("IDENTITY_KV_MOUNT", ""),
		Prefix: runhttp.EnvOr("IDENTITY_KV_PREFIX", ""),
		Clk:    clock.System{},
	})
}

// SetupDB opens the identity Postgres pool from IDENTITY_DSN, applying the identity
// migrations. A missing DSN is a configuration error, not a silent nil pool.
func SetupDB(ctx context.Context, logger *slog.Logger) (*pgxpool.Pool, error) {
	pool, err := db.Setup(ctx, db.SetupOptions{
		DSN:             runhttp.EnvOr("IDENTITY_DSN", ""),
		Migrations:      identitydb.Migrations,
		MigrationsDir:   identitydb.MigrationsDir,
		MigrationsTable: identitydb.MigrationsTable,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("db setup: %w", err)
	}
	if pool == nil {
		return nil, errors.New("IDENTITY_DSN is required")
	}
	return pool, nil
}
