// Command operator is the Identity Service's break-glass CLI. Its one job today is
// key revocation — the emergency lever that deliberately does NOT live behind a
// public HTTP endpoint (an unauthenticated one would let anyone kill any agent's
// keys). Whoever can run this binary already holds operator access to Vault and
// Postgres, so there is no untrusted caller to authenticate: the CLI itself is the
// authorization boundary, the same choice keystore.Export makes.
//
// Cross-process note: a revocation writes to the same Vault and Postgres the running
// server reads, so it takes effect there within the document TTL. The in-memory
// Invalidate fast path is same-process only, so the CLI cannot trigger it — see
// noopInvalidator.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/idconfig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/lifecycle"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
)

const usage = "usage: identity-operator revoke <subdomain> <thumbprint>"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger, os.Args[1:]); err != nil {
		logger.Error("identity-operator.exit", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, args []string) error {
	subdomain, thumbprint, err := parseRevokeArgs(args)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := idconfig.SetupDB(ctx, logger)
	if err != nil {
		return err
	}
	defer pool.Close()

	store, err := idconfig.NewKeyStore()
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	revoker := lifecycle.NewRevoker(store, repo.NewRevocationRepo(pool), noopInvalidator{}, clock.System{}, logger)
	if err := revoker.Revoke(ctx, subdomain, thumbprint); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stdout, "revoked %s %s\n", subdomain, thumbprint)
	return nil
}

// parseRevokeArgs validates the CLI invocation. Only the revoke subcommand exists
// today; an unknown command, or anything but exactly a subdomain and a thumbprint, is
// a usage error.
func parseRevokeArgs(args []string) (subdomain, thumbprint string, err error) {
	if len(args) != 3 || args[0] != "revoke" {
		return "", "", errors.New(usage)
	}
	return args[1], args[2], nil
}

// noopInvalidator satisfies lifecycle.Invalidator without doing anything: cache
// invalidation is a same-process fast path, and the running server is a DIFFERENT
// process, so there is no in-memory cache here to drop. The server picks up the
// revocation within its document TTL (publisher.DefaultTTL) — the cross-process bound
// the publisher already documents.
type noopInvalidator struct{}

func (noopInvalidator) Invalidate(string) {}
