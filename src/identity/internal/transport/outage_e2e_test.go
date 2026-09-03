//go:build integration

package transport_test

import (
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
)

// deadPool returns a pool aimed at a port nothing listens on. pgxpool.New does not
// dial, so construction succeeds and the FIRST QUERY fails with a pgconn.ConnectError
// — which is exactly the error class a real Postgres outage produces, and the class
// repo's isUnavailable classifies as retryable.
//
// A dead port rather than a paused container because the container is shared by the
// whole package: stopping it would break every sibling test, and per-test containers
// are the pattern the suite exists to avoid.
func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	// Port 1 is reserved and never bound; the DSN parses, so only the dial fails.
	pool, err := pgxpool.New(t.Context(), "postgres://ramp:ramp@127.0.0.1:1/ramp?connect_timeout=1")
	if err != nil {
		t.Fatalf("build unreachable pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestPostgresOutageAnswers503NotAbsence drives a real Postgres outage through the
// whole chain the production server runs: pgx -> PgxDeveloperRepo/PgxCardRepo ->
// publisher -> transport -> HTTP. Nothing is faked; only the database is unreachable.
//
// It exists because every layer of that chain was proven separately against an
// injected sentinel, and no test connected them. Changing the repository's outage
// mapping from account.ErrUnavailable to account.ErrNotFound survived the entire
// identity suite: the publisher and transport tests inject the sentinel they expect,
// and the repository tests cover only success and a genuinely missing row.
//
// The distinction is not cosmetic. 404 tells a consumer the agent does not exist,
// which is a durable claim about identity; 503 says ask again. Worse, a 404 is
// CACHEABLE here — an absent document carries no unavailability flag, so the
// publisher would store the outage as a fact and keep answering 404 for the full
// TTL after Postgres came back.
func TestPostgresOutageAnswers503NotAbsence(t *testing.T) {
	ctx := t.Context()
	if err := sharedVault.Reset(ctx); err != nil {
		t.Fatalf("reset vault: %v", err)
	}
	f := wireFixture(t, deadPool(t))
	sub := "agent-outage." + baseZone
	// Vault is healthy and holds this agent's key, so the key directory must keep
	// serving while its Postgres-backed siblings cannot answer. That split is the
	// per-document availability the publisher claims to provide.
	mustCreate(t, f.store, sub)

	for _, tc := range []struct {
		name, path string
	}{
		{"commercial overlay", rampwellknown.Path},
		{"signature agent card", directory.CardPath},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, _ := f.getForHost(t, sub, tc.path)
			if status != http.StatusServiceUnavailable {
				t.Errorf("GET %s during a Postgres outage: status = %d, want 503 (a 404 would"+
					" report the agent as absent, and would be cached as such)", tc.path, status)
			}
		})
	}

	t.Run("key directory is unaffected", func(t *testing.T) {
		if status, _, _ := f.getForHost(t, sub, rampwellknown.WBAPath); status != http.StatusOK {
			t.Errorf("WBA directory status = %d, want 200 — Vault is healthy, so a Postgres"+
				" outage must not take the key directory down with it", status)
		}
	})

	// A 503 must not be remembered. The publisher declines to cache a build that
	// carried any unavailability, so a second request re-reads rather than serving a
	// pinned outage; if that rule broke, recovery would wait out the TTL.
	t.Run("the outage is not cached", func(t *testing.T) {
		if status, _, _ := f.getForHost(t, sub, rampwellknown.Path); status != http.StatusServiceUnavailable {
			t.Errorf("second GET during the outage: status = %d, want 503", status)
		}
	})
}
