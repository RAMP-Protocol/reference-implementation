//go:build integration

package lifecycle_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// The scheduler tests need Vault (the keys it rotates) but not Postgres — revocation
// is the Revoker's concern, not the scheduler's — so this bespoke TestMain brings up
// one Vault container for the package and resets its mount per test.
const testMount = "identity-kv"

var sharedVault *testutil.SharedVault

func TestMain(m *testing.M) {
	vault, cleanup, err := testutil.StartSharedVault(context.Background(), testutil.DiscardLogger(), testMount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared vault: %v\n", err)
		os.Exit(1)
	}
	sharedVault = vault
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// schedAnchor is where the deterministic clock starts; every window in the suite is
// expressed relative to it, so nothing depends on the wall clock.
var schedAnchor = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

// newRotationStore resets the shared Vault to an empty mount and returns a store over
// it plus the deterministic clock driving it, so each test starts clean.
func newRotationStore(tb testing.TB) (*keystore.VaultStore, *clock.DeterministicClock) {
	tb.Helper()
	if err := sharedVault.Reset(tb.Context()); err != nil {
		tb.Fatalf("reset vault: %v", err)
	}
	clk := clock.NewDeterministic(schedAnchor)
	store, err := keystore.NewVaultStore(keystore.Config{
		Client: sharedVault.Client, Mount: sharedVault.Mount, Clk: clk,
	})
	if err != nil {
		tb.Fatalf("new vault store: %v", err)
	}
	return store, clk
}
