//go:build integration

package agentsign_test

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

// testMount is the KV v2 mount the suite writes to; Reset replaces it wholesale
// between tests.
const testMount = "identity-kv"

// sharedVault is the package's single Vault container, brought up once by TestMain
// and reset before each test.
var sharedVault *testutil.SharedVault

// anchor is the instant the deterministic clock starts at, so no key window
// depends on the wall clock.
var anchor = time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) { os.Exit(runIntegrationMain(m)) }

func runIntegrationMain(m *testing.M) int {
	vault, cleanup, err := testutil.StartSharedVault(context.Background(), testutil.DiscardLogger(), testMount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared vault: %v\n", err)
		return 1
	}
	defer cleanup()
	sharedVault = vault
	return m.Run()
}

// newCustody returns a store over a freshly reset shared Vault, plus the clock
// driving it so a test can move a key's window without waiting. Reset-at-start
// keeps the suite robust against a test that panics midway; these tests are serial
// because Reset unmounts the engine under any sibling.
func newCustody(tb testing.TB) (keystore.KeyStore, *clock.DeterministicClock) {
	tb.Helper()
	if err := sharedVault.Reset(tb.Context()); err != nil {
		tb.Fatalf("reset vault: %v", err)
	}
	clk := clock.NewDeterministic(anchor)
	store, err := keystore.NewVaultStore(keystore.Config{
		Client: sharedVault.Client,
		Mount:  sharedVault.Mount,
		Clk:    clk,
	})
	if err != nil {
		tb.Fatalf("new vault store: %v", err)
	}
	return store, clk
}

// liveWindow is the validity window most tests mint keys with: open now, close in
// thirty days.
func liveWindow() keystore.Window {
	return keystore.Window{NotBefore: anchor, NotAfter: anchor.Add(30 * 24 * time.Hour)}
}
