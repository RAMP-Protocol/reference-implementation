//go:build integration

package keystore_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// testMount is the KV v2 mount the suite writes to. Reset replaces it wholesale
// between tests.
const testMount = "identity-kv"

// sharedVault is the package's single Vault container, brought up once by
// TestMain and reset before each test. Written once before m.Run and read-only
// thereafter, so the serial integration tests need no synchronization.
var sharedVault *testutil.SharedVault

// TestMain brings up one dev-mode Vault container for the whole package. The
// os.Exit is delegated so the container-terminate defer actually runs.
func TestMain(m *testing.M) {
	os.Exit(runIntegrationMain(m))
}

func runIntegrationMain(m *testing.M) int {
	ctx := context.Background()
	logger := testutil.DiscardLogger()

	vault, cleanup, err := testutil.StartSharedVault(ctx, logger, testMount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared vault: %v\n", err)
		return 1
	}
	defer cleanup()

	sharedVault = vault
	return m.Run()
}

// anchor is the instant the deterministic clock starts at. Windows in the suite
// are expressed relative to it, so nothing depends on the wall clock.
var anchor = time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

// resetFor names the test the shared Vault was last reset for. Every store the
// suite builds passes through ensureReset, so a test cannot obtain a store over
// state the previous test left behind — not even by reaching for the constructor
// that takes its own client.
//
// A test that builds two stores (a root one and a scoped one, say) must not have
// the second reset wipe what the first just wrote, so the reset is once per test,
// not once per store. Reset-at-start rather than in cleanup keeps the suite robust
// against a test that panics midway. Tests touching the shared Vault are serial —
// Reset unmounts the engine under any sibling — so this needs no synchronization.
var resetFor testing.TB

// ensureReset restores the shared Vault to an empty mount, once, for tb.
func ensureReset(tb testing.TB) {
	tb.Helper()
	if resetFor == tb {
		return
	}
	if err := sharedVault.Reset(tb.Context()); err != nil {
		tb.Fatalf("reset vault: %v", err)
	}
	resetFor = tb
}

// newStore returns a store over the shared Vault, together with the clock driving
// it.
func newStore(tb testing.TB) (keystore.KeyStore, *clock.DeterministicClock) {
	tb.Helper()
	clk := clock.NewDeterministic(anchor)
	return newStoreWithClock(tb, sharedVault.Client, sharedVault.Mount, clk), clk
}

// newStoreWith builds a store over a caller-supplied client and mount, for
// the tests that exercise what happens when either is wrong — a dead Vault, a
// token Vault refuses, a mount that does not exist.
func newStoreWith(tb testing.TB, client *vaultapi.Client, mount string) keystore.KeyStore {
	tb.Helper()
	return newStoreWithClock(tb, client, mount, clock.NewDeterministic(anchor))
}

// newStoreWithClock is the one place this suite builds a store, so the per-test
// reset cannot be skipped by picking a different helper. The reset is once per test,
// not once per store (see ensureReset), so a test that needs a SECOND store — a
// restarted service, a differently-credentialed one — builds it through here too and
// keeps the keys the first one wrote.
func newStoreWithClock(
	tb testing.TB, client *vaultapi.Client, mount string, clk clock.Clock,
) keystore.KeyStore {
	tb.Helper()
	ensureReset(tb)
	store, err := keystore.NewVaultStore(keystore.Config{
		Client: client,
		Mount:  mount,
		Clk:    clk,
	})
	if err != nil {
		tb.Fatalf("new vault store: %v", err)
	}
	return store
}

// secretPathOf is the Vault path holding one key's record, for the two tests that
// must reach past the interface to INJECT a storage fault (a corrupted record, a
// key deleted out from under the store). Production owns this layout in
// VaultStore.secretPath; spelling it out a third time in each test would silently
// point them at nothing the day the layout moved.
func secretPathOf(ref keystore.Ref) string {
	return path.Join(keystore.DefaultPrefix, ref.Subdomain, ref.Thumbprint)
}

// clientWithToken returns a Vault client for the shared container authenticated
// with the given token. It is how a test stands in for a differently-credentialed
// deployment — the composition root is the only place that picks a credential, so
// this is the composition root of the test.
func clientWithToken(tb testing.TB, token string) *vaultapi.Client {
	tb.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = sharedVault.Client.Address()
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		tb.Fatalf("vault client: %v", err)
	}
	client.SetToken(token)
	return client
}

// liveWindow is the validity window most tests mint keys with: open now, close in
// thirty days.
func liveWindow() keystore.Window {
	return keystore.Window{NotBefore: anchor, NotAfter: anchor.Add(30 * 24 * time.Hour)}
}

// windowFrom builds a validity window that opens `offset` from the suite's anchor
// and stays open for `dur`. A negative offset mints a key whose window has already
// closed; a positive one, a key that is not yet valid. Everything is expressed
// relative to the deterministic clock, so no test waits on the wall clock to make a
// key expire.
func windowFrom(offset, dur time.Duration) keystore.Window {
	opens := anchor.Add(offset)
	return keystore.Window{NotBefore: opens, NotAfter: opens.Add(dur)}
}
