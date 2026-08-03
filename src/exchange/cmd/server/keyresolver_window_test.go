package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy/windowtest"
)

// writeTempKeys writes raw as a JWKS at a temp path and returns it.
func writeTempKeys(t *testing.T, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
	return p
}

// TestLoadKeysFile_WindowBehavior wires the Exchange's static key-file loader
// into the shared static-key validity-window table (windowtest.BehaviorCases):
// loadKeysFileIntoResolver + TimedStaticResolver must honour the
// [not_before, not_after) gate — a lapsed or not-yet-valid key resolves to
// ErrKeyExpired (not the window-blind unconditional verify the pre-SDK
// helpers.StaticKeyResolver.Put gave), an in-window key resolves to its pubkey.
func TestLoadKeysFile_WindowBehavior(t *testing.T) {
	windowtest.RunBehavior(t, func(t *testing.T, raw []byte, tp string) error {
		resolver := keypolicy.NewTimedStaticResolver(clock.NewDeterministic(windowtest.Anchor))
		if err := loadKeysFileIntoResolver(resolver, writeTempKeys(t, raw)); err != nil {
			t.Fatalf("loadKeysFileIntoResolver: %v", err)
		}
		_, err := resolver.Resolve(context.Background(), tp)
		return err
	})
}

// TestLoadKeysFile_UnparseableWindowNoKeysLoaded is the Exchange-specific
// fail-closed outcome (not shared, because the loaders diverge here): when the
// only entry has an unparseable window it is skipped, so the loader reports no
// keys loaded and the thumbprint stays unknown.
func TestLoadKeysFile_UnparseableWindowNoKeysLoaded(t *testing.T) {
	raw, tp := windowtest.MintWindowedJWKS(t, "", "not-a-timestamp")
	resolver := keypolicy.NewTimedStaticResolver(nil)
	if err := loadKeysFileIntoResolver(resolver, writeTempKeys(t, raw)); err == nil {
		t.Fatal("want error (no keys loaded) when the only entry has an unparseable window, got nil")
	}
	if _, err := resolver.Resolve(context.Background(), tp); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("skipped entry must be unknown, got %v", err)
	}
}
