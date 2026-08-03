//go:build integration

package keystore_test

import (
	"context"
	"errors"
	"path"
	"slices"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// This suite drives the two lifecycle-substrate operations rotation and revocation
// are built on — Expire (retire a key by shortening its window) and Destroy (erase a
// revoked key, every version of it). Like the rest of the package it arranges and
// asserts through the KeyStore interface; the one exception is the version-history
// test, which MUST read Vault directly because the leak it guards against — an old
// version still holding the seed — is by construction invisible through an interface
// that only ever reads the latest.

// missingThumbprint is a syntactically valid RFC 7638 thumbprint (43 base64url
// chars) that no test ever mints, so a ref built from it names a key that is not
// there without tripping validation first.
const missingThumbprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// TestExpireShortensWindowSoTheKeyStopsBeingActive is the retirement half of a
// rotation: the old key must keep its identity and its order but stop being handed
// out once the overlap has drained.
func TestExpireShortensWindowSoTheKeyStopsBeingActive(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow()) // [anchor, anchor+30d]
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	retireAt := anchor.Add(2 * time.Hour)
	if err := store.Expire(ctx, key.Ref, retireAt); err != nil {
		t.Fatalf("expire: %v", err)
	}

	// Published window closes at the shortened bound; identity and order are untouched.
	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("list returned %d keys, want 1", len(keys))
	}
	got := keys[0]
	if !got.Window.NotAfter.Equal(retireAt) {
		t.Errorf("shortened not_after = %s, want %s", got.Window.NotAfter, retireAt)
	}
	if got.Ref != key.Ref {
		t.Errorf("thumbprint changed under Expire: %+v, want %+v", got.Ref, key.Ref)
	}
	if !got.CreatedAt.Equal(key.CreatedAt) {
		t.Errorf("CreatedAt changed under Expire: %s, want %s", got.CreatedAt, key.CreatedAt)
	}
	if !got.Public.Equal(key.Public) {
		t.Error("public key changed under Expire")
	}

	// Before the shortened bound the key is still the active one; after it, gone.
	if _, err := store.Active(ctx, agent); err != nil {
		t.Errorf("active before the shortened bound: %v, want the key", err)
	}
	clk.Advance(3 * time.Hour) // now anchor+3h, past the anchor+2h bound
	if _, err := store.Active(ctx, agent); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("active after the shortened bound: %v, want ErrNotFound", err)
	}
}

// TestExpireRefusesToExtendAWindow: moving a window's end outward could resurrect a
// retired or revoked key, so Expire rejects it and leaves the stored window as it was.
func TestExpireRefusesToExtendAWindow(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow()) // ends anchor+30d
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	err = store.Expire(ctx, key.Ref, anchor.Add(60*24*time.Hour)) // later than the current end
	if !errors.Is(err, keystore.ErrInvalidWindow) {
		t.Fatalf("expire with a later bound: %v, want ErrInvalidWindow", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if want := liveWindow().NotAfter; !keys[0].Window.NotAfter.Equal(want) {
		t.Errorf("window moved on a refused extend: not_after = %s, want %s", keys[0].Window.NotAfter, want)
	}
}

// TestExpireRefusesAnEmptyWindow: a bound at or before NotBefore leaves a window that
// can contain no instant, which is malformed input, not a retirement.
func TestExpireRefusesAnEmptyWindow(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow()) // opens at anchor
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	err = store.Expire(ctx, key.Ref, anchor.Add(-time.Hour)) // before NotBefore
	if !errors.Is(err, keystore.ErrInvalidWindow) {
		t.Fatalf("expire before not_before: %v, want ErrInvalidWindow", err)
	}
}

// TestExpireOnAMissingKeyIsNotFound: retiring a key that is not there is the caller's
// mistake to hear about, distinct from a backend fault.
func TestExpireOnAMissingKeyIsNotFound(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	ref := keystore.Ref{Subdomain: agent, Thumbprint: missingThumbprint}
	if err := store.Expire(ctx, ref, anchor.Add(time.Hour)); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("expire on a missing key: %v, want ErrNotFound", err)
	}
}

// TestDestroyRemovesKeyFromListActiveAndSigner: after a revocation's erase the key is
// gone from every read surface at once — it cannot be published, selected, or signed with.
func TestDestroyRemovesKeyFromListActiveAndSigner(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := store.Destroy(ctx, key.Ref); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("list returned %d keys after Destroy, want 0", len(keys))
	}
	if _, err := store.Active(ctx, agent); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("active after Destroy: %v, want ErrNotFound", err)
	}
	if _, err := store.Signer(ctx, key.Ref); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("signer after Destroy: %v, want ErrNotFound", err)
	}
}

// TestDestroyErasesEveryVersionNotJustTheLatest is the KV v2 hazard test. An Expire
// writes a second version and leaves the first — seed and all — sitting in history; a
// naive "overwrite with an empty record" revocation would stop there and leave the key
// readable to anyone who can name version 1. Destroy must erase the whole history.
//
// This is the one test that reads Vault directly: the surviving old version is
// invisible through a KeyStore that only reads the latest, so the interface cannot see
// the very leak this test exists to catch.
func TestDestroyErasesEveryVersionNotJustTheLatest(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow()) // version 1, holds the seed
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Expire(ctx, key.Ref, anchor.Add(2*time.Hour)); err != nil { // version 2
		t.Fatalf("expire: %v", err)
	}

	// The leak is real before Destroy: version 1 still exists and still carries a seed.
	if v1 := readKeyVersion(t, ctx, key.Ref, "1"); v1 == nil {
		t.Fatal("version 1 absent before Destroy — cannot demonstrate the hazard")
	} else if data, _ := v1.Data["data"].(map[string]any); data["seed"] == nil {
		t.Fatal("version 1 carries no seed before Destroy — cannot demonstrate the hazard")
	}

	if err := store.Destroy(ctx, key.Ref); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	if readKeyVersion(t, ctx, key.Ref, "1") != nil {
		t.Error("version 1 survived Destroy — a plain overwrite would leave the seed readable")
	}
	if readKeyVersion(t, ctx, key.Ref, "2") != nil {
		t.Error("version 2 survived Destroy")
	}
	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("list returned %d keys after Destroy, want 0", len(keys))
	}
}

// TestDestroyIsIdempotent: a revocation whose first attempt died after the list write
// but before the erase must be safe to run again, so destroying an absent key succeeds.
func TestDestroyIsIdempotent(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	// A key that never existed.
	absent := keystore.Ref{Subdomain: agent, Thumbprint: missingThumbprint}
	if err := store.Destroy(ctx, absent); err != nil {
		t.Errorf("destroy on an absent key: %v, want nil", err)
	}

	// A real key destroyed twice.
	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Destroy(ctx, key.Ref); err != nil {
		t.Fatalf("first destroy: %v", err)
	}
	if err := store.Destroy(ctx, key.Ref); err != nil {
		t.Errorf("second destroy: %v, want nil", err)
	}
}

// TestListSubdomains_EmptyStoreYieldsNone: enumerating an empty store is a state, not
// an error — the scheduler simply has no agents to walk.
func TestListSubdomains_EmptyStoreYieldsNone(t *testing.T) {
	store, _ := newStore(t)
	subs, err := store.ListSubdomains(t.Context())
	if err != nil {
		t.Fatalf("ListSubdomains: %v", err)
	}
	if len(subs) != 0 {
		t.Errorf("empty store listed %v, want none", subs)
	}
}

// TestListSubdomains_ReturnsEveryAgentThatHoldsKeys: the scheduler walks agents, not
// keys, so an agent with several keys is named once and every key-holding agent is
// present.
func TestListSubdomains_ReturnsEveryAgentThatHoldsKeys(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()
	for _, sub := range []string{"agent-a.rampmcp.org", "agent-b.rampmcp.org"} {
		if _, err := store.Create(ctx, sub, liveWindow()); err != nil {
			t.Fatalf("create %s: %v", sub, err)
		}
	}
	// A second key for one agent must not list it twice.
	if _, err := store.Create(ctx, "agent-a.rampmcp.org", liveWindow()); err != nil {
		t.Fatalf("second create: %v", err)
	}

	subs, err := store.ListSubdomains(ctx)
	if err != nil {
		t.Fatalf("ListSubdomains: %v", err)
	}
	slices.Sort(subs)
	if want := []string{"agent-a.rampmcp.org", "agent-b.rampmcp.org"}; !slices.Equal(subs, want) {
		t.Errorf("ListSubdomains = %v, want %v", subs, want)
	}
}

// readKeyVersion reads one specific version of a key's Vault secret. A nil return
// means that version no longer exists (Vault answers a destroyed or absent version
// with a 404, which the client surfaces as a nil secret). It is the only place in the
// suite that reads a Vault path the KeyStore interface cannot expose — see the note on
// TestDestroyErasesEveryVersionNotJustTheLatest.
func readKeyVersion(tb testing.TB, ctx context.Context, ref keystore.Ref, version string) *vaultapi.Secret {
	tb.Helper()
	dataPath := path.Join(sharedVault.Mount, "data", secretPathOf(ref))
	sec, err := sharedVault.Client.Logical().ReadWithDataWithContext(
		ctx, dataPath, map[string][]string{"version": {version}},
	)
	if err != nil {
		tb.Fatalf("raw read of %s version %s: %v", dataPath, version, err)
	}
	return sec
}
