//go:build integration

package keystore_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// The tests above prove the store works when Vault behaves. These prove what it
// does when Vault does not — which is the half that decides whether a custody
// service is safe to run. Every one of them asserts the same shape: a failure is
// LOUD (an error the caller cannot mistake for a normal result) and CLOSED (no key,
// no signer, no silent success).

// A Vault that cannot be reached must not look like an agent that has no keys.
// Returning an empty list here would let the directory publish nothing and the
// service carry on as if the agent had simply never registered.
func TestUnreachableVaultIsAnErrorNotAnEmptyResult(t *testing.T) {
	store := newStoreWith(t, deadVaultClient(t), testMount)
	ctx := t.Context()

	keys, err := store.List(ctx, agent)
	if !errors.Is(err, keystore.ErrUnavailable) {
		t.Fatalf("list against a dead Vault = %v (%d keys), want ErrUnavailable", err, len(keys))
	}
	if keys != nil {
		t.Error("a failed list still returned a slice")
	}

	if _, err := store.Create(ctx, agent, liveWindow()); !errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("create against a dead Vault = %v, want ErrUnavailable", err)
	}
	if _, err := store.Active(ctx, agent); !errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("active against a dead Vault = %v, want ErrUnavailable", err)
	}
	if _, err := store.Active(ctx, agent); errors.Is(err, keystore.ErrNotFound) {
		t.Error("a dead Vault is reported as ErrNotFound — the caller cannot tell an outage " +
			"from an agent that holds no keys")
	}
}

// A cancelled context must stop the work, not be ignored. A custody call that keeps
// talking to Vault after its caller has gone is a request the caller can neither
// wait for nor account for.
func TestCancelledContextStopsTheCall(t *testing.T) {
	store, _ := newStore(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := store.Create(ctx, agent, liveWindow())
	if !errors.Is(err, context.Canceled) {
		t.Errorf("create with a cancelled context = %v, want context.Canceled", err)
	}
	// The caller hung up; Vault did nothing wrong. Classifying this as a backend
	// outage would page an operator every time a client walked away mid-request.
	if errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("the caller's own cancellation is reported as a backend outage (%v)", err)
	}

	if _, err := store.List(ctx, agent); !errors.Is(err, context.Canceled) {
		t.Errorf("list with a cancelled context = %v, want context.Canceled", err)
	}
}

// A mount that does not exist is a misconfigured deployment, and it must fail
// loudly. This is the sharpest failure mode in the whole backend: Vault answers a
// read on an unmounted path with "not found", which is indistinguishable — to a
// careless implementation — from "this agent holds no keys". A store that
// swallowed it would serve an empty directory for every agent in the system and
// report perfect health while doing so.
// EVERY operation must fail this way, not just the ones that happen to list. The
// read path (Signer, Export) reaches Vault through a different call than the listing
// path, and it is the one that decides whether a signing request against a broken
// deployment reads as "this deployment has no key store" or as "this agent has no
// such key" — the second sends whoever is on call looking for a bug in the caller.
func TestAMountThatDoesNotExistFailsLoudly(t *testing.T) {
	// Mint a key on the GOOD mount first, so the ref the read path is asked for names
	// a key that genuinely exists. Otherwise a store that answered ErrNotFound for
	// everything would pass this test for the wrong reason.
	good, _ := newStore(t)
	ctx := t.Context()
	key, err := good.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create on the good mount: %v", err)
	}

	store := newStoreWith(t, sharedVault.Client, "no-such-mount")

	keys, listErr := store.List(ctx, agent)
	if !errors.Is(listErr, keystore.ErrUnavailable) {
		t.Fatalf("list on a mount that does not exist = %v (%d keys), want ErrUnavailable — "+
			"a misconfigured mount would otherwise look exactly like an agent with no keys",
			listErr, len(keys))
	}
	if _, err := store.Create(ctx, agent, liveWindow()); !errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("create on a mount that does not exist = %v, want ErrUnavailable", err)
	}

	// The read path. A key that exists on the real mount, asked for on a mount that
	// does not exist: the answer is "there is no key store here", never "there is no
	// such key".
	for _, op := range []struct {
		name string
		call func() error
	}{
		{"signer", func() error { _, err := store.Signer(ctx, key.Ref); return err }},
		{"export", func() error { _, err := store.Export(ctx, key.Ref); return err }},
	} {
		err := op.call()
		if !errors.Is(err, keystore.ErrUnavailable) {
			t.Errorf("%s on a mount that does not exist = %v, want ErrUnavailable", op.name, err)
		}
		if errors.Is(err, keystore.ErrNotFound) {
			t.Errorf("%s reports a missing MOUNT as a missing KEY (%v) — the caller would be "+
				"blamed for naming a key that does exist, and nobody would go looking for the mount",
				op.name, err)
		}
	}
}

// Production will not hand this service a root token. It will hand it a token whose
// policy reaches exactly the paths the store needs and nothing else — and if the
// store needs a capability nobody wrote down, that is discovered in an outage.
// So the least-privilege policy is spelled out here and every operation is driven
// through it: this test IS the policy document, and it fails the day the store
// starts needing more.
func TestTheStoreWorksUnderALeastPrivilegePolicy(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	policy := fmt.Sprintf(`
path "%[1]s/data/agents/*" {
  capabilities = ["create", "update", "read"]
}
path "%[1]s/metadata/agents/*" {
  capabilities = ["list", "read"]
}`, sharedVault.Mount)

	scoped := newStoreWith(t, clientWithToken(t, tokenForPolicy(t, "identity-service", policy)), sharedVault.Mount)

	key, err := scoped.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create under the least-privilege policy: %v", err)
	}
	if _, err := scoped.List(ctx, agent); err != nil {
		t.Errorf("list under the least-privilege policy: %v", err)
	}
	if _, err := scoped.Active(ctx, agent); err != nil {
		t.Errorf("active under the least-privilege policy: %v", err)
	}
	if _, err := scoped.Signer(ctx, key.Ref); err != nil {
		t.Errorf("signer under the least-privilege policy: %v", err)
	}
	if _, err := scoped.Export(ctx, key.Ref); err != nil {
		t.Errorf("export under the least-privilege policy: %v", err)
	}

	// The other half of least privilege: a key minted by the store is readable
	// through the store and nowhere else the policy did not name.
	if _, err := store.Signer(ctx, key.Ref); err != nil {
		t.Errorf("the key the scoped token minted is not readable by the service: %v", err)
	}
}

// A token whose policy does not reach the store's paths must be refused, and the
// refusal must not be mistaken for "no such key". An operator who narrowed a policy
// too far needs to see a permission error, not a service that quietly forgot every
// agent it holds.
func TestATokenWithoutPermissionIsRefusedNotTreatedAsAMiss(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A policy that grants nothing on the store's paths.
	powerless := tokenForPolicy(t, "no-keys", `path "sys/health" { capabilities = ["read"] }`)
	denied := newStoreWith(t, clientWithToken(t, powerless), sharedVault.Mount)

	signer, err := denied.Signer(ctx, key.Ref)
	if !errors.Is(err, keystore.ErrPermissionDenied) {
		t.Fatalf("signer with a powerless token = %v, want ErrPermissionDenied", err)
	}
	if signer != nil {
		t.Error("a denied lookup returned a non-nil signer")
	}
	if errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("permission denied is reported as ErrNotFound (%v) — an over-narrowed policy "+
			"would look like an empty store", err)
	}
	// The distinction that decides who gets woken up. A denial is a policy an operator
	// narrowed too far; an outage is a Vault that is down. Retrying fixes one of them
	// and neither diagnoses the other, so the two must not arrive as the same error.
	if errors.Is(err, keystore.ErrUnavailable) {
		t.Errorf("permission denied is reported as ErrUnavailable (%v) — the caller would "+
			"retry a credential that will be refused every time, and page for an outage "+
			"that is not happening", err)
	}
	if _, err := denied.Create(ctx, agent, liveWindow()); !errors.Is(err, keystore.ErrPermissionDenied) {
		t.Errorf("create with a powerless token = %v, want ErrPermissionDenied", err)
	}
}

// The integrity check exists for records that storage itself gets wrong — a bad
// restore, a hand-edited secret, a half-finished migration. Proving it works means
// producing such a record, and the interface (correctly) offers no way to write one.
// So this test reaches past the interface to ARRANGE the corruption, then asserts
// back through the interface. The exception is deliberate and confined to this test:
// a guarantee about malformed storage cannot be tested through a surface that
// refuses to malform it.
func TestARecordCorruptedInStorageIsRefusedNotSignedWith(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Swap in the seed of a DIFFERENT key, leaving the public half untouched: the
	// record now describes one identity and holds the secret of another. Signing
	// with it would emit signatures that no verifier on earth accepts, and nothing
	// in the happy path would notice.
	other, err := store.Create(ctx, "other.rampmcp.org", liveWindow())
	if err != nil {
		t.Fatalf("create the second key: %v", err)
	}
	kv := sharedVault.Client.KVv2(sharedVault.Mount)
	victimPath := secretPathOf(key.Ref)
	thiefPath := secretPathOf(other.Ref)

	stolen, err := kv.Get(ctx, thiefPath)
	if err != nil {
		t.Fatalf("read the second key: %v", err)
	}
	victim, err := kv.Get(ctx, victimPath)
	if err != nil {
		t.Fatalf("read the first key: %v", err)
	}
	victim.Data["seed"] = stolen.Data["seed"]
	if _, err := kv.Put(ctx, victimPath, victim.Data); err != nil {
		t.Fatalf("write the corrupted record: %v", err)
	}

	if _, err := store.Signer(ctx, key.Ref); !errors.Is(err, keystore.ErrCorrupt) {
		t.Errorf("signer on a record whose seed does not match its public key = %v, want ErrCorrupt", err)
	}
	if _, err := store.Export(ctx, key.Ref); !errors.Is(err, keystore.ErrCorrupt) {
		t.Errorf("export of a corrupted record = %v, want ErrCorrupt", err)
	}
}

// A secret deleted out from under the store — by an operator, by a retention
// policy — reads as a miss, not as a crash and not as a key. And it must not take
// the agent's OTHER keys down with it: the listing skips what vanished and publishes
// the rest, or one deleted secret would empty an agent's entire directory and break
// every verifier holding a cached copy of it.
//
// The agent therefore holds TWO keys and loses one. With a single key, "skip the
// missing one and return the survivors" and "give up and return nothing" produce the
// identical empty result, and the assertion could not tell the guarantee from its
// violation.
func TestASecretDeletedInVaultReadsAsAMiss(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	doomed, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create the key that will be deleted: %v", err)
	}
	clk.Advance(time.Hour)
	survivor, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create the key that must survive: %v", err)
	}

	// Reaching past the interface to ARRANGE, for the same reason the corruption test
	// does: custody offers no way to delete a key, and a vanished key is exactly the
	// state under test. Every assertion comes back through the interface.
	kv := sharedVault.Client.KVv2(sharedVault.Mount)
	if err := kv.Delete(ctx, secretPathOf(doomed.Ref)); err != nil {
		t.Fatalf("delete the secret: %v", err)
	}

	if _, err := store.Signer(ctx, doomed.Ref); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("signer for a deleted secret = %v, want ErrNotFound", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list after a key was deleted: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("list returned %d keys after one of the agent's two was deleted, want 1 — "+
			"a key that vanished must not empty the agent's whole directory", len(keys))
	}
	if !publishesKey(keys, survivor.Ref) {
		t.Errorf("the surviving key %q is not published", survivor.Ref.Thumbprint)
	}
	if publishesKey(keys, doomed.Ref) {
		t.Error("the deleted key is still published")
	}
}

// Two keys minted for one agent at the same moment must both survive. Each key lives
// at its own path (its thumbprint), so nothing is overwritten — but that is a
// property of the layout, and a layout that keyed on the agent alone would lose one
// of them silently.
func TestConcurrentMintsForOneAgentAllSurvive(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	const minters = 8
	var wg sync.WaitGroup
	errs := make(chan error, minters)
	refs := make(chan keystore.Ref, minters)

	for range minters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key, err := store.Create(ctx, agent, liveWindow())
			if err != nil {
				errs <- err
				return
			}
			refs <- key.Ref
		}()
	}
	wg.Wait()
	close(errs)
	close(refs)

	for err := range errs {
		t.Fatalf("concurrent create: %v", err)
	}
	minted := make(map[string]bool, minters)
	for ref := range refs {
		if minted[ref.Thumbprint] {
			t.Fatalf("two mints produced the same thumbprint %q", ref.Thumbprint)
		}
		minted[ref.Thumbprint] = true
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != minters {
		t.Errorf("the agent holds %d keys, want all %d that were minted — a concurrent mint was lost",
			len(keys), minters)
	}
	for _, k := range keys {
		if !minted[k.Ref.Thumbprint] {
			t.Errorf("listed key %q was never minted", k.Ref.Thumbprint)
		}
	}
}

// deadVaultClient addresses a port nothing listens on, with a short timeout so the
// test fails fast rather than hanging.
func deadVaultClient(tb testing.TB) *vaultapi.Client {
	tb.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = "http://127.0.0.1:1"
	cfg.Timeout = 2 * time.Second
	cfg.MaxRetries = 0
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		tb.Fatalf("vault client: %v", err)
	}
	client.SetToken("irrelevant-nobody-is-listening")
	return client
}

// tokenForPolicy writes a Vault policy and returns a fresh token carrying it (and
// nothing else — the "default" policy is excluded so the test really measures what
// the named policy grants).
func tokenForPolicy(tb testing.TB, name, rules string) string {
	tb.Helper()
	ctx := tb.Context()

	if err := sharedVault.Client.Sys().PutPolicyWithContext(ctx, name, rules); err != nil {
		tb.Fatalf("write policy %q: %v", name, err)
	}
	secret, err := sharedVault.Client.Auth().Token().CreateWithContext(ctx, &vaultapi.TokenCreateRequest{
		Policies:        []string{name},
		NoDefaultPolicy: true,
		TTL:             "10m",
	})
	if err != nil {
		tb.Fatalf("create token for policy %q: %v", name, err)
	}
	return secret.Auth.ClientToken
}
