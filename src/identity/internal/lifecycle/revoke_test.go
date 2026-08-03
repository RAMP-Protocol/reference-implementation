package lifecycle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/lifecycle"
)

// These unit tests drive the Revoker's orchestration through fault-injecting fakes —
// the failure orderings that decide whether a revocation is safe, which a real Vault
// and Postgres cannot be made to exhibit on demand. The happy path and idempotency are
// covered end-to-end through the HTTP surface in the transport package's e2e suite.

const (
	luSub = "agent-1.rampmcp.org"
	luTP  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

type fakeKeys struct {
	keys       []keystore.Key
	listErr    error
	destroyErr error
	destroyed  []keystore.Ref
}

func (f *fakeKeys) List(_ context.Context, _ string) ([]keystore.Key, error) {
	return f.keys, f.listErr
}

func (f *fakeKeys) Destroy(_ context.Context, ref keystore.Ref) error {
	f.destroyed = append(f.destroyed, ref)
	return f.destroyErr
}

type fakeRevocations struct {
	asOf      int64
	revoked   []string // what Get returns
	revokeErr error
	revokes   []string // thumbprints Revoke recorded
}

func (f *fakeRevocations) Revoke(_ context.Context, _, thumbprint string, _ int64) (int64, error) {
	if f.revokeErr != nil {
		return 0, f.revokeErr
	}
	f.revokes = append(f.revokes, thumbprint)
	return f.asOf, nil
}

func (f *fakeRevocations) BySubdomain(_ context.Context, _ string) (int64, []string, error) {
	return f.asOf, f.revoked, nil
}

type fakeInvalidator struct{ calls []string }

func (f *fakeInvalidator) Invalidate(subdomain string) { f.calls = append(f.calls, subdomain) }

func heldKey(tp string) keystore.Key {
	return keystore.Key{Ref: keystore.Ref{Subdomain: luSub, Thumbprint: tp}}
}

func newTestRevoker(keys *fakeKeys, revs *fakeRevocations, inv *fakeInvalidator) *lifecycle.Revoker {
	return lifecycle.NewRevoker(keys, revs, inv, clock.NewDeterministic(time.Unix(0, 1_000_000)), testutil.DiscardLogger())
}

func TestRevoke_InvalidSubdomainIsRejectedBeforeAnyWrite(t *testing.T) {
	keys := &fakeKeys{keys: []keystore.Key{heldKey(luTP)}}
	revs := &fakeRevocations{}
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), "not a valid host!", luTP)
	if !errors.Is(err, keystore.ErrInvalidSubdomain) {
		t.Fatalf("Revoke with a bad subdomain = %v, want ErrInvalidSubdomain", err)
	}
	if len(revs.revokes) != 0 || len(keys.destroyed) != 0 || len(inv.calls) != 0 {
		t.Error("a rejected revoke still touched a backend")
	}
}

func TestRevoke_UnknownThumbprintIsRejectedBeforeAnyWrite(t *testing.T) {
	keys := &fakeKeys{keys: []keystore.Key{heldKey("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")}}
	revs := &fakeRevocations{} // Get returns nothing revoked either
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), luSub, luTP)
	if !errors.Is(err, lifecycle.ErrUnknownThumbprint) {
		t.Fatalf("Revoke of a foreign thumbprint = %v, want ErrUnknownThumbprint", err)
	}
	if len(revs.revokes) != 0 || len(keys.destroyed) != 0 {
		t.Error("a rejected revoke still touched a backend")
	}
}

// The security-critical ordering: once the list write lands, a failing Vault destroy
// must NOT fail the revocation — the key is already publicly revoked, and the erase is
// best-effort hygiene for the prune pass / a re-run.
func TestRevoke_DestroyFailureStillRevokesAndInvalidates(t *testing.T) {
	keys := &fakeKeys{keys: []keystore.Key{heldKey(luTP)}, destroyErr: errors.New("vault down")}
	revs := &fakeRevocations{asOf: 1234}
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), luSub, luTP)
	if err != nil {
		t.Fatalf("Revoke with a failing Destroy = %v, want nil (the list write already took effect)", err)
	}
	if len(revs.revokes) != 1 {
		t.Error("the revocation was not recorded despite the destroy failure")
	}
	if len(keys.destroyed) != 1 {
		t.Error("Destroy was not attempted")
	}
	if len(inv.calls) != 1 {
		t.Error("the cache was not invalidated despite the destroy failure")
	}
}

// The other side of the ordering: if the list write itself fails, the key must NOT be
// destroyed — erasing it without publicly revoking it is the worst outcome (a dead key
// that no verifier was told about).
func TestRevoke_ListWriteFailureAbortsBeforeDestroy(t *testing.T) {
	keys := &fakeKeys{keys: []keystore.Key{heldKey(luTP)}}
	revs := &fakeRevocations{revokeErr: errors.New("db down")}
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), luSub, luTP)
	if err == nil {
		t.Fatal("Revoke with a failing list write = nil, want an error")
	}
	if len(keys.destroyed) != 0 {
		t.Error("Destroy ran even though the list write failed — the key was erased without being revoked")
	}
	if len(inv.calls) != 0 {
		t.Error("cache invalidated despite the list write failing")
	}
}

// Vault being unreachable is the incident revocation exists for: the operator reaches
// for it precisely because a key was exfiltrated and Vault may be the thing that failed.
// The held-key pre-check is a Vault read, but it must NOT gate the durable list write —
// a Vault-unavailable List degrades to trusting the operator so the revocation still
// lands (the destroy then fails best-effort, as usual). Regression guard for the
// pre-check that used to abort the whole revocation here.
func TestRevoke_VaultUnavailableStillLandsListWrite(t *testing.T) {
	keys := &fakeKeys{listErr: keystore.ErrUnavailable, destroyErr: keystore.ErrUnavailable}
	revs := &fakeRevocations{asOf: 99}
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), luSub, luTP)
	if err != nil {
		t.Fatalf("Revoke while Vault is down = %v, want nil (the durable list write must still land)", err)
	}
	if len(revs.revokes) != 1 {
		t.Error("the revocation was not recorded while Vault was down — the durable write did not land")
	}
	if len(inv.calls) != 1 {
		t.Error("the cache was not invalidated after the revocation landed")
	}
}

// The degradation is scoped to an outage: a non-ErrUnavailable Vault fault (a denied
// token, a corrupt payload) is a real problem the operator must see, so it still aborts
// before any write rather than silently trusting the thumbprint.
func TestRevoke_NonOutageVaultErrorStillAbortsBeforeWrite(t *testing.T) {
	keys := &fakeKeys{listErr: keystore.ErrPermissionDenied}
	revs := &fakeRevocations{}
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), luSub, luTP)
	if err == nil {
		t.Fatal("Revoke with a non-outage Vault error = nil, want an error (only an outage degrades)")
	}
	if len(revs.revokes) != 0 || len(keys.destroyed) != 0 || len(inv.calls) != 0 {
		t.Error("a non-outage Vault fault still touched a backend")
	}
}

// A key already on the list but no longer held (its material was destroyed by an
// earlier run) is still "known", so a re-run re-publishes instead of erroring — the
// idempotency the crash-recovery path depends on.
func TestRevoke_AlreadyRevokedThumbprintIsStillKnown(t *testing.T) {
	keys := &fakeKeys{keys: nil} // nothing held: the first run destroyed it
	revs := &fakeRevocations{asOf: 5, revoked: []string{luTP}}
	inv := &fakeInvalidator{}

	err := newTestRevoker(keys, revs, inv).Revoke(context.Background(), luSub, luTP)
	if err != nil {
		t.Fatalf("re-revoke of an already-listed key = %v, want nil (idempotent)", err)
	}
	if len(revs.revokes) != 1 {
		t.Error("the re-revoke did not re-publish the list")
	}
}
