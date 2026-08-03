//go:build integration

package transport_test

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/lifecycle"
)

// This suite drives revocation as a full-surface round-trip: the write goes through
// the production Revoker service (keystore + revocation repo + publisher.Invalidate)
// and every observation comes back through the same public HTTP endpoints a verifier
// polls — the directory and the revocation list. Nothing reads Vault or SQL directly
// to assert (the one keystore.Signer check confirms destruction through the production
// custody surface, the documented tier-2 fallback the fixture already relies on).

func newRevoker(t *testing.T, f *fixture) *lifecycle.Revoker {
	t.Helper()
	return lifecycle.NewRevoker(f.store, f.revocations, f.svc, clock.System{}, testutil.DiscardLogger())
}

func parseRevocation(t *testing.T, body []byte) *rampwellknown.RevocationList {
	t.Helper()
	var list rampwellknown.RevocationList
	if err := protojson.Unmarshal(body, &list); err != nil {
		t.Fatalf("parse revocation list: %v", err)
	}
	return &list
}

func epoch() time.Time { return time.Unix(0, 0).UTC() }

// The end-to-end story: before any revocation the endpoint serves the epoch baseline;
// after revoking a key the served list names it with a real as_of, the directory has
// dropped it while still serving the agent's other key, and the key's material is gone.
func TestRevocation_BaselineThenRevokedRoundTrip(t *testing.T) {
	f := newFixture(t)
	sub := "agent-rev." + baseZone
	victim := mustCreate(t, f.store, sub)
	survivor := mustCreate(t, f.store, sub)

	// Baseline: a directory exists, nothing revoked yet.
	status, ctype, body := f.getForHost(t, sub, rampwellknown.RevocationPath)
	if status != http.StatusOK {
		t.Fatalf("baseline status = %d, want 200", status)
	}
	if ctype != directory.RevocationMediaType {
		t.Errorf("content-type = %q, want %q", ctype, directory.RevocationMediaType)
	}
	if base := parseRevocation(t, body); !base.GetAsOf().AsTime().Equal(epoch()) || len(base.GetRevoked()) != 0 {
		t.Errorf("baseline = {as_of %s, revoked %v}, want {epoch, empty}",
			base.GetAsOf().AsTime(), base.GetRevoked())
	}

	// Revoke the victim through the production service.
	if err := newRevoker(t, f).Revoke(t.Context(), sub, victim.Ref.Thumbprint); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// The served list now names the victim with a real (post-epoch) as_of.
	status, _, body = f.getForHost(t, sub, rampwellknown.RevocationPath)
	if status != http.StatusOK {
		t.Fatalf("post-revoke revocation status = %d, want 200", status)
	}
	list := parseRevocation(t, body)
	if !list.GetAsOf().AsTime().After(epoch()) {
		t.Errorf("post-revoke as_of = %s, want a real timestamp past the epoch", list.GetAsOf().AsTime())
	}
	if !contains(list.GetRevoked(), victim.Ref.Thumbprint) {
		t.Errorf("revoked = %v, want it to name the victim %s", list.GetRevoked(), victim.Ref.Thumbprint)
	}

	// The directory dropped the victim but still serves the survivor.
	status, _, dirBody := f.getForHost(t, sub, rampwellknown.WBAPath)
	if status != http.StatusOK {
		t.Fatalf("directory status = %d, want 200 (survivor keeps it alive)", status)
	}
	xs := directoryXValues(t, dirBody)
	if contains(xs, rampwellknown.EncodeEd25519X(victim.Public)) {
		t.Error("directory still publishes the revoked key")
	}
	if !contains(xs, rampwellknown.EncodeEd25519X(survivor.Public)) {
		t.Error("directory dropped the survivor, which was not revoked")
	}

	// The victim's material is destroyed — the service can no longer sign with it.
	if _, err := f.store.Signer(t.Context(), victim.Ref); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("signer for the revoked key = %v, want ErrNotFound (destroyed)", err)
	}
}

// A thumbprint that is not the agent's is an operator typo, rejected before it can put
// a junk entry on the list — and it leaves the served list untouched.
func TestRevocation_UnknownThumbprintIsRejectedWithNoSideEffect(t *testing.T) {
	f := newFixture(t)
	sub := "agent-typo." + baseZone
	mustCreate(t, f.store, sub)

	const foreign = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := newRevoker(t, f).Revoke(t.Context(), sub, foreign); !errors.Is(err, lifecycle.ErrUnknownThumbprint) {
		t.Fatalf("Revoke of a foreign thumbprint = %v, want ErrUnknownThumbprint", err)
	}

	_, _, body := f.getForHost(t, sub, rampwellknown.RevocationPath)
	if list := parseRevocation(t, body); len(list.GetRevoked()) != 0 {
		t.Errorf("revoked = %v, want empty after a rejected revoke", list.GetRevoked())
	}
}

// Re-running a revocation (the recovery path after a mid-operation crash) is safe: the
// key is listed exactly once and as_of advances on the re-publication.
func TestRevocation_IsIdempotent(t *testing.T) {
	f := newFixture(t)
	sub := "agent-idem." + baseZone
	victim := mustCreate(t, f.store, sub)
	mustCreate(t, f.store, sub) // survivor keeps the directory alive
	rv := newRevoker(t, f)

	if err := rv.Revoke(t.Context(), sub, victim.Ref.Thumbprint); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	_, _, body := f.getForHost(t, sub, rampwellknown.RevocationPath)
	first := parseRevocation(t, body)

	if err := rv.Revoke(t.Context(), sub, victim.Ref.Thumbprint); err != nil {
		t.Fatalf("second revoke (must be idempotent): %v", err)
	}
	_, _, body = f.getForHost(t, sub, rampwellknown.RevocationPath)
	second := parseRevocation(t, body)

	occurrences := 0
	for _, tp := range second.GetRevoked() {
		if tp == victim.Ref.Thumbprint {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("victim listed %d times after re-revoke, want exactly 1", occurrences)
	}
	if !second.GetAsOf().AsTime().After(first.GetAsOf().AsTime()) {
		t.Errorf("as_of did not advance on re-revoke: %s then %s",
			first.GetAsOf().AsTime(), second.GetAsOf().AsTime())
	}
}

// Revoking an agent's SOLE key makes its directory go absent (no active keys left) —
// but the revocation list MUST keep being served, or a consumer still holding a cached
// directory could never learn the key is dead. An absent directory reads as "unknown",
// not "revoked"; the list is the only channel that says the key is dead for good.
func TestRevocation_SurvivesDirectoryGoingAbsent(t *testing.T) {
	f := newFixture(t)
	sub := "agent-sole." + baseZone
	sole := mustCreate(t, f.store, sub)

	if err := newRevoker(t, f).Revoke(t.Context(), sub, sole.Ref.Thumbprint); err != nil {
		t.Fatalf("revoke the sole key: %v", err)
	}

	if status, _, _ := f.getForHost(t, sub, rampwellknown.WBAPath); status != http.StatusNotFound {
		t.Fatalf("directory status after revoking the sole key = %d, want 404", status)
	}

	status, _, body := f.getForHost(t, sub, rampwellknown.RevocationPath)
	if status != http.StatusOK {
		t.Fatalf("revocation status after the directory went absent = %d, want 200", status)
	}
	if list := parseRevocation(t, body); !contains(list.GetRevoked(), sole.Ref.Thumbprint) {
		t.Errorf("revoked = %v, want it to still name the dead key %s", list.GetRevoked(), sole.Ref.Thumbprint)
	}
}
