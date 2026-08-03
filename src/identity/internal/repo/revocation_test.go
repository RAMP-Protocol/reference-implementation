//go:build integration

package repo_test

import (
	"context"
	"reflect"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
)

// Thumbprints are opaque text to this layer (the RFC 7638 shape is enforced above
// it), but realistic 43-char base64url values keep the fixtures honest.
const (
	revAgent = "agent-7.rampmcp.org"
	tpA      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tpB      = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	tpC      = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

// A subdomain that has never had a revocation is the epoch-dated baseline, not an
// error: as_of 0 with an empty set is exactly what the builder serves as
// "nothing revoked".
func TestRevocationRepo_GetWithNoRowIsEmptyBaseline(t *testing.T) {
	ctx := context.Background()
	r := repo.NewRevocationRepo(acquireTestDB(t, ctx))

	asOf, revoked, err := r.BySubdomain(ctx, revAgent)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if asOf != 0 {
		t.Errorf("as_of = %d, want 0 for a never-revoked subdomain", asOf)
	}
	if len(revoked) != 0 {
		t.Errorf("revoked = %v, want empty", revoked)
	}
}

func TestRevocationRepo_RevokeThenGet(t *testing.T) {
	ctx := context.Background()
	r := repo.NewRevocationRepo(acquireTestDB(t, ctx))
	const now = int64(1_000_000)

	asOf, err := r.Revoke(ctx, revAgent, tpA, now)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if asOf != now {
		t.Errorf("first as_of = %d, want now_epoch %d", asOf, now)
	}

	gotAsOf, revoked, err := r.BySubdomain(ctx, revAgent)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if gotAsOf != now {
		t.Errorf("Get as_of = %d, want %d", gotAsOf, now)
	}
	if !reflect.DeepEqual(revoked, []string{tpA}) {
		t.Errorf("revoked = %v, want [%s]", revoked, tpA)
	}
}

// The registry owns as_of and keeps it strictly increasing regardless of the clock:
// two revokes in the same tick, or a clock that steps backward, must still advance
// it — otherwise the consumer's rollback guard would drop a real, later snapshot.
func TestRevocationRepo_AsOfStrictlyIncreasesEvenWhenTheClockStallsOrGoesBackward(t *testing.T) {
	ctx := context.Background()
	r := repo.NewRevocationRepo(acquireTestDB(t, ctx))

	a1, err := r.Revoke(ctx, revAgent, tpA, 1000)
	if err != nil {
		t.Fatalf("revoke 1: %v", err)
	}
	a2, err := r.Revoke(ctx, revAgent, tpB, 1000) // same tick
	if err != nil {
		t.Fatalf("revoke 2: %v", err)
	}
	a3, err := r.Revoke(ctx, revAgent, tpC, 400) // clock went backward
	if err != nil {
		t.Fatalf("revoke 3: %v", err)
	}
	if a1 >= a2 || a2 >= a3 {
		t.Errorf("as_of not strictly increasing across revokes: %d, %d, %d", a1, a2, a3)
	}
}

// Re-revoking a thumbprint already in the set republishes (as_of advances) but never
// duplicates the entry.
func TestRevocationRepo_RevokeIsIdempotentOnTheSetButStillBumpsAsOf(t *testing.T) {
	ctx := context.Background()
	r := repo.NewRevocationRepo(acquireTestDB(t, ctx))

	a1, err := r.Revoke(ctx, revAgent, tpA, 1000)
	if err != nil {
		t.Fatalf("revoke 1: %v", err)
	}
	a2, err := r.Revoke(ctx, revAgent, tpA, 1000) // same thumbprint again
	if err != nil {
		t.Fatalf("revoke 2: %v", err)
	}
	if a2 <= a1 {
		t.Errorf("as_of did not advance on re-revoke: %d then %d", a1, a2)
	}

	_, revoked, err := r.BySubdomain(ctx, revAgent)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(revoked, []string{tpA}) {
		t.Errorf("revoked = %v, want the thumbprint listed exactly once", revoked)
	}
}

func TestRevocationRepo_RevokeAppendsThumbprintsInOrder(t *testing.T) {
	ctx := context.Background()
	r := repo.NewRevocationRepo(acquireTestDB(t, ctx))

	if _, err := r.Revoke(ctx, revAgent, tpA, 1000); err != nil {
		t.Fatalf("revoke A: %v", err)
	}
	if _, err := r.Revoke(ctx, revAgent, tpB, 1001); err != nil {
		t.Fatalf("revoke B: %v", err)
	}

	_, revoked, err := r.BySubdomain(ctx, revAgent)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(revoked, []string{tpA, tpB}) {
		t.Errorf("revoked = %v, want [%s %s]", revoked, tpA, tpB)
	}
}

// Revocation is per-subdomain: revoking one agent's key leaves every other agent on
// the empty baseline.
func TestRevocationRepo_IsPerSubdomain(t *testing.T) {
	ctx := context.Background()
	r := repo.NewRevocationRepo(acquireTestDB(t, ctx))

	if _, err := r.Revoke(ctx, revAgent, tpA, 1000); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	asOf, revoked, err := r.BySubdomain(ctx, "other.rampmcp.org")
	if err != nil {
		t.Fatalf("Get other: %v", err)
	}
	if asOf != 0 || len(revoked) != 0 {
		t.Errorf("other subdomain saw as_of=%d revoked=%v, want the empty baseline", asOf, revoked)
	}
}
