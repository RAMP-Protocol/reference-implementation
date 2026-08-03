//go:build integration

package sor_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// Registers the Postgres backend into the shared conformance suite, so every
// cross-backend assertion in adapter_conformance_test.go also runs against a
// real migrated Postgres. parallel stays false: each factory invocation resets
// the package's shared container to its snapshot baseline, which cannot
// overlap parallel siblings (Testing Doctrine 11).
func init() {
	extraConformanceFactories = append(extraConformanceFactories, adapterFactory{
		name:     "PostgresAdapter",
		new:      newPostgresConformanceAdapter,
		parallel: false,
	})
}

// newPostgresConformanceAdapter acquires a fresh (baseline-reset) database and
// returns the production adapter over it — the same construction wiring uses.
func newPostgresConformanceAdapter(tb testing.TB) sor.Adapter {
	tb.Helper()
	pool := acquireTestDB(tb, context.Background())
	return sor.NewPostgresAdapter(sharedb.PoolRunner{Pool: pool})
}

// TestPostgresOnRegisterIdempotentRowIdentical drives a repeat registration —
// different candidate id, different data, different starting status — and
// asserts the returned account is IDENTICAL to the first call's across every
// field, observed purely through the adapter surface (persistence round-trip:
// adapter → repo → Postgres and back). It also re-reads through a SECOND
// adapter instance over the same database to prove the state lives in
// Postgres, not in the adapter value.
func TestPostgresOnRegisterIdempotentRowIdentical(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	adapter := sor.NewPostgresAdapter(sharedb.PoolRunner{Pool: pool})

	first, err := adapter.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: "11111111-1111-1111-1111-111111111111",
		Subdomain:  "acme.agents.example",
		Active:     true,
		RegistrationData: map[string]string{
			"legal_entity":             "ACME Inc",
			"jurisdiction_country":     "GB",
			"jurisdiction_subdivision": "ENG",
			"address_line1":            "1 High St",
			"address_line2":            "Floor 2",
			"address_city":             "London",
			"address_region":           "Greater London",
			"address_postal_code":      "E1 6AN",
			"address_country":          "GB",
			"email":                    "ops@acme.example",
			"vat_id":                   "GB123",
			"phone":                    "+44 20 0000 0000",
		},
	})
	if err != nil {
		t.Fatalf("first OnRegister: %v", err)
	}

	// Check that every typed column comes back with the exact value that went
	// in. The DeepEqual below only compares two reads with each other, and
	// both reads go through the same mapping code — so if that code mixed up
	// two columns (say city and region) on both the way in and the way out,
	// the two reads would still match and the test would stay green. Only
	// comparing against the original input catches such a mix-up.
	wantProfile := sor.LicensingProfile{
		LegalEntity:             "ACME Inc",
		JurisdictionCountry:     "GB",
		JurisdictionSubdivision: "ENG",
		AddressLine1:            "1 High St",
		AddressLine2:            "Floor 2",
		AddressCity:             "London",
		AddressRegion:           "Greater London",
		AddressPostalCode:       "E1 6AN",
		AddressCountry:          "GB",
	}
	if first.Profile != wantProfile {
		t.Errorf("first register profile round-trip:\n got: %+v\nwant: %+v", first.Profile, wantProfile)
	}
	if first.Email != "ops@acme.example" {
		t.Errorf("Email = %q, want %q", first.Email, "ops@acme.example")
	}
	if first.Extra["vat_id"] != "GB123" || first.Extra["phone"] != "+44 20 0000 0000" {
		t.Errorf("Extra = %+v, want the two unmapped keys preserved verbatim", first.Extra)
	}

	second, err := adapter.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: "22222222-2222-2222-2222-222222222222",
		Subdomain:  "acme.agents.example",
		Active:     false,
		RegistrationData: map[string]string{
			"legal_entity": "Changed Corp",
			"vat_id":       "XX999",
			"new_key":      "should never persist",
		},
	})
	if err != nil {
		t.Fatalf("repeat OnRegister: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Errorf("repeat register mutated the account:\n first: %+v\nsecond: %+v", first, second)
	}

	// Same database, fresh adapter value: the repeat result must be what a
	// later reader observes, proving the row (not adapter memory) is the record.
	reread := sor.NewPostgresAdapter(sharedb.PoolRunner{Pool: pool})
	active, err := reread.IsActive(ctx, first.BillingRef)
	if err != nil {
		t.Fatalf("IsActive via second adapter instance: %v", err)
	}
	if !active {
		t.Error("IsActive = false, want the first call's true preserved across instances")
	}
	if _, err := reread.IsActive(ctx, "22222222-2222-2222-2222-222222222222"); !errors.Is(err, sor.ErrAccountNotFound) {
		t.Errorf("IsActive(repeat candidate) = %v, want ErrAccountNotFound — the second candidate must never persist", err)
	}
}

// TestPostgresIsActiveUnknownCreatesNoRow drives IsActive for a never-seen
// billing_ref and asserts (through the adapter surface only) that the failed
// lookup left no row behind: a subsequent OnRegister reusing that exact
// billing_ref as the candidate succeeds and persists it — impossible had a
// phantom row already claimed the primary key.
func TestPostgresIsActiveUnknownCreatesNoRow(t *testing.T) {
	ctx := context.Background()
	pool := acquireTestDB(t, ctx)
	adapter := sor.NewPostgresAdapter(sharedb.PoolRunner{Pool: pool})

	const ref = "33333333-3333-3333-3333-333333333333"
	if _, err := adapter.IsActive(ctx, ref); !errors.Is(err, sor.ErrAccountNotFound) {
		t.Fatalf("IsActive(unknown) = %v, want ErrAccountNotFound", err)
	}

	got, err := adapter.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: ref,
		Subdomain:  "fresh.agents.example",
		Active:     true,
	})
	if err != nil {
		t.Fatalf("OnRegister after failed IsActive: %v", err)
	}
	if got.BillingRef != ref {
		t.Errorf("BillingRef = %q, want the probed candidate %q persisted — a phantom row from the failed lookup would have blocked it", got.BillingRef, ref)
	}
	active, err := adapter.IsActive(ctx, ref)
	if err != nil {
		t.Fatalf("IsActive after register: %v", err)
	}
	if !active {
		t.Error("IsActive = false, want true")
	}
}
