package sor_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// Adapter conformance suite. These assertions define the cross-backend
// behavioral contract for any sor.Adapter. InMemoryAdapter runs it today; a
// future Postgres backend registers the same factory so this file becomes its
// behavioral spec.

// Fixed candidate billing_refs. The SoR never mints ids — the Exchange does and
// passes them in (ADR-021 D2) — so the tests supply the candidates directly.
const (
	candidateA = "11111111-1111-1111-1111-111111111111"
	candidateB = "22222222-2222-2222-2222-222222222222"
	subAcme    = "acme.agents.example"
)

type adapterFactory struct {
	name string
	// new builds a fresh, empty adapter for one subtest. It takes the subtest's
	// testing.TB so a DB-backed factory can acquire (and reset) its database
	// per invocation; the in-memory factory ignores it.
	new func(tb testing.TB) sor.Adapter
	// parallel makes subtest parallelism a per-factory decision. The in-memory
	// factory sets it true; the shared-container Postgres factory MUST leave
	// it false — its per-test snapshot Reset cannot overlap parallel siblings
	// (Testing Doctrine 11).
	parallel bool
}

// extraConformanceFactories collects backend factories registered from
// build-tagged files (the Postgres factory registers itself from the
// integration-tagged file's init), so this base suite still compiles and runs
// untagged with the in-memory adapter alone.
var extraConformanceFactories []adapterFactory

func conformanceFactories() []adapterFactory {
	base := make([]adapterFactory, 0, 1+len(extraConformanceFactories))
	base = append(base, adapterFactory{
		name:     "InMemoryAdapter",
		new:      func(testing.TB) sor.Adapter { return sor.NewInMemoryAdapter() },
		parallel: true,
	})
	return append(base, extraConformanceFactories...)
}

// Deliberately not parallel at the top level: the factory list can include a
// shared-database backend whose per-test snapshot Reset must never overlap a
// sibling top-level test. Per-factory parallelism is maybeParallel's job.
func TestSoRAdapterConformance(t *testing.T) {
	for _, f := range conformanceFactories() {
		runSoRConformance(t, f)
	}
}

// runSoRConformance takes the factory by value (no loop-var capture) so a
// parallel factory's subtests are safe.
func runSoRConformance(t *testing.T, f adapterFactory) {
	t.Run(f.name, func(t *testing.T) {
		maybeParallel(t, f)
		sub := func(name string, fn func(*testing.T, adapterFactory)) {
			t.Run(name, func(t *testing.T) {
				maybeParallel(t, f)
				fn(t, f)
			})
		}
		sub("OnRegister_Persists_ReturnsCandidate", confOnRegisterPersists)
		sub("OnRegister_Idempotent_DifferentCandidate", confOnRegisterIdempotent)
		sub("IsActive_True", confIsActiveTrue)
		sub("IsActive_False", confIsActiveFalse)
		sub("IsActive_Unknown_NotFound", confIsActiveUnknown)
		sub("IsActive_EmptyBillingRef_Rejected", confIsActiveEmptyBillingRef)
		sub("OnRegister_EmptySubdomain_Rejected", confEmptySubdomain)
		sub("OnRegister_EmptyBillingRef_Rejected", confEmptyBillingRef)
	})
}

func maybeParallel(t *testing.T, f adapterFactory) {
	t.Helper()
	if f.parallel {
		t.Parallel()
	}
}

// confOnRegisterPersists: a fresh account persists the passed-in candidate and
// returns it; the account is then resolvable and active through IsActive.
func confOnRegisterPersists(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(t)

	got, err := a.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: candidateA, Subdomain: subAcme, Active: true,
		RegistrationData: map[string]string{
			"legal_entity": "ACME Inc",
			"email":        "ops@acme.example",
			"vat_id":       "GB123",
		},
	})
	if err != nil {
		t.Fatalf("OnRegister: %v", err)
	}
	if got.BillingRef != candidateA {
		t.Errorf("BillingRef = %q, want the passed-in candidate %q", got.BillingRef, candidateA)
	}
	if !got.Active {
		t.Error("Active = false, want true (passed in)")
	}
	if got.Profile.LegalEntity != "ACME Inc" {
		t.Errorf("Profile.LegalEntity = %q, want mapped to typed field", got.Profile.LegalEntity)
	}
	if got.Email != "ops@acme.example" {
		t.Errorf("Email = %q, want mapped out of registration data", got.Email)
	}
	if got.Extra["vat_id"] != "GB123" {
		t.Errorf("Extra = %v, want the unmapped vat_id retained", got.Extra)
	}

	active, err := a.IsActive(ctx, candidateA)
	if err != nil {
		t.Fatalf("IsActive after register: %v", err)
	}
	if !active {
		t.Error("IsActive = false, want true — account was not persisted")
	}
}

// confOnRegisterIdempotent: a repeat on the same subdomain carrying a DIFFERENT
// candidate id and different data returns the ORIGINALLY stored account
// unchanged — stored billing_ref wins, first-call active preserved, and the
// second candidate never becomes resolvable (ADR-021 D4, no side effects).
func confOnRegisterIdempotent(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(t)

	first, err := a.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: candidateA, Subdomain: subAcme, Active: true,
		RegistrationData: map[string]string{"legal_entity": "ACME Inc", "vat_id": "GB123"},
	})
	if err != nil {
		t.Fatalf("first OnRegister: %v", err)
	}

	second, err := a.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: candidateB, Subdomain: subAcme, Active: false,
		RegistrationData: map[string]string{"legal_entity": "Changed Corp", "vat_id": "XX999"},
	})
	if err != nil {
		t.Fatalf("repeat OnRegister: %v", err)
	}
	if second.BillingRef != candidateA {
		t.Errorf("repeat BillingRef = %q, want the originally stored %q", second.BillingRef, candidateA)
	}
	if !second.Active {
		t.Error("repeat Active = false, want the first call's true preserved")
	}
	if second.Profile.LegalEntity != "ACME Inc" {
		t.Errorf("repeat Profile.LegalEntity = %q, want the first call's value unchanged", second.Profile.LegalEntity)
	}
	if second.Extra["vat_id"] != "GB123" {
		t.Errorf("repeat Extra[vat_id] = %q, want the first call's %q preserved unchanged", second.Extra["vat_id"], "GB123")
	}
	if first.BillingRef != second.BillingRef {
		t.Errorf("stored id drifted: first %q, second %q", first.BillingRef, second.BillingRef)
	}

	if _, err := a.IsActive(ctx, candidateB); !errors.Is(err, sor.ErrAccountNotFound) {
		t.Errorf("IsActive(candidateB) = %v, want ErrAccountNotFound — the second candidate must never persist", err)
	}
	active, err := a.IsActive(ctx, candidateA)
	if err != nil {
		t.Fatalf("IsActive(candidateA): %v", err)
	}
	if !active {
		t.Error("IsActive(candidateA) = false, want the first account still active")
	}
}

func confIsActiveTrue(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(t)
	mustRegister(t, a, candidateA, subAcme, true)

	active, err := a.IsActive(ctx, candidateA)
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if !active {
		t.Error("IsActive = false, want true")
	}
}

func confIsActiveFalse(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(t)
	mustRegister(t, a, candidateA, subAcme, false)

	active, err := a.IsActive(ctx, candidateA)
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if active {
		t.Error("IsActive = true, want false — a known-inactive account reports false, not an error")
	}
}

func confIsActiveUnknown(t *testing.T, f adapterFactory) {
	a := f.new(t)
	_, err := a.IsActive(context.Background(), candidateA)
	if !errors.Is(err, sor.ErrAccountNotFound) {
		t.Fatalf("IsActive(unknown) = %v, want ErrAccountNotFound", err)
	}
}

// confIsActiveEmptyBillingRef: an empty billing_ref cannot identify an account,
// so it is rejected as invalid input — distinct from an unknown ref, which is
// ErrAccountNotFound.
func confIsActiveEmptyBillingRef(t *testing.T, f adapterFactory) {
	a := f.new(t)
	_, err := a.IsActive(context.Background(), "")
	if !errors.Is(err, sor.ErrBillingRefRequired) {
		t.Fatalf("IsActive(\"\") = %v, want ErrBillingRefRequired", err)
	}
}

// confEmptySubdomain: an empty subdomain is rejected and nothing is persisted.
func confEmptySubdomain(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(t)

	_, err := a.OnRegister(ctx, sor.OnRegisterRequest{
		BillingRef: candidateA, Subdomain: "", Active: true,
	})
	if !errors.Is(err, sor.ErrSubdomainRequired) {
		t.Fatalf("OnRegister(empty subdomain) = %v, want ErrSubdomainRequired", err)
	}
	if _, err := a.IsActive(ctx, candidateA); !errors.Is(err, sor.ErrAccountNotFound) {
		t.Errorf("IsActive after rejected register = %v, want ErrAccountNotFound (no side effect)", err)
	}
}

func confEmptyBillingRef(t *testing.T, f adapterFactory) {
	a := f.new(t)
	_, err := a.OnRegister(context.Background(), sor.OnRegisterRequest{
		BillingRef: "", Subdomain: subAcme, Active: true,
	})
	if !errors.Is(err, sor.ErrBillingRefRequired) {
		t.Fatalf("OnRegister(empty billing_ref) = %v, want ErrBillingRefRequired", err)
	}
}

func mustRegister(t *testing.T, a sor.Adapter, billingRef, subdomain string, active bool) {
	t.Helper()
	if _, err := a.OnRegister(context.Background(), sor.OnRegisterRequest{
		BillingRef: billingRef, Subdomain: subdomain, Active: active,
	}); err != nil {
		t.Fatalf("OnRegister(%q): %v", subdomain, err)
	}
}
