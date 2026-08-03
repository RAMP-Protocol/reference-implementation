//go:build integration

package service

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service/servicetest"
)

const feeTestTenantID = "t1"

// setupFeeTest brings up a migrated testcontainer Postgres and seeds the tenant
// prerequisite, returning the sqlc querier (for the fixture mutators) and the
// tenant id. Shared by the resolution and negative tests.
func setupFeeTest(t *testing.T) (context.Context, sqlc.Querier, string) {
	t.Helper()
	ctx := context.Background()
	pool := servicetest.AcquireTestDB(t, ctx)
	q := sqlc.New(pool)
	// pt9 documented corner: no public tenant-provisioning RPC exists yet, so the
	// tenant prerequisite is seeded via the sqlc InsertTenant query (the same
	// surface sibling Exchange tests use), not a raw SQL string.
	if _, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID: feeTestTenantID, Domain: "publisher.example", HmacSecretRef: "h", Ed25519KeyRef: "k",
		ReportingPolicy: []byte(`{}`), SigningScheme: sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return ctx, q, feeTestTenantID
}

// TestFeeRateResolutionPersists drives the commission-rate resolution through the
// production repository surfaces against a real Postgres: a per-(tenant, owner)
// override wins, and an owner with no override row falls back to the tenant
// default.
//
// The resolved rate has no public read RPC — it is a server-side commercial term,
// never on the wire (ADR-010: reporting reads accrued revenue by resource_owner_id
// via the future RevenueReport surface, and the rate is only observable end-to-end
// through the posted settlement split, not directly). Reading it back through
// FeeOverrideRepo + TenantReadRepo and resolving with the production ResolveFeeRateBps
// is the sanctioned Testing Doctrine §9 tier-2 fallback until that read surface
// exists; the follow-up is the RevenueReport read path (ADR-010 D2). This
// is a persistence round-trip, not a protocol one — the end-to-end "rate rides the
// hold and posts net-of-fee" assertion belongs to the settlement-split slice.
func TestFeeRateResolutionPersists(t *testing.T) {
	ctx, q, tenantID := setupFeeTest(t)
	// Configure a non-zero tenant default via the fixture mutator (column
	// defaults to 0 on insert).
	if _, err := q.SetTenantFeeRateBps(ctx, sqlc.SetTenantFeeRateBpsParams{TenantID: tenantID, FeeRateBps: 250}); err != nil {
		t.Fatalf("set tenant default rate: %v", err)
	}
	feeRepo := repo.NewFeeOverrideRepo(q)
	tenantRepo := repo.NewTenantReadRepo(q)

	// Seed an override for one owner through the repo write surface.
	const ownerWithOverride = "owner-x"
	if err := feeRepo.Set(ctx, tenantID, ownerWithOverride, 1000); err != nil {
		t.Fatalf("seed override: %v", err)
	}

	tenant, err := tenantRepo.ByID(ctx, tenantID)
	if err != nil {
		t.Fatalf("load tenant: %v", err)
	}

	// Override present → override rate wins.
	override, err := feeRepo.ByOwner(ctx, tenantID, ownerWithOverride)
	if err != nil {
		t.Fatalf("ByOwner (with override): %v", err)
	}
	if override == nil {
		t.Fatal("expected an override row for owner-x, got nil")
	}
	if got := ResolveFeeRateBps(tenant.FeeRateBps, override); got != 1000 {
		t.Errorf("override present: resolved rate = %d, want 1000", got)
	}

	// Override absent → tenant default.
	noOverride, err := feeRepo.ByOwner(ctx, tenantID, "owner-without-override")
	if err != nil {
		t.Fatalf("ByOwner (no override): %v", err)
	}
	if noOverride != nil {
		t.Errorf("expected nil override for an unconfigured owner, got %d", *noOverride)
	}
	if got := ResolveFeeRateBps(tenant.FeeRateBps, noOverride); got != 250 {
		t.Errorf("no override: resolved rate = %d, want tenant default 250", got)
	}
}

// TestFeeOverrideRejectsOutOfRange drives an out-of-range rate through the repo
// write surface and asserts the DB CHECK rejection surfaces as ErrFeeRateOutOfRange
// with nothing persisted (Testing Doctrine §10 — the failure path through the same
// surface that owns the write).
func TestFeeOverrideRejectsOutOfRange(t *testing.T) {
	ctx, q, tenantID := setupFeeTest(t)
	feeRepo := repo.NewFeeOverrideRepo(q)

	// 10000 bps (= 100%) violates the CHECK (fee_rate_bps < 10000) at write time.
	const owner = "owner-bad"
	if err := feeRepo.Set(ctx, tenantID, owner, 10000); !errors.Is(err, repo.ErrFeeRateOutOfRange) {
		t.Fatalf("Set(bps=10000) error = %v, want ErrFeeRateOutOfRange", err)
	}

	// No row was persisted by the rejected write.
	got, err := feeRepo.ByOwner(ctx, tenantID, owner)
	if err != nil {
		t.Fatalf("ByOwner after rejected write: %v", err)
	}
	if got != nil {
		t.Errorf("expected no override row after a rejected write, got %d", *got)
	}
}

// TestFeeOverrideTenantIsolation (negative, Testing Doctrine §10) — the fee-override
// lookup is tenant-scoped: an override seeded for (tenantA, owner) must NOT leak into
// tenantB's resolution for the SAME owner. resource_owner_id is a global payee
// namespace — one owner may span tenants (TestPushResources_ResourceOwnerGroupsDomains
// establishes exactly that) — so the tenant predicate in the override query is
// load-bearing: dropping it would misroute money between platform and owner while a
// single-tenant suite stayed green. Seeded through the repo write surface and the sqlc
// InsertTenant query (the same tier-2 fallback the sibling fee tests use — no public
// tenant-provisioning RPC exists yet).
func TestFeeOverrideTenantIsolation(t *testing.T) {
	ctx, q, tenantA := setupFeeTest(t)
	const tenantB = "t2"
	if _, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID: tenantB, Domain: "sibling.example", HmacSecretRef: "h", Ed25519KeyRef: "k",
		ReportingPolicy: []byte(`{}`), SigningScheme: sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	// Distinct tenant defaults so a leak is unambiguous.
	if _, err := q.SetTenantFeeRateBps(ctx, sqlc.SetTenantFeeRateBpsParams{TenantID: tenantA, FeeRateBps: 250}); err != nil {
		t.Fatalf("set tenant A default: %v", err)
	}
	if _, err := q.SetTenantFeeRateBps(ctx, sqlc.SetTenantFeeRateBpsParams{TenantID: tenantB, FeeRateBps: 700}); err != nil {
		t.Fatalf("set tenant B default: %v", err)
	}
	feeRepo := repo.NewFeeOverrideRepo(q)
	tenantRepo := repo.NewTenantReadRepo(q)

	// One owner, override configured ONLY under tenant A.
	const sharedOwner = "owner-shared"
	if err := feeRepo.Set(ctx, tenantA, sharedOwner, 1000); err != nil {
		t.Fatalf("seed override (tenantA, owner): %v", err)
	}

	// Tenant B resolves the SAME owner: no override row for B → tenant B's own
	// default, never tenant A's 1000 override.
	overrideB, err := feeRepo.ByOwner(ctx, tenantB, sharedOwner)
	if err != nil {
		t.Fatalf("ByOwner(tenantB, owner): %v", err)
	}
	if overrideB != nil {
		t.Fatalf("tenant B saw tenant A's override (%d): the lookup is not tenant-scoped", *overrideB)
	}
	tenantBRow, err := tenantRepo.ByID(ctx, tenantB)
	if err != nil {
		t.Fatalf("load tenant B: %v", err)
	}
	if got := ResolveFeeRateBps(tenantBRow.FeeRateBps, overrideB); got != 700 {
		t.Fatalf("tenant B resolved rate = %d, want its own default 700 (not tenant A's 1000)", got)
	}
}
