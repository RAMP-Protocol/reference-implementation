//go:build integration

package repo_test

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestCatalogUpsert_URIMoveRefused pins the DATABASE backstop for catalog URI
// immutability. The service precheck (rejectURIConflicts) rejects a URI move
// before the write, so the guarded upsert — DO UPDATE suppressed when the
// existing row holds a different uri — is reachable only in the race window
// between that read and the commit. No RPC can drive that window
// deterministically, which is why this test stays at the repository tier: it
// arranges and asserts through the production CatalogRepo surface and proves
// the write itself refuses the move even with the precheck out of the picture.
//
// The tenant seed uses sqlc InsertTenant — the same held-open arrange as the
// package's other tests: no production code inserts tenants (operator SQL
// provisions them), so a repository insert port would exist only for tests.
// Converting these arrange sites behind a real tenant-provisioning surface is
// filed as its own task.
func TestCatalogUpsert_URIMoveRefused(t *testing.T) {
	ctx := context.Background()
	pool := newTestPool(t, ctx)
	q := sqlc.New(pool)
	const tenantID = "t-uri-immutable"
	if _, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID: tenantID, Domain: "uri-immutable.example", Ed25519KeyRef: "k",
		ReportingPolicy: []byte(`{}`), SigningScheme: sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	catalog := repo.NewCatalogRepo(q)

	entry := repo.CatalogEntry{
		ResourceID:      tenantID + ":mover",
		TenantID:        tenantID,
		URI:             "https://uri-immutable.example/articles/old",
		URIPrefix:       "https://uri-immutable.example/articles/old",
		PricingJSON:     []byte(`{}`),
		DeliveryMethod:  "INSTRUCTIONS",
		ResourceOwnerID: "owner-1",
	}
	if _, err := catalog.Upsert(ctx, entry); err != nil {
		t.Fatalf("initial upsert: %v", err)
	}

	// Same resource, same URI: mutable fields still update in place.
	title := "renamed"
	retitled := entry
	retitled.Title = &title
	if _, err := catalog.Upsert(ctx, retitled); err != nil {
		t.Fatalf("same-URI re-upsert: %v", err)
	}

	// Same resource, DIFFERENT URI: the guarded DO UPDATE yields no row and the
	// repo surfaces the immutability error.
	moved := retitled
	moved.URI = "https://uri-immutable.example/articles/new"
	moved.URIPrefix = moved.URI
	if _, err := catalog.Upsert(ctx, moved); !errors.Is(err, repo.ErrCatalogURIImmutable) {
		t.Fatalf("URI-move upsert error = %v, want repo.ErrCatalogURIImmutable", err)
	}

	// The stored row is untouched by the refused move: URI unchanged, and the
	// same-URI update above (the title) survived.
	got, err := catalog.ByID(ctx, entry.ResourceID)
	if err != nil {
		t.Fatalf("ByID after refused move: %v", err)
	}
	if got.URI != entry.URI {
		t.Errorf("stored URI = %q, want %q (refused move must not change it)", got.URI, entry.URI)
	}
	if got.Title == nil || *got.Title != title {
		t.Errorf("stored title = %v, want %q (same-URI update must persist)", got.Title, title)
	}
}
