//go:build integration

package transport_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestDiscoverResources_MintsUniqueOfferIDs pins the offer_id contract: each
// issued offer carries a freshly minted random UUID v4, decoupled from the
// resource. Two discoveries of the SAME URL therefore return different
// offer_ids — the property that keeps batch correlation, per-item replay keys
// (idempotency_key + offer_id), and audit rows distinct when the same resource
// is bought twice through separately issued offers.
func TestDiscoverResources_MintsUniqueOfferIDs(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)

	first := discoverFirst(t, h)[0].GetOfferId()
	second := discoverFirst(t, h)[0].GetOfferId()

	for _, id := range []string{first, second} {
		u, err := uuid.Parse(id)
		if err != nil {
			t.Fatalf("offer_id %q does not parse as a UUID: %v", id, err)
		}
		if u.Version() != 4 {
			t.Errorf("offer_id %q is UUID version %d, want 4 (random)", id, u.Version())
		}
	}
	if first == second {
		t.Errorf("two discoveries of the same URL returned the same offer_id %q; each issued offer must mint its own", first)
	}
}
