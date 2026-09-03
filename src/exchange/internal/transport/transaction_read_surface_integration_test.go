//go:build integration

package transport_test

import (
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// TestTransactionReadSurface_ByID proves the production read surface added for
// a transaction created through the ExecuteTransaction RPC is
// observable by its public transaction_id through repo.TransactionRepo.ByID —
// the documented tier-2 surface (Testing Doctrine pt9) that remediated tests
// assert through instead of a raw transaction_log SELECT. The arrange side
// drives the full push -> discover -> execute chain through the public RPCs;
// only the read-back uses the repository interface (no raw sqlc/SQL).
//
// This is the public read surface that transaction-by-id assertions route through.
func TestTransactionReadSurface_ByID(t *testing.T) {
	h := newTestHarness(t)
	ctx := h.ctx

	unit := "accesses"
	if _, err := h.catalogClient.PushResources(ctx, connect.NewRequest(newPushRequest(h.tenantID, "agent-test", []*rampv1.ResourceEntry{{
		Domain: h.tenantDomain,
		Path:   "/articles/read-surface",
		Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing: &rampv1.Pricing{
				Model:    rampv1.PricingModel_PRICING_MODEL_PER_UNIT,
				Rate:     "0.05",
				Currency: "USD",
				Unit:     &unit,
			},
		}},
	}}))); err != nil {
		t.Fatalf("push: %v", err)
	}

	discovered, err := h.exchangeClient.DiscoverResources(ctx, connect.NewRequest(newResourceQuery(newRequester("agent-test", "agent.example"), []string{"https://" + h.tenantDomain + "/articles/read-surface"})))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	offers := discovered.Msg.GetOffers()
	if len(offers) != 1 {
		t.Fatalf("offers = %d, want 1", len(offers))
	}
	offer := offers[0]

	execResp, err := executeSingleItem(t, h, "tx-read", offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	txID := singleResultItem(t, execResp).GetTransactionId()
	if txID == "" {
		t.Fatal("transaction id empty")
	}

	// Read-back through the production repository surface — NOT a raw
	// transaction_log SELECT (Testing Doctrine pt9).
	txRepo := repo.NewTransactionRepo(h.queries)
	rec, err := txRepo.ByID(ctx, txID)
	if err != nil {
		t.Fatalf("TransactionRepo.ByID(%q): %v", txID, err)
	}
	if rec.TransactionID != txID {
		t.Errorf("transaction_id = %q, want %q", rec.TransactionID, txID)
	}
	if rec.TenantID != h.tenantID {
		t.Errorf("tenant_id = %q, want %q (the returned record carries tenant for the caller to scope/assert)", rec.TenantID, h.tenantID)
	}
	if rec.AgentID != "agent-test" {
		t.Errorf("agent_id = %q, want agent-test", rec.AgentID)
	}

	// Negative: an unknown id maps to the typed not-found error, never a
	// zero-value record masquerading as a hit.
	if _, err := txRepo.ByID(ctx, "tx-does-not-exist"); !errors.Is(err, repo.ErrTransactionNotFound) {
		t.Fatalf("ByID(unknown) err = %v, want ErrTransactionNotFound", err)
	}
}
