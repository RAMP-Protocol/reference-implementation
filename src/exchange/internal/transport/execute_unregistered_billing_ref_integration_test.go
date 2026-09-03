//go:build integration

package transport_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Negative + free-path coverage for the billing_ref repoint: a PAID
// transaction from an agent that never registered has no account to charge, so it
// is denied before Authorize; a FREE transaction from the same unregistered agent
// still succeeds because the free path bypasses billing entirely.

// TestExecuteTransaction_UnregisteredAgentPaidDenied drives a PAID transaction
// from an agent whose agents row carries no billing_ref (the skipRegister harness).
// The service denies it BEFORE Authorize (ADR-021 D5 / decision D1): the item is
// denied in-body with DENIAL_REASON_ACCOUNT_NOT_REGISTERED, no transaction row is
// persisted, and no billing hold is taken (Authorize is never reached).
func TestExecuteTransaction_UnregisteredAgentPaidDenied(t *testing.T) {
	h, rec := newRecordingHarnessWith(t, harnessOptions{skipRegister: true})
	seedCatalog(t, h)
	offer := discoverFirst(t, h)[0]

	const idem = "tx-unregistered-paid"
	resp, err := executeSingleItem(t, h, idem, offer)
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_ACCOUNT_NOT_REGISTERED)

	// No side effect: the denial persisted no transaction_log row (same tier-2
	// repo read the sibling negative tests use — no public transaction-read RPC
	// yet).
	assertNoTransaction(t, h, derivedTxKey(idem, offer))

	// No hold taken: the paid path denied before Authorize, so the billing adapter
	// saw nothing. Observed through the recordingAdapter surface the sibling
	// lifecycle tests use.
	assertNoBillingHold(t, rec, "an unregistered agent")
}

// TestExecuteTransaction_UnregisteredAgentFreeSucceeds proves the free path is
// unaffected by the billing_ref repoint: an agent with no billing_ref (skipRegister)
// still gets a FREE resource. The pricing.IsFree() bypass runs before the
// registration check, so an empty ref is never consulted and no billing lifecycle
// engages.
func TestExecuteTransaction_UnregisteredAgentFreeSucceeds(t *testing.T) {
	h, rec := newRecordingHarnessWith(t, harnessOptions{skipRegister: true})
	offer := pushDiscoverTermOffer(t, h, "/articles/free", seedFreeTerm())
	if got := offer.GetPricing().GetModel(); got != rampv1.PricingModel_PRICING_MODEL_FREE {
		t.Fatalf("discovered offer pricing model = %v, want FREE", got)
	}

	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer for unregistered agent: %v", err)
	}
	item := singleResultItem(t, resp)
	if itemSignedURL(t, resp) == "" {
		t.Error("free path for an unregistered agent returned no signed URL")
	}
	if got := item.GetBillingId(); got != "" {
		t.Errorf("wire billing_id present (%q) on the free path; want omitted", got)
	}

	// The billing adapter saw nothing: no Authorize, Record, or Release.
	assertBillingLifecycle(t, rec, false, 0, 0)
}
