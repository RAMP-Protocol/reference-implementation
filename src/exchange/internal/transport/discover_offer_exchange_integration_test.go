//go:build integration

package transport_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// TestDiscover_OfferCarriesSignedExchangeDomain pins step 1 of the signed-exchange-domain routing contract: the
// Exchange populates Offer.exchange with its configured canonical domain BEFORE
// signing, so the field falls inside the signed offer payload
// (helpers.canonicalOfferPayload covers the whole Offer minus
// signature/signature_algorithm). The broker derives the execute-routing target
// from this signed field, retiring the X-RAMP-Exchange-Endpoint header.
//
// Round-trip: the offer is produced and read through the public
// CatalogService.PushResources → ExchangeService.DiscoverResources surface; the
// signature is then validated through the public ExecuteTransaction surface
// (which runs helpers.VerifyPresentedOffer against the presented bytes),
// proving the signature now covers offer.exchange. No raw DB / sqlc access.
func TestDiscover_OfferCarriesSignedExchangeDomain(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/exch-domain", "0.05")

	offer := discoverOfferForURI(t, h, uri)

	// The configured canonical domain wired in startExchangeServer
	// (ExchangeConfig{Exchange: "exchange.ramp.test"}).
	const wantDomain = "exchange.ramp.test"
	if got := offer.GetExchange(); got != wantDomain {
		t.Fatalf("offer.exchange = %q, want %q", got, wantDomain)
	}
	if offer.GetSignature() == "" || offer.GetSignatureAlgorithm() != "EdDSA" {
		t.Fatalf("offer not signed: %+v", offer)
	}

	// VerifyPresentedOffer still passes: the genuine offer (carrying
	// offer.exchange) is accepted by ExecuteTransaction, which verifies the
	// presented signature server-side.
	const txID = "tx-exch-domain-ok"
	if _, err := executePresented(t, h, txID, offer.GetOfferId(), offer); err != nil {
		t.Fatalf("execute genuine offer with exchange field: %v", err)
	}
	// The items[] path persists under the DERIVED key idempotency_key:offer_id.
	assertTransactionLogged(t, h.ctx, h, derivedTxKey(txID, offer))
}

// TestDiscover_TamperedExchangeDomainRejected proves offer.exchange is covered
// by the signature: mutating it after signing makes the presented bytes diverge
// from what the Exchange signed, so ExecuteTransaction's VerifyPresentedOffer
// rejects the offer with SIGNATURE_INVALID and persists no transaction. This is
// the security guarantee that lets the broker route from the signed field — a
// rogue caller cannot rewrite the routing target without breaking the signature.
func TestDiscover_TamperedExchangeDomainRejected(t *testing.T) {
	h := newTestHarness(t)
	uri := seedResourceWithRate(t, h, "/articles/exch-tamper", "0.05")
	offer := discoverOfferForURI(t, h, uri)

	tampered, ok := proto.Clone(offer).(*rampv1.Offer)
	if !ok {
		t.Fatal("clone offer")
	}
	// Repoint the signed routing target at an attacker-chosen Exchange domain.
	// The signature was computed over "exchange.ramp.test".
	tampered.Exchange = "evil.exchange.test"

	const txID = "tx-exch-tampered"
	resp, err := executePresented(t, h, txID, tampered.GetOfferId(), tampered)
	// A tampered signed field → SIGNATURE_INVALID, a denial-map kind → in-body
	// per-item denial after the C4 items-only collapse (Flag #1).
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)
	assertNoTransaction(t, h, derivedTxKey(txID, tampered))
}
