//go:build integration

package transport_test

import (
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceclient"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/transactionkey"
)

// The operator ledger's fetch path, driven against the real admin handler.
//
// The sibling round-trip test reads the route with a hand-built request and
// decodes the body itself. This one reads it the way the shipped tool does: the
// same evidenceclient.Fetch the ramp-ledger binary calls, against the same
// WrapAdminSurface the server builds, over a transaction really executed through
// the public RPC. Nothing stands in for either side.
//
// WHAT THIS PROVES, precisely. The producer's projection functions really
// populate every field the consumer reads, the route answers on the path both
// sides take from one constant, the status and headers are what the client
// expects, and Validate passes on a payload the Exchange actually produced. A
// projection that forgot a field, or a handler that answered on another path,
// fails here.
//
// WHAT IT DOES NOT PROVE, checked rather than assumed: it does not catch a JSON
// TAG change. Producer and consumer share internal/evidenceview, so renaming a
// tag moves both sides together and this test still passes — verified by
// renaming offer_canonical_bytes and watching it stay green. The wire key names
// are pinned instead by TestEncodingIsBase64BytesAndRFC3339Timestamps in
// internal/evidenceview, which asserts the literal JSON keys and does fail on
// that rename. The two tests cover different halves; neither replaces the other.
//
// The fetch lives in a package outside both service trees because the CLI's own
// package is `main` and cannot be imported, so no test elsewhere could otherwise
// drive the shipped read path.
func TestEvidenceClient_FetchesThroughTheRealAdminHandler(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")

	const reqKey = "tx-evidence-client-fetch"
	offer, item := executeForEvidence(t, h, reqKey)

	// The shipped read path: build the URL, GET, check the status, decode, and
	// Validate. A failure here is a real wire-format disagreement, not a
	// decoding choice made by the test.
	view, err := evidenceclient.Fetch(h.ctx, baseURL, item.GetTransactionId(), 30*time.Second)
	if err != nil {
		t.Fatalf("Fetch through the real admin handler: %v", err)
	}

	// Validate already ran inside Fetch, so Evidence and TransactionState are
	// non-nil. Asserting the VALUES is the point: Validate checks a handful of
	// members are present, so a projection that dropped one of these would leave
	// a zero value Validate accepts and the chain would render it as a fact.
	ev := view.Evidence
	if got, want := ev.TransactionID, item.GetTransactionId(); got != want {
		t.Errorf("transaction_id did not survive the wire: %q, want %q", got, want)
	}
	if got, want := ev.TenantID, h.tenantID; got != want {
		t.Errorf("tenant_id did not survive the wire: %q, want %q", got, want)
	}
	if got, want := ev.OfferID, offer.GetOfferId(); got != want {
		t.Errorf("offer_id did not survive the wire: %q, want %q", got, want)
	}
	if got, want := ev.RequestIdempotencyKey, reqKey; got != want {
		t.Errorf("request idempotency key did not survive the wire: %q, want %q", got, want)
	}

	// The byte-slice fields fail most quietly: they decode from base64, so a
	// projection that never set one leaves it empty rather than wrong, and an
	// empty signature reads to the renderer as "nothing to verify".
	if len(ev.OfferCanonicalBytes) == 0 {
		t.Error("offer canonical bytes came back empty; the chain would have nothing to re-verify")
	}
	if len(ev.ExchangeSigningPublicKey) == 0 {
		t.Error("exchange signing public key came back empty; the chain could not check the offer signature")
	}
	if len(ev.AgentAcceptanceCanonicalBytes) == 0 {
		t.Error("agent acceptance canonical bytes came back empty")
	}
	if len(ev.AgentPublicKey) == 0 {
		t.Error("agent public key came back empty")
	}
	if ev.OfferSig == "" {
		t.Error("offer signature came back empty")
	}

	// The transaction-log key the ledger asserts on, derived here the same way
	// the Exchange derived it when it wrote the row. This is the one assertion
	// the renderer makes that depends on two binaries agreeing about a string,
	// so proving it across a real request is worth more than proving it in the
	// renderer's own unit test.
	wantKey := transactionkey.DerivedItemKey(reqKey, offer.GetOfferId())
	if got := view.TransactionState.IdempotencyKey; got != wantKey {
		t.Errorf("transaction-log key = %q, want %q — the ledger's key assertion would report FAILED",
			got, wantKey)
	}
	if len(view.TransactionState.SignedURLHash) == 0 {
		t.Error("signed URL hash came back empty; the delivery leg joins on it")
	}
}

// A transaction id that names no row must reach the caller as an error carrying
// the status, not as an empty chain.
//
// Fetch validates the decoded payload, so the danger is the opposite of a decode
// failure: a 404 body that happened to parse would produce a Response with nil
// members, and a renderer that trusted it would describe a transaction that does
// not exist. The status check is what stops that, and this drives it through the
// real handler's own 404.
func TestEvidenceClient_UnknownTransactionIsAnError(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")

	view, err := evidenceclient.Fetch(h.ctx, baseURL,
		"00000000-0000-4000-8000-000000000000", 30*time.Second)
	if err == nil {
		t.Fatalf("Fetch accepted a transaction that does not exist and returned %+v", view)
	}
	if view != nil {
		t.Errorf("Fetch returned both an error and a payload: %+v", view)
	}
}
