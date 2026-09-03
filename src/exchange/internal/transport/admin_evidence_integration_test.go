//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// Coverage for GET /ops/transaction-evidence on the internal admin listener.
//
// Every test here buys through the PUBLIC ExecuteTransaction RPC and reads back
// over real HTTP against the admin listener, decoding the body through the same
// internal/evidenceview package the operator tooling decodes it with. Neither leg
// touches the database, so what these tests prove is the round trip an operator
// actually makes: a transaction executed on the agent plane is readable, and
// re-verifiable, on the operator plane.

// evidenceReply is what a test observes from one call to the route: the status,
// the response headers, and the body already read. The whole *http.Response is
// deliberately not carried out of the request helper, so the body is closed in
// the same function that opened it.
type evidenceReply struct {
	status int
	header http.Header
	body   []byte
}

// callEvidence issues one request against the route over real HTTP. rawQuery is
// appended verbatim so a malformed or missing selector can be driven too.
func callEvidence(t *testing.T, h *testHarness, method, baseURL, rawQuery string) evidenceReply {
	t.Helper()
	target := baseURL + transport.TransactionEvidencePath + rawQuery
	req, err := http.NewRequestWithContext(h.ctx, method, target, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return evidenceReply{status: resp.StatusCode, header: resp.Header, body: body}
}

// readEvidence issues the read for one transaction id, requires 200 with the two
// headers the route owes, and decodes and validates the payload.
func readEvidence(t *testing.T, h *testHarness, baseURL, txID string) evidenceview.Response {
	t.Helper()
	reply := callEvidence(t, h, http.MethodGet, baseURL, "?tx="+url.QueryEscape(txID))
	if reply.status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", reply.status, reply.body)
	}
	// Content-Type is asserted because without it net/http sniffs the body and
	// JSON sniffs as text/plain, which would leave the operator tooling decoding
	// a response the server never claimed was JSON.
	if got := reply.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	// no-store because the body carries signatures, public keys and a
	// correlation id; no intermediary may keep a copy.
	if got := reply.header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var view evidenceview.Response
	if err := json.Unmarshal(reply.body, &view); err != nil {
		t.Fatalf("decode body: %v; body = %s", err, reply.body)
	}
	if err := view.Validate(); err != nil {
		t.Fatalf("payload does not validate: %v; body = %s", err, reply.body)
	}
	return view
}

// executeForEvidence buys one offer through the public surface and returns the
// discovered offer plus the result item. The two together are the "what the
// execute leg produced" side of every comparison below.
func executeForEvidence(
	t *testing.T, h *testHarness, reqKey string,
) (offer *rampv1.Offer, item *rampv1.TransactionResultItem) {
	t.Helper()
	seedCatalog(t, h)
	offer = discoverFirst(t, h)[0]
	resp, err := executeSingleItem(t, h, reqKey, offer)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item = singleResultItem(t, resp)
	if item.GetTransactionId() == "" {
		t.Fatalf("execute was denied in-body (reason=%v); want success", item.GetDenialReason())
	}
	return offer, item
}

// TestTransactionEvidence_RoundTripFromExecute is the load-bearing test: a paid
// transaction executed on the agent plane is served back on the operator plane
// with every field matching what the execute leg produced, and the two stored
// signatures still verify against the two stored public keys.
//
// The re-verification is the point. An evidence row is only evidence if a third
// party can check it from the row alone, with no live service and no key
// registry — so the test verifies both signatures the way that third party
// would, over the stored canonical bytes with the stored keys.
func TestTransactionEvidence_RoundTripFromExecute(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")

	const reqKey = "tx-evidence-round-trip"
	offer, item := executeForEvidence(t, h, reqKey)
	view := readEvidence(t, h, baseURL, item.GetTransactionId())

	ev := view.Evidence
	if got, want := ev.TransactionID, item.GetTransactionId(); got != want {
		t.Errorf("evidence transaction_id = %q, want %q", got, want)
	}
	if got, want := ev.TenantID, h.tenantID; got != want {
		t.Errorf("evidence tenant_id = %q, want %q", got, want)
	}
	if got, want := ev.OfferID, offer.GetOfferId(); got != want {
		t.Errorf("evidence offer_id = %q, want %q", got, want)
	}
	// The stored signature is the one the discover leg handed out, byte for byte.
	if got, want := ev.OfferSig, offer.GetSignature(); got != want {
		t.Errorf("evidence offer_sig = %q, want the discovered offer's %q", got, want)
	}
	// request_idempotency_key is the REQUEST-level key the acceptance signed, not
	// the per-item key the transaction log stores.
	if got, want := ev.RequestIdempotencyKey, reqKey; got != want {
		t.Errorf("evidence request_idempotency_key = %q, want %q", got, want)
	}
	if got, want := ev.RequesterID, "agent-test"; got != want {
		t.Errorf("evidence requester_id = %q, want %q", got, want)
	}
	if got, want := ev.RequesterDomain, "agent.example"; got != want {
		t.Errorf("evidence requester_domain = %q, want %q", got, want)
	}

	assertOfferSignatureVerifies(t, ev)
	assertAcceptanceVerifies(t, h, ev)

	// The delivery join: the transaction state carries the SHA-256 of the very
	// URL the execute leg returned, which is what lets a delivery record be
	// matched to this transaction without either side carrying a transaction id.
	// The URL itself is deliberately not served — on the CloudFront-RSA path it
	// is a live bearer capability until it expires.
	state := view.TransactionState
	wantDigest := sha256.Sum256([]byte(item.GetRetrievalEndpoint()))
	if string(state.SignedURLHash) != string(wantDigest[:]) {
		t.Errorf("transaction_state signed_url_hash = %x, want the digest of the returned URL %x",
			state.SignedURLHash, wantDigest)
	}
	if got, want := state.IdempotencyKey, derivedTxKey(reqKey, offer); got != want {
		t.Errorf("transaction_state idempotency_key = %q, want the per-item key %q", got, want)
	}
	if state.SignedURLExpiry == nil {
		t.Error("transaction_state signed_url_expiry is absent; a paid delivery URL always expires")
	}
	if strings.Contains(string(mustMarshal(t, view)), item.GetRetrievalEndpoint()) {
		t.Error("the response carries the full signed URL, which is a live bearer capability")
	}

	assertUnreportedObligation(t, view.ObligationState)
}

// assertUnreportedObligation asserts the obligation as it stands immediately
// after an execute: minted, pending, and carrying nothing a report would fill in.
func assertUnreportedObligation(t *testing.T, ob *evidenceview.ObligationState) {
	t.Helper()
	if ob == nil {
		t.Fatal("obligation_state is absent; a metered term mints an obligation")
	}
	if got, want := ob.State, "PENDING"; got != want {
		t.Errorf("obligation state = %q, want %q", got, want)
	}
	// Absent, not zero: the field is optional precisely so "no report yet" is
	// distinguishable from "a report of zero units", which is a legitimate value.
	if ob.ConsumedQuantity != nil {
		t.Errorf("obligation consumed_quantity = %q, want absent before any report", *ob.ConsumedQuantity)
	}
	if ob.FulfilledAt != nil {
		t.Error("obligation fulfilled_at is set before any report was accepted")
	}
}

// TestTransactionEvidence_ReflectsAcceptedReport proves the read serves the
// obligation as it stands now rather than as it stood at execute: after a usage
// report is accepted through the public ReportUsage RPC, the same operator read
// shows the obligation received and carrying the reported quantity.
func TestTransactionEvidence_ReflectsAcceptedReport(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")

	txID, billingID := executeTransactionFor(t, h, 100)
	if _, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-evidence-1", txID, billingID, &rampv1.Usage{ConsumedQuantity: 100}))); err != nil {
		t.Fatalf("report usage: %v", err)
	}

	ob := readEvidence(t, h, baseURL, txID).ObligationState
	// The persisted vocabulary is served verbatim, with no mapping, so the
	// rendered word cannot differ from the row under dispute.
	if got, want := ob.State, "RECEIVED"; got != want {
		t.Errorf("obligation state after an accepted report = %q, want %q", got, want)
	}
	if ob.ConsumedQuantity == nil {
		t.Fatal("obligation consumed_quantity is absent after an accepted report")
	}
	// The column is NUMERIC(20,8) and the quantity is carried as a decimal
	// string, so the served value keeps whatever scale the store wrote.
	if got := *ob.ConsumedQuantity; !strings.HasPrefix(got, "100") {
		t.Errorf("obligation consumed_quantity = %q, want the reported 100", got)
	}
	if ob.FulfilledAt == nil {
		t.Error("obligation fulfilled_at absent after an accepted report")
	}
}

// TestTransactionEvidence_FreePathTransaction drives a zero-cost execute, which
// engages none of the billing lifecycle, and proves its evidence still reads back
// whole.
//
// A transaction that minted NO obligation is reachable through the public
// surface: a term whose pricing meters nothing owes no usage report and writes no
// obligation row. This test does not arrange that shape — it is about the free
// path, which still mints one — and the handler's nil-obligation branch is driven
// end to end by the metering-NONE case in the reporting-gate suite, which reads
// this same route back and requires obligation_state to be absent.
func TestTransactionEvidence_FreePathTransaction(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")

	offer := pushDiscoverTermOffer(t, h, "/articles/free-evidence", seedFreeTerm())
	if got := offer.GetPricing().GetModel(); got != rampv1.PricingModel_PRICING_MODEL_FREE {
		t.Fatalf("discovered offer pricing model = %v, want FREE", got)
	}
	resp, err := executeOfferRaw(t, h, offer)
	if err != nil {
		t.Fatalf("execute free offer: %v", err)
	}
	item := singleResultItem(t, resp)

	view := readEvidence(t, h, baseURL, item.GetTransactionId())
	if got, want := view.Evidence.OfferID, offer.GetOfferId(); got != want {
		t.Errorf("evidence offer_id = %q, want %q", got, want)
	}
	assertOfferSignatureVerifies(t, view.Evidence)
	assertAcceptanceVerifies(t, h, view.Evidence)
	// A free delivery is still a signed delivery, so the join to what the edge
	// served exists here exactly as it does on the paid path.
	if len(view.TransactionState.SignedURLHash) == 0 {
		t.Error("transaction_state signed_url_hash is absent on a free-path delivery")
	}
	if view.ObligationState == nil {
		t.Error("obligation_state is absent; a free transaction mints one too")
	}
}

// TestTransactionEvidence_Refusals drives every rejection through the same HTTP
// surface the success path uses.
//
// The 500 case in the route's contract is not here and cannot be: an evidence row
// whose transaction_log row is missing is what it reports, and
// ramp.transaction_evidence.transaction_id is a primary key referencing
// ramp.transaction_log with ON DELETE RESTRICT, so that state cannot exist. The
// branch stays in the handler as defensive code — a read that finds one half of
// the pair must not render half a chain.
func TestTransactionEvidence_Refusals(t *testing.T) {
	h := newTestHarness(t)
	_, baseURL := startAdminServer(t, h, "127.0.0.0/8")

	// A real transaction, so the unknown-id case below is a miss on the lookup
	// rather than a miss on an empty table.
	executeForEvidence(t, h, "tx-evidence-refusals")

	cases := []struct {
		name     string
		query    string
		want     int
		wantBody string // "" when the body is net/http's, not the handler's
	}{
		{
			name: "no tx parameter", query: "", want: http.StatusBadRequest,
			wantBody: "query parameter tx must be a transaction id",
		},
		{
			name: "empty tx parameter", query: "?tx=", want: http.StatusBadRequest,
			wantBody: "query parameter tx must be a transaction id",
		},
		{
			// transaction_id is a server-minted UUID, so a value that is not one
			// cannot name a row and is refused before any lookup runs.
			name: "malformed tx parameter", query: "?tx=not-a-transaction-id", want: http.StatusBadRequest,
			wantBody: "query parameter tx must be a transaction id",
		},
		{
			name: "well-formed tx that was never executed", query: "?tx=" + neverExecutedTxID,
			want: http.StatusNotFound, wantBody: "no evidence for that transaction",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply := callEvidence(t, h, http.MethodGet, baseURL, tc.query)
			if reply.status != tc.want {
				t.Fatalf("status = %d, want %d; body = %s", reply.status, tc.want, reply.body)
			}
			if !strings.Contains(string(reply.body), tc.wantBody) {
				t.Errorf("body = %q, want it to contain %q", reply.body, tc.wantBody)
			}
		})
	}

	// The method is part of the route pattern, so net/http refuses anything but
	// GET before the handler runs. The body is net/http's own text and is not
	// asserted; the status and the Allow header are what the route owes.
	t.Run("POST is refused", func(t *testing.T) {
		reply := callEvidence(t, h, http.MethodPost, baseURL, "?tx="+neverExecutedTxID)
		if reply.status != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", reply.status)
		}
		if got := reply.header.Get("Allow"); !strings.Contains(got, http.MethodGet) {
			t.Errorf("Allow = %q, want it to name GET", got)
		}
	})
}

// neverExecutedTxID is a syntactically valid transaction id that no execute can
// have minted, so it separates "you asked wrongly" (400) from "nothing matched"
// (404).
const neverExecutedTxID = "00000000-0000-4000-8000-000000000000"

// mustMarshal re-encodes a decoded response so a test can assert on what the
// payload does NOT contain.
func mustMarshal(t *testing.T, view evidenceview.Response) []byte {
	t.Helper()
	b, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// assertOfferSignatureVerifies re-runs the Exchange's offer signature the way an
// auditor holding only this row would: over the stored canonical bytes, with the
// stored public key.
func assertOfferSignatureVerifies(t *testing.T, ev *evidenceview.Evidence) {
	t.Helper()
	sig, err := hex.DecodeString(ev.OfferSig)
	if err != nil {
		t.Fatalf("stored offer_sig is not hex: %v", err)
	}
	if len(ev.ExchangeSigningPublicKey) != ed25519.PublicKeySize {
		t.Fatalf("stored exchange_signing_public_key is %d bytes, want %d",
			len(ev.ExchangeSigningPublicKey), ed25519.PublicKeySize)
	}
	if !ed25519.Verify(ev.ExchangeSigningPublicKey, ev.OfferCanonicalBytes, sig) {
		t.Error("the stored offer signature does not verify over the stored canonical bytes with the\n" +
			"stored key — the evidence row cannot be checked without a live service, which is the\n" +
			"one property it exists to provide")
	}
	if got, want := ev.OfferSigAlgorithm, "EdDSA"; got != want {
		t.Errorf("offer_sig_algorithm = %q, want %q", got, want)
	}
}

// assertAcceptanceVerifies does the same for the agent's acceptance, and pins
// that the stored key is the one the executing agent actually holds.
func assertAcceptanceVerifies(t *testing.T, h *testHarness, ev *evidenceview.Evidence) {
	t.Helper()
	sig, err := hex.DecodeString(ev.AgentAcceptanceSignature)
	if err != nil {
		t.Fatalf("stored agent_acceptance_signature is not hex: %v", err)
	}
	if string(ev.AgentPublicKey) != string(h.callerPub) {
		t.Error("stored agent_public_key is not the executing agent's key")
	}
	if !ed25519.Verify(ev.AgentPublicKey, ev.AgentAcceptanceCanonicalBytes, sig) {
		t.Error("the stored acceptance signature does not verify over the stored canonical bytes with\n" +
			"the stored agent key")
	}
	if got, want := ev.AgentAcceptanceSignatureAlgorithm, "EdDSA"; got != want {
		t.Errorf("agent_acceptance_signature_algorithm = %q, want %q", got, want)
	}
}
