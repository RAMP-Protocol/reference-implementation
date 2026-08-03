//go:build integration

package transport_test

import (
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// Negative-path coverage for the Exchange RPCs. Each behaviour with a
// meaningful failure mode is driven through the
// SAME public Connect-Go surface that owns it and asserted back through that
// surface (Testing Doctrine §10: correct connect.Code AND absence of side
// effect). The guards under test all live in the service layer; protovalidate
// owns none of THESE messages (its buf.validate rules cover Pricing and
// restriction-token format — exercised in catalog_protovalidate_e2e_test.go —
// not the requester/uri/offer presence checks here), so the textual field
// detail is stable and pinned via assertConnectError.

// execTxNegReq builds an items[] TransactionRequest for the negative cases (the
// items-only contract after the C4 collapse). A shared builder keeps the
// near-identical literals out of every case (jscpd). The single item carries the
// offer; callers set its agent_acceptance when the case needs to clear the
// envelope presence checks and reach the offer-signature verify.
func execTxNegReq(id, offerID, sig string, requester *rampv1.Requester) *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{
		Ver:            "1.0",
		IdempotencyKey: id,
		Requester:      requester,
		// the offer signature rides on the reflected full Offer. An empty
		// sig leaves the offer signature empty (the validateBatchRequest per-item
		// guard case).
		Items: []*rampv1.TransactionItem{
			{Offer: &rampv1.Offer{OfferId: offerID, Signature: sig}},
		},
	}
}

// negItemOffer returns the offer carried on the single item of an execTxNegReq
// request, for cases that need to sign a body acceptance over it.
func negItemOffer(req *rampv1.TransactionRequest) *rampv1.Offer {
	return req.GetItems()[0].GetOffer()
}

// setNegItemAcceptance attaches a body acceptance to the single item.
func setNegItemAcceptance(req *rampv1.TransactionRequest, acc *rampv1.AgentAcceptance) {
	req.GetItems()[0].AgentAcceptance = acc
}

func agentRequester(id string) *rampv1.Requester {
	return &rampv1.Requester{
		Id:     id,
		Domain: "agent.example",
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
}

// ── DiscoverResources input validation (service/exchange.go:137-145) ──────────

func TestDiscoverResources_NilRequesterRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver: "1.0", Requester: nil,
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "requester required")
	// Every DiscoverResources fault carries the ExchangeService domain
	// stamp (ADR-019 §1), read through the public Connect error envelope.
	assertErrorDomain(t, err, "ramp.v1.ExchangeService")
}

func TestDiscoverResources_EmptyRequesterIDRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{"https://" + h.tenantDomain + "/articles/hello"},
		Requester: &rampv1.Requester{
			Id: "", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "requester.id required")
	// Every DiscoverResources fault carries the ExchangeService domain stamp.
	assertErrorDomain(t, err, "ramp.v1.ExchangeService")
}

func TestDiscoverResources_NoURIsRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: nil,
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example", Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "at least one uri required")
	// Every DiscoverResources fault carries the ExchangeService domain stamp.
	assertErrorDomain(t, err, "ramp.v1.ExchangeService")
}

// ── ExecuteTransaction validation + not-found (validateTxRequest / resolveOfferForTx) ──

// Empty offer_signature hits the validateTxRequest envelope guard
// (exchange_helpers.go) — InvalidArgument, NOT Unauthenticated. A non-empty WRONG
// signature is the VerifyPresentedOffer path, covered by
// TestExecuteTransaction_SignatureInvalid. Under the presented-offer contract
// the top-level offer_id is OPTIONAL correlation, so the guard requires
// only the offer signature's presence.
func TestExecuteTransaction_EmptyOfferSignatureRejected(t *testing.T) {
	h := newTestHarness(t)
	// Empty offer signature → validateBatchRequest per-item envelope guard
	// (KindInvalidRequest, not in the denial map) → CodeInvalidArgument abort.
	_, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(
		execTxNegReq("tx-empty-sig", "some-offer", "", agentRequester("agent-test")),
	))
	assertConnectError(t, err, connect.CodeInvalidArgument, "offer signature required")
	// A non-denial ExecuteTransaction fault (the txDenialReason ok=false
	// branch — invalid-argument, NOT a typed denial) also carries the
	// ExchangeService domain stamp (ADR-019 §1), read at the Connect boundary.
	assertErrorDomain(t, err, "ramp.v1.ExchangeService")
}

// A malformed (non-hex) offer signature is a per-item denial, not a batch abort.
// VerifyOffer fails the hex-decode of the signature and returns
// ErrOfferSignatureInvalid — the SAME sentinel as a decodable-but-wrong
// signature — so verifyPresentedOffer maps it to KindSignatureInvalid, a
// denial-map kind. Under the collapsed batch contract a per-item signature
// failure is folded into the response as DENIAL_REASON_SIGNATURE_INVALID (the
// loop continues; only an envelope/internal fault aborts the whole batch).
// Verification still runs BEFORE the catalog lookup, so a denied offer never
// leaks catalog membership and leaves no persisted transaction.
func TestExecuteTransaction_MalformedSignatureRejected(t *testing.T) {
	h := newTestHarness(t)
	const txID = "tx-malformed-sig"
	// A valid body acceptance over the malformed offer clears the envelope
	// presence checks so the denial comes from the offer-signature verification
	// (verify presented offer), not the agent_acceptance presence guard.
	req := execTxNegReq(txID, "some-offer", "not-hex", agentRequester("agent-test"))
	setNegItemAcceptance(req, h.defaultAcceptance(t, negItemOffer(req), txID))
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(req))
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)

	// The denied item persists no transaction (no charge, no delivery).
	derived := txID + ":" + negItemOffer(req).GetOfferId()
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derived); !errors.Is(err, repo.ErrTransactionNotFound) {
		t.Fatalf("ByIdempotencyKey(%q) after denied Execute = %v, want ErrTransactionNotFound (no side effect)", derived, err)
	}
}

// An offer whose signature does not verify against the Exchange key is rejected
// with Unauthenticated BEFORE the catalog lookup, so an unknown offer_id never
// produces a NotFound that would leak catalog membership to an unauthenticated
// caller. (Pre-0d0jk.3 the lookup ran first and returned NotFound for an unknown
// offer_id; the presented-offer contract reorders verify-before-lookup, so a
// bogus-signature offer for any offer_id — known or not — fails at verification.)
// Genuine catalog membership is exercised on the happy path
// (TestExecuteTransaction_PresentedOfferAccepted); a validly-signed offer for a
// since-removed catalog entry (the only remaining NotFound path) is not driveable
// from the harness because the test side does not hold the Exchange offer key.
func TestExecuteTransaction_UnknownOfferRejectedBeforeLookup(t *testing.T) {
	h := newTestHarness(t)
	seedCatalog(t, h)
	const txID = "tx-unknown-offer"
	// A valid body acceptance clears the envelope presence checks so the
	// rejection comes from the offer-signature verification (verify-before-lookup),
	// not the agent_acceptance presence guard. A decodable-but-wrong signature is
	// KindSignatureInvalid, a denial-map kind → in-body per-item denial after the
	// C4 collapse (Flag #1).
	req := execTxNegReq(txID, "offer-does-not-exist", "00", agentRequester("agent-test"))
	setNegItemAcceptance(req, h.defaultAcceptance(t, negItemOffer(req), txID))
	resp, err := h.exchangeClient.ExecuteTransaction(h.ctx, connect.NewRequest(req))
	assertItemDenied(t, resp, err, rampv1.DenialReason_DENIAL_REASON_SIGNATURE_INVALID)

	derived := txID + ":" + negItemOffer(req).GetOfferId()
	if _, err := repo.NewTransactionRepo(h.queries).ByIdempotencyKey(h.ctx, derived); !errors.Is(err, repo.ErrTransactionNotFound) {
		t.Fatalf("ByIdempotencyKey(%q) after rejected Execute = %v, want ErrTransactionNotFound (no side effect)", derived, err)
	}
}

// The Exchange no longer refuses Execute for a requester-attribute mismatch:
// ADR-014's 2026-06-15 amendment removed user_type / geography / intended_use
// restriction matching from the term projection, so a requester's self-declared
// attributes never make a term "ineligible". Execute still returns NotFound for
// an unknown offer (TestExecuteTransaction_UnknownOfferIDNotFound above) and for
// an entry with no scope-covered priced term, but never for an attribute
// mismatch — that exclusion path is gone, so its negative test is gone with it.

// ── ReportUsage validation (service/report_usage.go) ─────────────────────────
//
// The report==nil guard (report_usage.go:41) is structurally unreachable through
// the RPC — Connect always delivers a non-nil typed UsageReport — so it is a
// defensive in-process guard, not a public-surface behaviour, and is not tested
// here. The two reachable field guards are covered below.

func TestReportUsage_EmptyIdempotencyKeyRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "", TransactionId: "tx-x", BillingId: "b-x",
		Usage: &rampv1.Usage{ConsumedQuantity: 1},
	}))
	// An empty idempotency_key is now rejected at the SDK boundary by the proto
	// (min_len=1) before the handler runs — the contract enforces it, not a
	// hand-rolled string check.
	assertConnectError(t, err, connect.CodeInvalidArgument, "idempotency_key")
}

func TestReportUsage_EmptyTransactionIDRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-x", TransactionId: "", BillingId: "b-x",
		Usage: &rampv1.Usage{ConsumedQuantity: 1},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "transaction_id required")
}
