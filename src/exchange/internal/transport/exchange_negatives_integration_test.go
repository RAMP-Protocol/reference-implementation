//go:build integration

package transport_test

import (
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

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

// negOfferCanonicalURL is the catalog binding the negative-case offers carry. It
// names a resource none of these cases seeds, so it clears the presence check
// without ever resolving to a catalog entry. A var rather than a const because
// the proto field is a pointer.
var negOfferCanonicalURL = "https://publisher.example/articles/negative-case"

// execTxNegReq builds an items[] TransactionRequest for the negative cases (the
// items-only contract after the C4 collapse). A shared builder keeps the
// near-identical literals out of every case (jscpd). The single item carries the
// offer; callers set its agent_acceptance when the case needs to clear the
// envelope presence checks and reach the offer-signature verify.
func execTxNegReq(id, offerID, sig string, requester *rampv1.Requester) *rampv1.TransactionRequest {
	return &rampv1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: id,
		Requester:      requester,
		// the offer signature rides on the reflected full Offer. An empty
		// sig leaves the offer signature empty (the validateBatchRequest per-item
		// guard case).
		// The offer names this Exchange. Every case here is about a guard that
		// runs INSIDE the handler, and the recipient check runs before it, so an
		// offer naming nobody would be refused up front and none of these cases
		// would reach the behaviour they name.
		//
		// It carries a canonical URL for the same reason: the envelope validator
		// requires one before the request claims its idempotency key, so an offer
		// without one is refused there and never reaches the signature guard these
		// cases are about. The URL names a resource no case seeds, so a case that
		// reaches the catalog lookup at all would fail with a catalog miss rather
		// than succeed.
		Items: []*rampv1.TransactionItem{
			{Offer: &rampv1.Offer{
				OfferId:   offerID,
				Exchange:  harnessExchangeDomain,
				Signature: sig,
				Identity: &rampv1.ResourceIdentity{
					CanonicalUrl: &negOfferCanonicalURL,
					// The proto requires a mutability other than UNSPECIFIED on any
					// present ResourceIdentity, and the request validator enforces it
					// before the handler runs.
					ResourceMutability: rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC,
				},
			}},
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
	return newRequester(id, "agent.example")
}

// ── DiscoverResources input validation (service/exchange.go:137-145) ──────────

func TestDiscoverResources_NilRequesterRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(nil, nil)))
	assertConnectError(t, err, connect.CodeInvalidArgument, "requester required")
	// Every DiscoverResources fault carries the ExchangeService domain
	// stamp (ADR-019 §1), read through the public Connect error envelope.
	assertErrorDomain(t, err, exchangeServiceDomainLiteral)
}

func TestDiscoverResources_EmptyRequesterIDRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(newRequester("", "agent.example"), []string{"https://" + h.tenantDomain + "/articles/hello"})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "requester.id required")
	// Every DiscoverResources fault carries the ExchangeService domain stamp.
	assertErrorDomain(t, err, exchangeServiceDomainLiteral)
}

func TestDiscoverResources_NoURIsRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.DiscoverResources(h.ctx, connect.NewRequest(newResourceQuery(newRequester("agent-test", "agent.example"), nil)))
	assertConnectError(t, err, connect.CodeInvalidArgument, "at least one uri required")
	// Every DiscoverResources fault carries the ExchangeService domain stamp.
	assertErrorDomain(t, err, exchangeServiceDomainLiteral)
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
	assertErrorDomain(t, err, exchangeServiceDomainLiteral)
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
// BEFORE the catalog lookup, so an unknown offer never produces a NotFound that
// would leak catalog membership to an unauthenticated caller. (Previously the
// lookup ran first and returned NotFound for an unknown offer; the
// presented-offer contract reorders verify-before-lookup, so a bogus-signature
// offer — for a known or unknown resource alike — fails at verification.)
// The remaining NotFound path (a validly-signed offer whose canonical URL binds
// to no catalog entry) IS driveable — the harness holds the Exchange offer key —
// and is covered by TestExecuteTransaction_CanonicalURLExactMatchOnly in
// execute_canonical_binding_integration_test.go.
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
// attributes never make a term "ineligible". Term eligibility is decided only
// at discovery (licenseterm.Select's lone caller is the discovery path, where
// an ineligible requester simply gets no offer); Execute's only NotFound is a
// signed canonical URL that binds to no catalog entry, and it never rejects for
// an attribute mismatch — that exclusion path is gone, so its negative test is
// gone with it.

// ── ReportUsage validation (service/report_usage.go) ─────────────────────────
//
// The report==nil guard (report_usage.go:41) is structurally unreachable through
// the RPC — Connect always delivers a non-nil typed UsageReport — so it is a
// defensive in-process guard, not a public-surface behaviour, and is not tested
// here. The two reachable field guards are covered below.

func TestReportUsage_EmptyIdempotencyKeyRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("", "tx-x", "b-x", &rampv1.Usage{ConsumedQuantity: 1})))
	// An empty idempotency_key is now rejected at the SDK boundary by the proto
	// (min_len=1) before the handler runs — the contract enforces it, not a
	// hand-rolled string check.
	assertConnectError(t, err, connect.CodeInvalidArgument, "idempotency_key")
}

func TestReportUsage_EmptyTransactionIDRejected(t *testing.T) {
	h := newTestHarness(t)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(newUsageReport("r-x", "", "b-x", &rampv1.Usage{ConsumedQuantity: 1})))
	assertConnectError(t, err, connect.CodeInvalidArgument, "transaction_id required")
}
