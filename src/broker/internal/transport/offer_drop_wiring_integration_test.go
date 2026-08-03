//go:build integration

package transport_test

// Broker discover-path offer-DROP-wiring regression test.
//
// Core Invariant: every offer that reaches the Broker's typed
// DiscoveryResponse.offer_groups MUST have passed the broker's offer Verifier;
// an offer the Verifier REJECTS is dropped before it can fold into a group
// (discover.go collectGroups → Deps.Verifier.Sort → only Verified offers become
// candidates). This test pins that drop wiring.
//
// Why this shape (Testing Doctrine pt 6). The deleted predecessor proved the
// same wiring by mocking the EXCHANGE's signature verification (an httptest
// ExchangeService that signed one good + one doctored offer, verified against a
// mock WBA directory). That mocks a first-party service RAMP owns — a pt-6
// violation whose "end-to-end" claim a mock cannot back. Here the offers are
// genuine Exchange-signed offers (the mock Exchange stands in only as the offer
// DATA source — the pre-existing, separately-tracked boundary-stub pattern), and
// the verify/REJECT verdict is injected through the broker's OWN
// Deps.OfferVerifier seam (a legitimate broker port, resolve.go OfferVerifier).
// Nothing about the Exchange's verification is mocked. The genuine positive leg —
// a valid offer surviving the real fail-closed Verifier against a REAL Exchange —
// is pinned e2e in tests/e2e/harness/test_offer_verification.py.
//
// Non-tautology. The injected verifier rejects ONE offer id and VERIFIES the
// other over the SAME two-offer batch, and the test asserts BOTH: the verified
// offer is PRESENT and the rejected offer is ABSENT. So the assertion cannot pass
// vacuously — an empty offer_groups fails the presence leg, and a discover path
// that ignored the Verifier (relayed both offers) fails the absence leg. Only the
// real drop wiring — Verifier.Sort's verdict deciding group membership per offer —
// satisfies both at once.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
)

// validOfferID / rejectedOfferID are the offer_ids the mock Exchange stamps on
// the two genuinely-signed offers it emits when armed with an offer-signing key
// (testutil_test.go DiscoverResources two-offer mode). The injected verifier
// below VERIFIES validOfferID and REJECTS rejectedOfferID.
const (
	validOfferID    = "offer-valid"
	rejectedOfferID = "offer-rejected"
)

// errInjectedReject is the reason the injected verifier attaches to the offer it
// rejects. Its value is irrelevant to the assertion (the broker only logs it);
// it exists so RejectedOffer carries a non-nil reason like production does.
var errInjectedReject = errors.New("injected test verifier: offer rejected by policy")

// rejectingVerifier is an injected Deps.OfferVerifier that REJECTS the offer whose
// id == rejectID and VERIFIES every other offer. It mocks the broker's
// verify/reject DECISION (the legitimate OfferVerifier port) — NOT the Exchange.
// A VerifiedOffer cannot be composite-literal-constructed across packages (its
// wrapped field is unexported), so the sole cross-package mint is the SDK's
// RejectedOffer.Unsafe() escape — used here to surface a genuinely-signed offer
// as verified without re-running the crypto.
type rejectingVerifier struct {
	rejectID string
}

func (v rejectingVerifier) Sort(_ context.Context, offers []*rampv1.Offer) core.Result {
	var res core.Result
	for _, off := range offers {
		if off.GetOfferId() == v.rejectID {
			res.Rejected = append(res.Rejected, core.RejectedOffer{Offer: off, Reason: errInjectedReject})
			continue
		}
		res.Verified = append(res.Verified, core.RejectedOffer{Offer: off}.Unsafe())
	}
	return res
}

// TestResolve_RejectingVerifierDropsOfferFromOfferGroups pins the broker
// discover-path drop wiring through the public Connect Resolve surface: over a
// batch of TWO genuinely Exchange-signed offers, a Deps.OfferVerifier that
// rejects one id MUST cause that offer to be ABSENT from
// DiscoveryResponse.offer_groups while the verified offer remains PRESENT.
//
// Round-trip honesty. The request half is a genuine protocol round-trip: signed
// Connect client → RFC 9421 signature → real httpsig middleware → registered
// BrokerService handler → shared resolve core → Deps.Verifier.Sort → the typed
// DiscoveryResponse the client decodes. The offer verify/reject verdict is the
// ONLY injected seam; the offers themselves are real Exchange-signed offers.
func TestResolve_RejectingVerifierDropsOfferFromOfferGroups(t *testing.T) {
	ctx := context.Background()

	// Inject a verifier that rejects rejectedOfferID and verifies validOfferID.
	fx := newFixture(t, ctx, fixtureOpts{
		providerDomain: "acme.example",
		verifier:       rejectingVerifier{rejectID: rejectedOfferID},
	})

	// Arm the mock Exchange to emit the two genuinely-signed offers.
	exchangePub, exchangePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate exchange keypair: %v", err)
	}
	fx.exchange.offerSigningKey = exchangePriv
	fx.exchange.offerSigningPub = exchangePub

	_, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 10000,
	})

	groups := out.GetOfferGroups()
	if len(groups) == 0 {
		t.Fatal("expected non-empty offer_groups: the verified offer must still surface")
	}

	seen := collectOfferIDs(out)

	// Non-vacuity: the VERIFIED offer must remain — proving offer_groups is not
	// empty for an unrelated reason and that the verdict is applied per-offer.
	if !seen[validOfferID] {
		t.Errorf("verified offer (id=%q) must appear in offer_groups but was absent: got ids=%v",
			validOfferID, setKeys(seen))
	}

	// The DROP: the REJECTED offer must not appear anywhere in the typed response.
	// A discover path that ignored the Verifier verdict (relayed the offer) fails
	// here — this is the fail-closed drop wiring the deleted mock test covered.
	if seen[rejectedOfferID] {
		t.Errorf(
			"rejected offer (id=%q) MUST NOT appear in offer_groups; the discover path "+
				"folded a Verifier-rejected offer into a group — the drop wiring "+
				"(Deps.Verifier.Sort → only Verified offers become candidates) is broken: got ids=%v",
			rejectedOfferID, setKeys(seen))
	}
}

// rejectAllVerifier is an injected Deps.OfferVerifier that REJECTS every offer
// in the batch (the fail-closed shape the production unwiredVerifier default also
// takes). It mocks only the broker's verify/reject DECISION (the legitimate
// OfferVerifier port) — NOT the Exchange; the offers themselves are genuine
// Exchange-signed offers.
type rejectAllVerifier struct{}

func (rejectAllVerifier) Sort(_ context.Context, offers []*rampv1.Offer) core.Result {
	var res core.Result
	for _, off := range offers {
		res.Rejected = append(res.Rejected, core.RejectedOffer{Offer: off, Reason: errInjectedReject})
	}
	return res
}

// TestResolve_AllOffersRejected_FailClosedNoOffersRefusal pins the fail-closed
// tail of the resolve offer-verification orchestration through the public Connect
// Resolve surface: when the Verifier rejects EVERY offer in the discovered batch,
// the typed DiscoveryResponse MUST carry ZERO offers and surface the no-offers
// refusal (typed absence_reason NOT_IN_CATALOG), and no ExecuteTransaction fires.
//
// Why this guards the resolve-orchestration extraction. The single-drop test above proves ONE
// rejected offer is dropped while ONE verified offer survives; it never exercises
// the case where the verified-only fold empties the batch entirely. That empty-
// batch path threads two pieces of the orchestration slated to move into
// internal/resolve: collectGroups' verified-only fold (no candidate is appended)
// AND resolve()'s `winner := out.Winner(); if winner == nil { return
// noOffersResponse(flags) }` branch. A behavior-preserving move must keep both
// intact; a regression that leaked rejected offers (winner != nil) or mapped the
// empty batch to an error instead of the typed refusal is caught here and nowhere
// else. This is the Core Invariant's fail-closed guarantee ("a wiring omission
// surfaces as loud empty discovery, never as unverified offers reaching the
// agent") asserted end-to-end through the RPC.
//
// Non-vacuity. The mock Exchange emits TWO genuinely-signed offers; the injected
// verifier rejects BOTH. The test asserts (a) NEITHER offer id appears anywhere in
// the response — so a discover path that ignored the verdict and relayed the
// offers fails — AND (b) the refusal cause is the typed NOT_IN_CATALOG — so a path
// that dropped the offers but lost the refusal shape (e.g. UNSPECIFIED, or a
// transport error) also fails.
//
// Round-trip honesty. The request half is a genuine protocol round-trip: signed
// Connect client → RFC 9421 signature → real httpsig middleware → registered
// BrokerService handler → shared resolve core → Deps.Verifier.Sort → the typed
// DiscoveryResponse the client decodes. Only the verify/reject verdict is injected;
// the offers are real Exchange-signed offers. This test PASSES on HEAD — it guards
// existing behavior before the extraction (sanctioned refactor exception to
// red-first).
func TestResolve_AllOffersRejected_FailClosedNoOffersRefusal(t *testing.T) {
	ctx := context.Background()

	// Inject a verifier that rejects EVERY offer over the two-offer batch.
	fx := newFixture(t, ctx, fixtureOpts{
		providerDomain: "acme.example",
		verifier:       rejectAllVerifier{},
	})

	// Arm the mock Exchange to emit the two genuinely-signed offers.
	exchangePub, exchangePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate exchange keypair: %v", err)
	}
	fx.exchange.offerSigningKey = exchangePriv
	fx.exchange.offerSigningPub = exchangePub

	srv, out := resolveOverConnect(t, fx, "agent-1", reqOpts{
		uri:         "https://acme.example/article-42",
		budgetMinor: 10000,
	})

	// The fail-closed DROP: NOT ONE offer id may appear — both were rejected, so
	// the verified-only fold produced zero candidates.
	seen := collectOfferIDs(out)
	if len(seen) != 0 {
		t.Errorf(
			"all offers were Verifier-rejected, so offer_groups MUST carry zero offers; "+
				"a rejected offer folded into a group — the fail-closed verified-only fold "+
				"is broken: got ids=%v", setKeys(seen))
	}

	// The REFUSAL SHAPE: an empty verified batch is the no-offers refusal, surfaced
	// as the typed absence_reason NOT_IN_CATALOG (winner==nil → noOffersResponse →
	// pickResolveAbsenceReason with no upstream/scope/transient flags set). Losing
	// this mapping (UNSPECIFIED, or a transport fault) is a regression this pins.
	if got := out.GetAbsenceReason(); got != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG {
		t.Errorf("typed absence_reason = %v, want NOT_IN_CATALOG (fail-closed no-offers refusal)", got)
	}

	// No transaction may fire for a batch that produced no verified offer.
	if srv.exchange.executeCalls != 0 {
		t.Errorf("fail-closed no-offers refusal must not call ExecuteTransaction: got %d",
			srv.exchange.executeCalls)
	}
}

// collectOfferIDs returns the set of offer_ids that appear in ANY offer_group in
// the response — used to assert both presence (verified) and absence (rejected).
func collectOfferIDs(resp *rampv1.DiscoveryResponse) map[string]bool {
	seen := make(map[string]bool)
	for _, group := range resp.GetOfferGroups() {
		for _, offer := range group.GetOffers() {
			seen[offer.GetOfferId()] = true
		}
	}
	return seen
}

// setKeys returns the keys of a bool-valued map as a slice for error messages.
func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
