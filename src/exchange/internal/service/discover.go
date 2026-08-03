package service

import (
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/licenseterm"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// groupFor builds the per-URI OfferGroup and returns the concrete offers that
// also land in the flat ResourceResponse.Offers slice (for backwards-compat
// with single-URI callers). The second return value is a subset of
// group.Offers.
func (s *ExchangeService) groupFor(
	uri string,
	entry repo.CatalogEntry,
	verdict LookupVerdict,
	requester *rampv1.Requester,
	profiles []string,
) (*rampv1.OfferGroup, []*rampv1.Offer, error) {
	switch verdict {
	case LookupMiss:
		absence := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
		return &rampv1.OfferGroup{Uri: uri, AbsenceReason: &absence}, nil, nil
	case LookupHitPublic:
		offer, err := s.buildOffer(entry, requester, profiles)
		if err != nil {
			return nil, nil, exchange.Wrap(exchange.KindInternal, err, "build offer")
		}
		// No offer when the requester is entitled to no priced term: an entry
		// whose terms all filter out (or that carries no terms) has no real
		// LicenseTerm to derive a price from, so it yields NO offer rather than a
		// stub-priced one (core invariant). The resource is still visible
		// by URI; the group just carries no offers. (Surfacing the unified
		// OFFER_ABSENCE_REASON_RESTRICTION_FILTERED reason on a restriction-driven
		// filter-out is a flagged follow-up.)
		if offer == nil {
			return &rampv1.OfferGroup{Uri: uri}, nil, nil
		}
		return &rampv1.OfferGroup{Uri: uri, Offers: []*rampv1.Offer{offer}}, []*rampv1.Offer{offer}, nil
	default:
		return nil, nil, exchange.Newf(exchange.KindInternal, "unknown lookup verdict %d", verdict)
	}
}

// buildOffer constructs and signs the Offer for a catalog entry. When requester
// is non-nil the persisted terms are first filtered through licenseterm.Select
// so the offer carries only the terms this requester is entitled to — the
// requester-eligibility FILTERING layered on top of the resource→offer terms
// projection (Select is the single source of term-eligibility; this is its only
// caller on the discovery path). The signature is computed AFTER filtering so it
// covers exactly the projected subset.
//
// A nil requester skips Select and projects all stored terms unchanged. The
// execute path no longer reconstructs offers for verification (it verifies the
// PRESENTED signed offer via helpers.VerifyPresentedOffer); buildOffer is the
// discovery-time producer only.
//
// Returns (nil, nil) — no error — when the requester is entitled to no priced
// term: the entry's terms all filtered out (or it carries none), so there is no
// real LicenseTerm to derive a price from and therefore no offer.
func (s *ExchangeService) buildOffer(
	entry repo.CatalogEntry, requester *rampv1.Requester, profiles []string,
) (*rampv1.Offer, error) {
	// Project the publisher's persisted (normalized) license terms onto the
	// offer and derive pricing from the SELECTED term. This is the public read
	// surface for terms: DiscoverResources → Offer.terms is how canonicalized
	// restriction tokens become observable to agents (ADR-008 full-surface
	// round-trip), and Offer.pricing is the price of the first projected term.
	//
	// Terms are read from the snapshot's rebuild-time decode cache — NOT decoded
	// per call. The stored JSONB stays untrusted: a row that failed to
	// decode at rebuild is cached as zero terms, which yields no offer here.
	snap := s.catalog.Snapshot()
	stored := snap.DecodedTerms(entry.ResourceID)
	pricing, terms, headlineIdx, ok, err := s.selectedPricing(stored, requester)
	if err != nil {
		return nil, fmt.Errorf("derive pricing: %w", err)
	}
	if !ok {
		return nil, nil
	}
	rateStr, err := helpers.FormatMoney(pricing.Rate)
	if err != nil {
		return nil, fmt.Errorf("format offer rate: %w", err)
	}
	ucStr, err := helpers.FormatMoney(pricing.UnitCost)
	if err != nil {
		return nil, fmt.Errorf("format offer unit_cost: %w", err)
	}
	expires := s.clk.Now().Add(s.cfg.OfferTTL)
	offer := &rampv1.Offer{
		OfferId: entry.ResourceID,
		// Canonical domain of the Exchange that issued this offer. Set BEFORE
		// SignOffer so it falls inside the signed offer payload
		// (helpers.canonicalOfferPayload marshals the whole Offer minus
		// signature/signature_algorithm). This is the same value echoed in
		// ResourceResponse.exchange; it makes the broker's execute-routing target
		// derivable from the signed offer itself, retiring the
		// X-RAMP-Exchange-Endpoint transport header.
		Exchange: s.cfg.Exchange,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel(rampv1.PricingModel_value[pricing.Model]),
			Rate:     rateStr,
			Currency: pricing.Currency,
			UnitCost: &ucStr,
			Unit:     &pricing.Unit,
		},
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		ExpiresAt:      timestamppb.New(expires),
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl: strPtr(entry.URI),
			// Catalog entries carry no per-resource mutability column yet, so every
			// discovered offer defaults to STATIC (seeded content is static). This
			// also satisfies the proto rule ResourceIdentity.resource_mutability
			// {not_in:[0]}, which the response-validating interceptor now enforces on
			// the reflected offer at execute. Sourcing mutability from the catalog
			// entry is a flagged follow-up.
			ResourceMutability: rampv1.ResourceMutability_RESOURCE_MUTABILITY_STATIC,
		},
		Terms: terms,
	}
	if pricing.EstQty > 0 {
		offer.Pricing.EstimatedQuantity = &pricing.EstQty
	}
	// Project the resource extension metadata onto the offer BEFORE signing so it
	// is covered by the signature. Read from the same rebuild-time snapshot decode
	// cache (no per-call decode). buildOffer is also the tx-reconstruction path
	// (verifyOffer), and every field applied here derives only from stored
	// snapshot state — never s.clk.Now() — so the reconstructed offer reproduces
	// identical signed bytes (signature parity).
	md := snap.DecodedMetadata(entry.ResourceID)
	if md != nil {
		applyMetadata(offer, md)
	}
	// Merge the CoMP projection (precomputed once at snapshot rebuild)
	// AFTER metadata and BEFORE signing, so the comp ext is signature-covered and
	// reproduced at tx-reconstruction. Looked up by the selected headline term's
	// ORIGINAL stored index, so the blob is deterministic from stored state and
	// discovery/reconstruction merge identical bytes.
	cached := snap.RenderedProfile(entry.ResourceID, headlineIdx, profileCoMPV1)
	applyCompProfile(offer, cached, profiles)
	sig, err := s.offerSigner.SignOffer(offer)
	if err != nil {
		return nil, fmt.Errorf("sign offer: %w", err)
	}
	offer.Signature = sig
	offer.SignatureAlgorithm = signing.SignatureAlgorithm
	return offer, nil
}

// selectedPricing is the single derivation of an offer's price and projected
// terms from a catalog entry's terms, shared by the discovery path (buildOffer)
// and the billing path (resolveOfferForTx) so the price an agent is SHOWN and the
// price it is CHARGED can never diverge.
//
// The persisted terms are decoded ONCE at snapshot-rebuild time and passed in
// here as `stored` (the caller reads them from the snapshot via DecodedTerms);
// this method NEVER decodes JSONB per call. It filters `stored` through
// licenseterm.Select for the requester (the single source of term eligibility)
// and returns:
//   - the PricingDoc derived from the FIRST projected term (the
//     publisher controls the headline price by term order),
//   - the full Select-projected term slice (for Offer.terms / the signature),
//   - the ORIGINAL stored index of that headline term (the CoMP
//     package_id carries the publisher index, so the discovery path can look up
//     the precomputed CoMP projection for the selected term),
//   - ok=false when the projection is empty (no eligible priced term → no
//     offer; the caller MUST NOT fabricate a default price),
//   - a non-nil error when the headline term's stored Pricing fails to project
//     into a PricingDoc (e.g. an unparseable money string).
//
// A nil requester projects all stored terms unchanged (the offer-reconstruction
// path); an empty stored-terms set still yields ok=false.
func (s *ExchangeService) selectedPricing(
	stored []*rampv1.LicenseTerm, requester *rampv1.Requester,
) (PricingDoc, []*rampv1.LicenseTerm, int, bool, error) {
	terms := stored
	if requester != nil {
		terms = licenseterm.Select(terms, requester)
	}
	if len(terms) == 0 {
		return PricingDoc{}, nil, 0, false, nil
	}
	doc, err := pricingDocFromTerm(terms[0])
	if err != nil {
		return PricingDoc{}, nil, 0, false, err
	}
	return doc, terms, headlineIndex(stored, terms[0]), true, nil
}

// headlineIndex returns the ORIGINAL stored position of the selected headline
// term. licenseterm.Select is order-preserving and returns the same pointers it
// was given, so identity match recovers the publisher index that the CoMP
// package_id carries (Q8). Falls back to 0 if not found (defensive).
func headlineIndex(stored []*rampv1.LicenseTerm, headline *rampv1.LicenseTerm) int {
	for i, t := range stored {
		if t == headline {
			return i
		}
	}
	return 0
}

func strPtr(s string) *string { return &s }
