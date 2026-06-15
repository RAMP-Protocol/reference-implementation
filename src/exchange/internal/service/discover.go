package service

import (
	"encoding/json"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
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
) (*rampv1.OfferGroup, []*rampv1.Offer, error) {
	switch verdict {
	case LookupMiss:
		absence := rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_NOT_IN_CATALOG
		return &rampv1.OfferGroup{Uri: uri, AbsenceReason: &absence}, nil, nil
	case LookupHitPublic:
		offer, err := s.buildOffer(entry)
		if err != nil {
			return nil, nil, exchange.Wrap(exchange.KindInternal, err, "build offer")
		}
		return &rampv1.OfferGroup{Uri: uri, Offers: []*rampv1.Offer{offer}}, []*rampv1.Offer{offer}, nil
	default:
		return nil, nil, exchange.Newf(exchange.KindInternal, "unknown lookup verdict %d", verdict)
	}
}

func (s *ExchangeService) buildOffer(entry repo.CatalogEntry) (*rampv1.Offer, error) {
	var pricing PricingDoc
	if err := json.Unmarshal(entry.PricingJSON, &pricing); err != nil {
		return nil, fmt.Errorf("unmarshal pricing: %w", err)
	}
	expires := s.clk.Now().Add(s.cfg.OfferTTL)
	offer := &rampv1.Offer{
		OfferId: entry.ResourceID,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel(rampv1.PricingModel_value[pricing.Model]),
			Rate:     pricing.Rate,
			Currency: pricing.Currency,
			UnitCost: &pricing.UnitCost,
			Unit:     &pricing.Unit,
		},
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		ExpiresAt:      timestamppb.New(expires),
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl: strPtr(entry.URI),
		},
	}
	if pricing.EstQty > 0 {
		offer.Pricing.EstimatedQuantity = &pricing.EstQty
	}
	sig, err := s.offerSigner.SignOffer(offer)
	if err != nil {
		return nil, fmt.Errorf("sign offer: %w", err)
	}
	offer.Signature = sig
	offer.SignatureAlgorithm = signing.SignatureAlgorithm
	return offer, nil
}

func strPtr(s string) *string { return &s }
