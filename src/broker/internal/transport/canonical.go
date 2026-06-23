package transport

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/structpb"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/selection"
)

// rampRequestToInput maps the canonical wire RAMPRequest onto the Broker's
// internal resolve input. requester.id becomes the self-act identity; the first
// uri / intended_use are taken (multi-URI batch is forward-looking). max_hops is
// mapped only when present: RAMPRequest.constraints.max_hops is optional, and
// GetMaxHops()==0 on absent would be read by enforceHopBudget as an impossible
// chain — 400'ing every constraint-less request.
func rampRequestToInput(rr *rampv1.RAMPRequest) ResolveRequest {
	in := ResolveRequest{
		AgentID:      rr.GetRequester().GetId(),
		RequesterDom: rr.GetRequester().GetDomain(),
		LicenseID:    rr.GetRequester().GetLicenseId(),
		Query:        rr.GetQuery(),
	}
	if uris := rr.GetRequester().GetUris(); len(uris) > 0 {
		in.URI = uris[0]
	}
	if uses := rr.GetRequester().GetIntendedUse(); len(uses) > 0 {
		in.IntendedUse = uses[0]
	}
	if c := rr.GetConstraints(); c != nil {
		if pb := c.GetPeriodBudget(); pb != nil {
			in.BudgetMinor = int64(pb.GetAmount() * 100)
		}
		if c.MaxHops != nil {
			in.MaxHops = c.MaxHops
		}
	}
	return in
}

// toRAMPResponse maps the Broker's internal resolve outcome to the canonical
// wire RAMPResponse. Canonical fields come from the Exchange TransactionResponse
// (r.tx, set on the licensed path; nil on refusal → those fields stay empty).
// Broker-specific signals ride under ext with ramp.broker.* keys (brokerExt).
//
// agent_identity_hash is forwarded verbatim from the Exchange's
// TransactionResponse. The Exchange emits the requesting key's RFC 7638 JWK
// thumbprint (base64url-no-pad); on the direct-agent path it is the binding
// value a proof-of-possession-enforcing edge checks, and on the MCP relay path
// it is the broker's own thumbprint (the Exchange binds to the proven caller,
// which is the broker there; edge enforcement defaults OFF for exactly this
// reason — see ADR-013 D5/D6.1). The Broker neither recomputes nor interprets
// it; it is an opaque passthrough. Do not recompute here.
func toRAMPResponse(r *ResolveResponse, requestID string) *rampv1.RAMPResponse {
	out := &rampv1.RAMPResponse{
		Ver:       rampproto.Ver,
		Id:        "rampresp-" + uuid.NewString(),
		RequestId: requestID,
		Exchange:  r.ExchangeID,
		Ext:       brokerExt(r),
	}

	// RAMP-56: Discovery phase returns offers in ext; execute phase returns tx.
	// Offers are placed in ext.ramp.broker.offers since RAMPResponse doesn't
	// have a canonical offers field (it's designed for the execute phase).
	if len(r.Offers) > 0 {
		return out
	}

	tx := r.tx
	if tx == nil {
		return out
	}
	out.TransactionId = tx.GetTransactionId()
	out.BillingId = tx.GetBillingId()
	out.Cost = tx.GetCost()
	out.DeliveryMethod = tx.GetDeliveryMethod()
	out.ReportingObligation = tx.GetReportingObligation()
	out.ExpiresAt = tx.GetExpiresAt()
	if title := tx.GetResourceTitle(); title != "" {
		out.ResourceTitle = stringPtr(title)
	}
	if url := tx.GetRetrievalEndpoint(); url != "" {
		out.RetrievalEndpoint = stringPtr(url)
	}
	if h := tx.GetAgentIdentityHash(); h != "" {
		out.AgentIdentityHash = stringPtr(h)
	}
	return out
}

// brokerExt packs the Broker-specific signals that RAMPResponse has no canonical
// field for into a google.protobuf.Struct under ramp.broker.* keys. Empty
// optional signals are omitted. structpb numbers are float64, so minor-unit
// int64s are widened on the way in.
//
// RAMP-56: Discovery phase offers are serialized here since RAMPResponse has no
// canonical offers field (it's designed for the execute phase).
func brokerExt(r *ResolveResponse) *structpb.Struct {
	fields := map[string]any{"ramp.broker.licensed": r.Licensed}
	if r.OfferID != "" {
		fields["ramp.broker.offer_id"] = r.OfferID
	}
	if r.Error != "" {
		fields["ramp.broker.error"] = r.Error
	}
	if r.AbsenceReason != "" {
		fields["ramp.broker.absence_reason"] = r.AbsenceReason
	}
	if r.Budget != nil {
		fields["ramp.broker.budget"] = map[string]any{
			"limit_minor":     float64(r.Budget.Limit),
			"consumed_minor":  float64(r.Budget.Consumed),
			"remaining_minor": float64(r.Budget.Remaining),
		}
	}
	if cands := brokerCandidates(r.Candidates); cands != nil {
		fields["ramp.broker.candidates"] = cands
	}
	// RAMP-56: Serialize discovered offers for agent selection.
	if offers := brokerOffers(r.Offers); offers != nil {
		fields["ramp.broker.offers"] = offers
	}
	s, err := structpb.NewStruct(fields)
	if err != nil {
		// Unreachable: every value above is bool/string/float64/map/slice.
		// Guard anyway so a future field addition cannot panic the handler.
		return nil
	}
	return s
}

// brokerCandidates serializes ranked candidate summaries for the
// ramp.broker.candidates ext key. Returns nil when there are none.
func brokerCandidates(candidates []CandidateInfo) []any {
	if len(candidates) == 0 {
		return nil
	}
	cands := make([]any, 0, len(candidates))
	for _, c := range candidates {
		cands = append(cands, map[string]any{
			"offer_id":    c.OfferID,
			"exchange_id": c.ExchangeID,
			"unit_cost":   c.UnitCost,
			"trust_level": c.TrustLevel,
		})
	}
	return cands
}

// brokerOffers serializes discovered offers (RAMP-56 discovery phase) for the
// ramp.broker.offers ext key. Returns nil when there are none.
func brokerOffers(candidates []selection.Candidate) []any {
	if len(candidates) == 0 {
		return nil
	}
	offers := make([]any, 0, len(candidates))
	for _, candidate := range candidates {
		offers = append(offers, brokerOffer(candidate))
	}
	return offers
}

// brokerOffer serializes a single discovered offer into the map shape carried
// under ramp.broker.offers.
func brokerOffer(candidate selection.Candidate) map[string]any {
	offer := candidate.Offer
	offerMap := map[string]any{
		"offer_id":          offer.GetOfferId(),
		"exchange_domain":   candidate.Exchange.Domain,
		"exchange_endpoint": candidate.Exchange.Endpoint,
	}
	if sig := offer.GetSignature(); sig != "" {
		offerMap["signature"] = sig
	}
	if p := offer.GetPricing(); p != nil {
		pricing := map[string]any{"rate": p.GetRate()}
		if p.EstimatedQuantity != nil {
			pricing["estimated_quantity"] = *p.EstimatedQuantity
		}
		if p.UnitCost != nil {
			pricing["unit_cost"] = *p.UnitCost
		}
		offerMap["pricing"] = pricing
	}
	return offerMap
}
