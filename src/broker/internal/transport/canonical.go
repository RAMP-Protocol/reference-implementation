package transport

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
)

// rampRequestToInput maps the canonical wire DiscoveryRequest onto the Broker's
// internal resolve input. requester.id becomes the self-act identity; uris and
// acceptable_restrictions now ride on the DiscoveryRequest message itself (the
// requester is identity-only after the Universal Licensing Core overhaul). The
// first uri is taken (multi-URI batch is forward-looking) and the first
// FUNCTION-axis acceptable-restriction value is taken as the advisory intended
// use. max_hops is mapped only when present: DiscoveryRequest.constraints.max_hops
// is optional, and GetMaxHops()==0 on absent would be read by enforceHopBudget as
// an impossible chain — 400'ing every constraint-less request.
func rampRequestToInput(rr *rampv1.DiscoveryRequest) resolve.Request {
	in := resolve.Request{
		AgentID:      rr.GetRequester().GetId(),
		RequesterDom: rr.GetRequester().GetDomain(),
		Query:        rr.GetQuery(),
	}
	if uris := rr.GetUris(); len(uris) > 0 {
		// Carry the WHOLE requested batch (batch fan-out): candidateDomains maps every
		// uri to its publisher domain and buildResourceQuery forwards them all to
		// each named exchange. URI (== uris[0]) stays the scalar back-compat handle
		// the single-uri call sites read.
		in.URIs = uris
		in.URI = uris[0]
	}
	in.IntendedUse = firstFunctionRestriction(rr.GetAcceptableRestrictions())
	if c := rr.GetConstraints(); c != nil {
		if pb := c.GetPeriodBudget(); pb != nil {
			// PeriodBudget.amount is a canonical wire money string; cross it to 1e8
			// fixed-point (DECISION 1+3) — never int64(amount*100) cents, which
			// truncated sub-cent budgets. moneyStringToFixedPoint maps empty/malformed
			// to 0 (no cap), so the assignment cannot fail the request.
			in.BudgetMinor, _ = moneyStringToFixedPoint(pb.GetAmount())
		}
		if c.MaxHops != nil {
			in.MaxHops = c.MaxHops
		}
	}
	return in
}

// firstFunctionRestriction returns the first non-empty FUNCTION-axis
// acceptable-restriction value — the advisory "intended use" the agent
// volunteers. The Exchange filters by resource_id + scopes only (ADR-014); this
// value rides through as an advisory passthrough, never an enforcement input.
func firstFunctionRestriction(rs []*rampv1.AcceptableRestriction) string {
	for _, r := range rs {
		if r.GetAxis() != rampv1.RestrictionKind_RESTRICTION_KIND_FUNCTION {
			continue
		}
		for _, v := range r.GetValues() {
			if v != "" {
				return v
			}
		}
	}
	return ""
}

// toDiscoveryResponse maps the Broker's internal resolve outcome to the canonical
// wire DiscoveryResponse. R7: resolve is DISCOVERY-ONLY. On the
// licensed-discovery path it emits the ranked, already-signed Offers (r.Offers)
// as DiscoveryResponse.offer_groups — NON-EMPTY offer_groups IS the licensed signal
// (ADR-019). The execute-shaped fields (retrieval_endpoint,
// transaction_id, cost, agent_identity_hash) are NO LONGER set here: the Broker
// no longer authors a transaction at resolve; the Exchange is the sole executor
// and biller, at the agent's own ExecuteTransaction. On refusal (r.Offers
// empty) the response carries only the typed absence_reason.
//
// The agent-facing response is PURELY the canonical typed DiscoveryResponse — the
// Broker sets NO ext. Broker selection/billing detail (budget/spend state, the
// evaluated-candidate list) has no canonical field and is NOT echoed to the
// agent; it lives in the Broker's SelectionLog (auditSelection) and budget
// service, never on the wire.
func toDiscoveryResponse(r *resolve.Response) *rampv1.DiscoveryResponse {
	// The canonical DiscoveryResponse carries no top-level exchange after the
	// combined proto line: the issuing Exchange rides per-offer as Offer.exchange
	// (inside the signed offer bytes), so a relaying Broker cannot redirect
	// execution without invalidating the signature.
	out := &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
	}
	// Typed absence_reason (proto field 16) is the SOLE refusal-cause surface
	// (ADR-019 — the ramp.broker.absence_reason ext key is gone). It is
	// set on the refusal path (empty Offers), so it must be assigned BEFORE the
	// empty-Offers return below.
	if r.AbsenceReason != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
		out.AbsenceReason = r.AbsenceReason.Enum()
	}
	if len(r.Groups) == 0 {
		return out
	}
	// One wire OfferGroup per REQUESTED uri (the merge of the upstream exchanges'
	// per-URI OfferGroups, keyed on OfferGroup.Uri). Each carries the ranked
	// offers (winner first) for that uri, with Uri + DiscoveryMethod set; a uri
	// absent across every authorized exchange rides as an empty group with its
	// per-URI AbsenceReason.
	out.OfferGroups = make([]*rampv1.OfferGroup, 0, len(r.Groups))
	for i := range r.Groups {
		out.OfferGroups = append(out.OfferGroups, toWireOfferGroup(&r.Groups[i]))
	}
	return out
}

// toWireOfferGroup maps one internal per-URI OfferGroup to the canonical wire
// rampv1.OfferGroup: Uri echoed from the request, the discovery method the
// resolve layer recorded, ranked offers when present, else the per-URI
// AbsenceReason. It maps and decides nothing — resolve.stampMethod is where the
// method comes from.
//
// The method is written only when it is set, the same guard AbsenceReason gets
// below. discovery_method is an optional proto field and this response is
// served with EmitUnpopulated, so writing it unconditionally would send the
// literal DISCOVERY_METHOD_UNSPECIFIED for a group that was never stamped. An
// unstamped group is a bug in resolve, and it should reach the agent as a
// missing field rather than as an answer.
func toWireOfferGroup(g *resolve.OfferGroup) *rampv1.OfferGroup {
	wire := &rampv1.OfferGroup{Uri: g.URI}
	if g.DiscoveryMethod != rampv1.DiscoveryMethod_DISCOVERY_METHOD_UNSPECIFIED {
		wire.DiscoveryMethod = g.DiscoveryMethod.Enum()
	}
	if len(g.Offers) == 0 {
		if g.AbsenceReason != rampv1.OfferAbsenceReason_OFFER_ABSENCE_REASON_UNSPECIFIED {
			wire.AbsenceReason = g.AbsenceReason.Enum()
		}
		return wire
	}
	offers := make([]*rampv1.Offer, 0, len(g.Offers))
	for _, c := range g.Offers {
		offers = append(offers, c.Offer.Offer())
	}
	wire.Offers = offers
	return wire
}
