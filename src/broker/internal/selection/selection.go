// Package selection implements the Broker's offer deduplication and ranking
// logic. Handlers fan out DiscoverResources across exchanges, collect the
// returned Offers, then call Rank() to produce a deterministic selection
// order. The first entry is the chosen winner; the rest are alternates for
// audit and logging.
package selection

import (
	"sort"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// ExchangeRef annotates an Offer with its originating exchange so the
// Broker can record the routing decision.
type ExchangeRef struct {
	Domain   string
	Endpoint string
	Trust    string // DISCOVERED / VERIFIED / PREFERRED / BLOCKED
	Priority int32
}

// Candidate pairs an offer with the exchange it came from.
type Candidate struct {
	Offer    *rampv1.Offer
	Exchange ExchangeRef
}

// Dedup collapses candidates representing the same underlying resource,
// keeping the cheapest (lowest unit_cost) candidate per identity.
func Dedup(cands []Candidate) []Candidate {
	best := make(map[string]Candidate, len(cands))
	for _, c := range cands {
		key := identityKey(c.Offer)
		existing, ok := best[key]
		if !ok {
			best[key] = c
			continue
		}
		if unitCost(c.Offer) < unitCost(existing.Offer) {
			best[key] = c
		}
	}
	out := make([]Candidate, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	return out
}

// Rank returns the candidates in winner-first order.
//
// Ordering:
//  1. Higher trust_level_priority wins  (PREFERRED > VERIFIED > DISCOVERED)
//  2. Then lower unit_cost wins
//  3. Then higher exchange_priority wins
//  4. Then stable by offer_id for determinism
func Rank(cands []Candidate) []Candidate {
	sort.SliceStable(cands, func(i, j int) bool {
		ti, tj := trustWeight(cands[i].Exchange.Trust), trustWeight(cands[j].Exchange.Trust)
		if ti != tj {
			return ti > tj
		}
		ci, cj := unitCost(cands[i].Offer), unitCost(cands[j].Offer)
		if ci != cj {
			return ci < cj
		}
		if cands[i].Exchange.Priority != cands[j].Exchange.Priority {
			return cands[i].Exchange.Priority > cands[j].Exchange.Priority
		}
		return cands[i].Offer.GetOfferId() < cands[j].Offer.GetOfferId()
	})
	return cands
}

func trustWeight(level string) int {
	switch strings.ToUpper(level) {
	case "PREFERRED":
		return 3
	case "VERIFIED":
		return 2
	case "DISCOVERED":
		return 1
	case "BLOCKED":
		return -1
	default:
		return 0
	}
}

func unitCost(o *rampv1.Offer) float64 {
	if o == nil || o.GetPricing() == nil {
		return 0
	}
	if uc := o.GetPricing().UnitCost; uc != nil {
		return *uc
	}
	return o.GetPricing().GetRate()
}

func identityKey(o *rampv1.Offer) string {
	if o == nil {
		return ""
	}
	ident := o.GetIdentity()
	if ident != nil {
		if v := ident.CanonicalUrl; v != nil && *v != "" {
			return "url:" + *v
		}
		if v := ident.Doi; v != nil && *v != "" {
			return "doi:" + *v
		}
		if v := ident.IptcGuid; v != nil && *v != "" {
			return "iptc:" + *v
		}
		if v := ident.ContentHash; v != nil && *v != "" {
			return "hash:" + *v
		}
	}
	return "offer:" + o.GetOfferId()
}
