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
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"
)

// ExchangeRef annotates an Offer with its originating exchange so the
// Broker can record the routing decision.
type ExchangeRef struct {
	Domain   string
	Endpoint string
	Trust    string // DISCOVERED / VERIFIED / PREFERRED / BLOCKED
	Priority int32
}

// Candidate pairs a VERIFIED offer with the exchange it came from. The field
// is core.VerifiedOffer — the SDK's unforgeable wrapper — so "only offers that
// passed the fail-closed Verifier are rankable" is a COMPILE guard: the only
// way to build a Candidate is through the verify path (or the audit-visible
// RejectedOffer.Unsafe escape).
type Candidate struct {
	Offer    core.VerifiedOffer
	Exchange ExchangeRef
}

// Dedup collapses candidates representing the same underlying resource,
// keeping the cheapest (lowest unit_cost) candidate per identity.
func Dedup(cands []Candidate) []Candidate {
	best := make(map[string]Candidate, len(cands))
	for _, c := range cands {
		key := identityKey(c.Offer.Offer())
		existing, ok := best[key]
		if !ok {
			best[key] = c
			continue
		}
		if OfferCharge(c.Offer.Offer()).LessThan(OfferCharge(existing.Offer.Offer())) {
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
		ci, cj := OfferCharge(cands[i].Offer.Offer()), OfferCharge(cands[j].Offer.Offer())
		if !ci.Equal(cj) {
			return ci.LessThan(cj)
		}
		if cands[i].Exchange.Priority != cands[j].Exchange.Priority {
			return cands[i].Exchange.Priority > cands[j].Exchange.Priority
		}
		return cands[i].Offer.Offer().GetOfferId() < cands[j].Offer.Offer().GetOfferId()
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

// OfferCharge is the EXACT decimal charge for an offer: its unit_cost when
// present, else its rate. This is the SINGLE source of truth for what the agent
// is billed — the Exchange charges unit_cost (rate is the provider's own model
// price, normalized to unit_cost; catalog_pricing falls back unit_cost<-rate
// only when a term omits unit_cost). Both offer ranking (Dedup/Rank) AND the
// broker budget pre-flight read this one function, so the gate can never admit
// or deny against a different price than the one selection ranks and the agent
// pays. Money rides the wire as a canonical decimal string; it is parsed once
// here via helpers.ParseMoney so comparisons are exact decimals (decimal.Cmp),
// never float. A nil offer/pricing, an unset (nil) unit_cost, or an
// empty/unparseable string all map to decimal.Zero — preserving the prior
// zero-value ranking semantics for offers without a price. (Empty must stay loud
// on the billing/mapper paths; here, on the ranking/budget path only, it is
// deliberately treated as zero.)
func OfferCharge(o *rampv1.Offer) decimal.Decimal {
	if o == nil || o.GetPricing() == nil {
		return decimal.Zero
	}
	if uc := o.GetPricing().UnitCost; uc != nil {
		return parseMoneyOrZero(*uc)
	}
	return parseMoneyOrZero(o.GetPricing().GetRate())
}

func parseMoneyOrZero(s string) decimal.Decimal {
	d, err := helpers.ParseMoney(s)
	if err != nil {
		return decimal.Zero
	}
	return d
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
