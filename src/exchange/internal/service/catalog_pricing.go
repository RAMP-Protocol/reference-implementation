package service

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"
)

// PricingDoc is the internal pricing shape the discovery and billing paths
// operate on. It is no longer persisted as the source of truth: pricing is
// derived per-request from the selected LicenseTerm via pricingDocFromTerm
// . The catalog.pricing JSONB column still exists (NOT NULL) but holds
// only legacyPricingSentinel.
//
// Money fields (Rate, UnitCost) are exact decimal.Decimal — never float64.
// They are parsed from the canonical wire decimal string at the boundary
// (pricingDocFromTerm via helpers.ParseMoney) and re-rendered to the wire
// via helpers.FormatMoney. PricingDoc is internal-only and never
// serialized, so it carries no json tags.
type PricingDoc struct {
	Model    string
	Rate     decimal.Decimal
	Currency string
	UnitCost decimal.Decimal
	Unit     string
	EstQty   int32
	// Metering is how usage is tracked for billing reconciliation, carried as a
	// pointer so an absent value stays distinguishable from an explicit ONLINE.
	// The protocol reads absent as ONLINE, which is also what MetersUsage below
	// does; the distinction is kept so the offer we mint says exactly what the
	// term said, and no more.
	Metering *rampv1.PricingMetering
}

// MetersUsage reports whether a transaction under this price owes a usage
// report. False only for a one-time perpetual sale (PRICING_METERING_NONE):
// billing closes at ExecuteTransaction, so there is nothing to report later and
// no obligation is minted. Absent metering reads as ONLINE per the protocol, so
// a term that says nothing still meters.
func (p PricingDoc) MetersUsage() bool {
	return p.Metering == nil || *p.Metering != rampv1.PricingMetering_PRICING_METERING_NONE
}

// IsFree reports whether this resolved price is zero — the single predicate behind
// the free-resource path: a zero unit_cost bypasses the billing adapter (no
// Authorize, no Record, no Release; ADR-009 D2) and stores an empty billing_id
// (ADR-009 D5). Keyed on unit_cost — the normalized, signature-covered charge basis
// — not rate, so a publisher may advertise a headline rate while setting unit_cost 0
// for free execution.
func (p PricingDoc) IsFree() bool { return p.UnitCost.IsZero() }

// moneyOrZero parses a canonical wire money string into an exact decimal,
// mapping the empty (unset / FREE) string to decimal.Zero. Any non-empty but
// non-canonical value surfaces as an error — empty is the ONLY value treated as
// zero, so a malformed price fails loud rather than silently pricing at 0.
func moneyOrZero(s string) (decimal.Decimal, error) {
	if s == "" {
		return decimal.Zero, nil
	}
	return helpers.ParseMoney(s)
}

// pricingDocFromTerm projects a selected LicenseTerm's Pricing into the internal
// PricingDoc used by discovery (Offer.pricing) and billing (the charge). It is
// the single conversion from a real LicenseTerm to a price, so an offer's price
// is always backed by a term (core invariant) — never the retired $0.05
// default. UnitCost falls back to Rate when the term omits the normalized
// unit_cost, preserving the prior billing semantics where unit_cost == rate.
//
// Rate and unit_cost cross the wire as canonical decimal strings; they are
// parsed here once via helpers.ParseMoney so all downstream math is exact
// decimal (never float).
func pricingDocFromTerm(term *rampv1.LicenseTerm) (PricingDoc, error) {
	return pricingDocFromPricing(term.GetPricing())
}

// pricingDocFromPricing projects a wire Pricing message into the internal
// PricingDoc. It is the single conversion from a Pricing block to a price,
// shared by the term-derived discovery path (pricingDocFromTerm) and the
// presented-offer billing path (resolveOfferForTx reads the VERIFIED offer's
// signed Pricing — the agent is charged exactly what it signed, never a
// recompute from a drifted catalog). UnitCost falls back to Rate when the block
// omits the normalized unit_cost, preserving unit_cost == rate semantics. Rate
// and unit_cost are parsed once via helpers.ParseMoney so all downstream
// math is exact decimal.
func pricingDocFromPricing(p *rampv1.Pricing) (PricingDoc, error) {
	rate, err := moneyOrZero(p.GetRate())
	if err != nil {
		return PricingDoc{}, err
	}
	doc := PricingDoc{
		Model:    p.GetModel().String(),
		Rate:     rate,
		Currency: p.GetCurrency(),
		Unit:     p.GetUnit(),
		EstQty:   p.GetEstimatedQuantity(),
	}
	if p.Metering != nil {
		// Enum() returns a pointer to a copy, so the doc cannot observe a later
		// mutation of the request message it came from.
		doc.Metering = p.GetMetering().Enum()
	}
	if p.UnitCost != nil {
		uc, ucErr := moneyOrZero(p.GetUnitCost())
		if ucErr != nil {
			return PricingDoc{}, ucErr
		}
		doc.UnitCost = uc
	} else {
		doc.UnitCost = rate
	}
	return doc, nil
}
