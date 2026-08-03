package selection_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/selection"
)

// offerWith builds an offer whose unit_cost is the canonical wire decimal STRING
// for the given amount (money-as-string). The float argument is a
// test-authoring convenience; FormatMoney renders it to the same canonical form
// the production wire carries (e.g. 0.05 -> "0.05", 0.10 -> "0.1").
func offerWith(id, canonical string, unitCost float64) *rampv1.Offer {
	u, err := helpers.FormatMoney(decimal.NewFromFloat(unitCost))
	if err != nil {
		panic(err)
	}
	url := canonical
	return &rampv1.Offer{
		OfferId: id,
		Pricing: &rampv1.Pricing{UnitCost: &u},
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl: &url,
		},
	}
}

func TestDedup_KeepsCheapestPerIdentity(t *testing.T) {
	cands := []selection.Candidate{
		{
			Offer:    unsafeVerified(offerWith("a1", "https://a/article", 0.05)),
			Exchange: selection.ExchangeRef{Domain: "mp1", Trust: "VERIFIED"},
		},
		{
			Offer:    unsafeVerified(offerWith("a2", "https://a/article", 0.03)),
			Exchange: selection.ExchangeRef{Domain: "mp2", Trust: "VERIFIED"},
		},
		{
			Offer:    unsafeVerified(offerWith("b1", "https://b/article", 0.10)),
			Exchange: selection.ExchangeRef{Domain: "mp1", Trust: "VERIFIED"},
		},
	}
	got := selection.Dedup(cands)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	for _, c := range got {
		if c.Offer.Offer().GetIdentity().GetCanonicalUrl() == "https://a/article" &&
			c.Offer.Offer().GetOfferId() != "a2" {
			t.Errorf("expected cheapest a2 to survive, got %q", c.Offer.Offer().GetOfferId())
		}
	}
}

func TestRank_TrustBeatsCost(t *testing.T) {
	cands := []selection.Candidate{
		{
			Offer:    unsafeVerified(offerWith("cheap", "url-a", 0.01)),
			Exchange: selection.ExchangeRef{Domain: "mp1", Trust: "DISCOVERED"},
		},
		{
			Offer:    unsafeVerified(offerWith("expensive", "url-b", 0.05)),
			Exchange: selection.ExchangeRef{Domain: "mp2", Trust: "PREFERRED"},
		},
	}
	got := selection.Rank(cands)
	if got[0].Offer.Offer().GetOfferId() != "expensive" {
		t.Errorf("winner = %q, want expensive (PREFERRED trust wins)", got[0].Offer.Offer().GetOfferId())
	}
}

func TestRank_TieBreakByCostThenPriority(t *testing.T) {
	cands := []selection.Candidate{
		{
			Offer:    unsafeVerified(offerWith("b", "url-a", 0.05)),
			Exchange: selection.ExchangeRef{Domain: "mp1", Trust: "VERIFIED", Priority: 1},
		},
		{
			Offer:    unsafeVerified(offerWith("a", "url-b", 0.03)),
			Exchange: selection.ExchangeRef{Domain: "mp2", Trust: "VERIFIED", Priority: 1},
		},
		{
			Offer:    unsafeVerified(offerWith("c", "url-c", 0.03)),
			Exchange: selection.ExchangeRef{Domain: "mp3", Trust: "VERIFIED", Priority: 5},
		},
	}
	got := selection.Rank(cands)
	if got[0].Offer.Offer().GetOfferId() != "c" {
		t.Errorf("winner = %q, want c (priority breaks cost tie)", got[0].Offer.Offer().GetOfferId())
	}
}

// unsafeVerified mints a core.VerifiedOffer for fixture construction via the
// SDK's explicit, audit-visible escape hatch (RejectedOffer.Unsafe) — it does
// NOT verify a signature. The name says "unsafe" so a reader never mistakes the
// fixture for a genuinely-verified offer: these unit tests exercise ranking
// semantics, not verification (the verify path is covered by the transport
// integration suite).
func unsafeVerified(o *rampv1.Offer) core.VerifiedOffer {
	return core.RejectedOffer{Offer: o}.Unsafe()
}
