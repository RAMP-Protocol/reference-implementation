package selection_test

import (
	"testing"

	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/selection"
)

func offerWith(id, canonical string, unitCost float64) *rampv1.Offer {
	u := unitCost
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
			Offer:       offerWith("a1", "https://a/article", 0.05),
			Marketplace: selection.MarketplaceRef{Domain: "mp1", Trust: "VERIFIED"},
		},
		{
			Offer:       offerWith("a2", "https://a/article", 0.03),
			Marketplace: selection.MarketplaceRef{Domain: "mp2", Trust: "VERIFIED"},
		},
		{
			Offer:       offerWith("b1", "https://b/article", 0.10),
			Marketplace: selection.MarketplaceRef{Domain: "mp1", Trust: "VERIFIED"},
		},
	}
	got := selection.Dedup(cands)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	for _, c := range got {
		if c.Offer.GetIdentity().GetCanonicalUrl() == "https://a/article" &&
			c.Offer.GetOfferId() != "a2" {
			t.Errorf("expected cheapest a2 to survive, got %q", c.Offer.GetOfferId())
		}
	}
}

func TestRank_TrustBeatsCost(t *testing.T) {
	cands := []selection.Candidate{
		{
			Offer:       offerWith("cheap", "url-a", 0.01),
			Marketplace: selection.MarketplaceRef{Domain: "mp1", Trust: "DISCOVERED"},
		},
		{
			Offer:       offerWith("expensive", "url-b", 0.05),
			Marketplace: selection.MarketplaceRef{Domain: "mp2", Trust: "PREFERRED"},
		},
	}
	got := selection.Rank(cands)
	if got[0].Offer.GetOfferId() != "expensive" {
		t.Errorf("winner = %q, want expensive (PREFERRED trust wins)", got[0].Offer.GetOfferId())
	}
}

func TestRank_TieBreakByCostThenPriority(t *testing.T) {
	cands := []selection.Candidate{
		{
			Offer:       offerWith("b", "url-a", 0.05),
			Marketplace: selection.MarketplaceRef{Domain: "mp1", Trust: "VERIFIED", Priority: 1},
		},
		{
			Offer:       offerWith("a", "url-b", 0.03),
			Marketplace: selection.MarketplaceRef{Domain: "mp2", Trust: "VERIFIED", Priority: 1},
		},
		{
			Offer:       offerWith("c", "url-c", 0.03),
			Marketplace: selection.MarketplaceRef{Domain: "mp3", Trust: "VERIFIED", Priority: 5},
		},
	}
	got := selection.Rank(cands)
	if got[0].Offer.GetOfferId() != "c" {
		t.Errorf("winner = %q, want c (priority breaks cost tie)", got[0].Offer.GetOfferId())
	}
}
