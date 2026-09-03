//go:build integration

package transport_test

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"
)

// TestResolve_EachFanOutLegNamesTheExchangeItGoesTo pins what the Broker states
// when it authors a discovery leg. The agent asks for URLs; the Broker chooses
// which Exchanges see them, so the Broker is the sender that names each
// recipient — one value per leg, the registered domain of the Exchange that leg
// is dialled at.
//
// Two Exchanges is the whole point. With one, stamping the Broker's own domain
// on every leg, or the first Exchange's domain on all of them, is
// indistinguishable from stamping each leg's own. Here the second Exchange
// refuses anything not addressed to it, and both recorded values are read back.
func TestResolve_EachFanOutLegNamesTheExchangeItGoesTo(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{
		providerDomain: "acme.example",
		secondary: &secondaryProvider{
			providerDomain:    "beta.example",
			exchangeDomain:    "mp.beta.example",
			offerID:           "offer-2",
			offerCost:         0.05,
			offerCanonicalURL: "https://beta.example/article-2",
		},
	})

	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, "agent-1", pub)
	client := signingBrokerClient(srv.base, srv.server.URL, "agent-1", priv)
	out, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest("agent-1", reqOpts{
		uris: []string{
			"https://acme.example/article-1",
			"https://beta.example/article-2",
		},
		budgetMinor: 100000,
	})))
	if err != nil {
		t.Fatalf("Resolve returned transport error: %v", err)
	}
	// Both legs must have been served. A leg refused for its recipient comes back
	// as a group with no offers, so this is what separates "addressed correctly"
	// from "refused by both Exchanges and reported as nothing found".
	if len(out.Msg.GetOfferGroups()) < 2 {
		t.Fatalf("offer_groups = %d, want 2 — a leg was refused before it was served",
			len(out.Msg.GetOfferGroups()))
	}

	for _, leg := range []struct {
		name string
		got  string
		want string
	}{
		{"first exchange", fx.exchange.lastDiscoverExchange, mockExchangeDomain},
		{"second exchange", fx.exchange2.lastDiscoverExchange, "mp.beta.example"},
	} {
		if leg.got != leg.want {
			t.Errorf("%s was addressed as %q, want its own domain %q", leg.name, leg.got, leg.want)
		}
	}
}
