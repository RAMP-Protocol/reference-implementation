//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// TestPushResources_NamesAnotherExchange_RefusedWithNothingWritten drives the
// recipient check through the CATALOG surface, which is the one that carries
// the exposure: a push writes contributor-supplied entries into this Exchange's
// catalog, and the recipient field is what refuses a push captured for another
// Exchange and replayed here under a forged Host header. The signature does not
// establish that on its own — it proves the sender signed the URL it dialled,
// and the arriving request is where that URL is rebuilt.
//
// Every other test of the check runs on the ExchangeService mount, and the two
// mounts are built by different calls. Before this test, removing the check
// from the raw mount left the whole suite passing.
//
// The entry carries a priced term, so a push that went through would leave one
// discoverable offer behind. Reading zero back through DiscoverResources is
// what says the request was refused before the catalog was touched, rather than
// written and then reported as an error.
func TestPushResources_NamesAnotherExchange_RefusedWithNothingWritten(t *testing.T) {
	h := newPushHarness(t)
	const callerID = "caller.example"
	h.publisher.setContributors(callerID)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	const uriPath = "/articles/misaddressed"
	client := h.signedCat(callerID, priv)
	_, err = client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		Exchange: "other-exchange.example",
		Ver:      helpers.ProtocolVersion,
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: uriPath,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "addressed to a different Exchange")
	assertRecipientRefusal(t, err, "mismatch")

	offers := discoverOffersAs(t, h, "https://"+h.publisherDom+uriPath,
		requesterWithScopes("agent-discover"))
	if len(offers) != 0 {
		t.Errorf("offers for the refused entry = %d, want 0 — the push was written "+
			"before it was refused", len(offers))
	}
}
