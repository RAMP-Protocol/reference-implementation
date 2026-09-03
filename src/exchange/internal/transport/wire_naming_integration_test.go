//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// The two tests here answer a question the rest of this package cannot: what
// field names does the Exchange actually put on the JSON wire?
//
// Every other test in this package drives its calls over gRPC, where proto
// framing carries field numbers and the JSON codec never runs. So a mount that
// lost connectserver.WithEmitUnpopulated — or the raw mount's
// connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()) — would serve the
// camelCase json_name alias to every JSON client while this suite stayed
// entirely quiet. A Go client reads both spellings and would not complain
// either. A reader built from the generated Pydantic or Zod schemas refuses the
// answer outright, because those declare proto names only.
//
// internal/guards holds the source-level half of this: no mount may be written
// without the codec. This is the behavioral half — the codec is registered AND
// it does what its name says.

// TestDiscoverResources_ServesCanonicalProtoNamesOnTheJSONWire drives the
// SDK-wrapped ExchangeService mount over Connect-JSON and reads the bytes back.
func TestDiscoverResources_ServesCanonicalProtoNamesOnTheJSONWire(t *testing.T) {
	h := newTestHarness(t)
	wire := h.jsonWireClients()

	seedOneArticle(t, h, wire.catalog, "/wire-names/discover")

	resp, err := wire.exchange.DiscoverResources(h.ctx, connect.NewRequest(
		newResourceQuery(
			newRequester("agent-test", "agent.example"),
			[]string{"https://" + h.tenantDomain + "/wire-names/discover"},
		),
	))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(resp.Msg.GetOffers()) == 0 {
		t.Fatal("discover returned no offers, so the response carries none of the " +
			"nested fields this test exists to read")
	}
	testutil.AssertCanonicalWireNames(t, wire.exchangeCapture.Body(t), resp.Msg)
}

// TestPushResources_ServesTheCanonicalCodecOnTheJSONWire covers the RAW
// CatalogService mount, which takes its options from RawValidatedMountOptions
// rather than the connectserver seam and so would drift on its own.
//
// Both assertions below are load-bearing, and each catches a different drift.
//
// Emit-unpopulated is what puts anything on this wire to read. A push that
// rejects nothing answers rejected = 0, which default protojson omits and the
// canonical codec keeps; lose the codec option altogether and the body is
// {"ver":"1.0","accepted":1}, which AssertWireCarries catches. The naming walk
// stays quiet there, because a field that is not emitted has no spelling.
//
// The walk catches the narrower drift: a codec that still emits unpopulated
// fields but no longer pins UseProtoNames. PushResourcesResponse carries six
// fields and only one, ext_critical, has a name of more than one word. It is a
// repeated string a push never fills, so emit-unpopulated writes it as an empty
// list — "ext_critical" canonically, "extCritical" under default naming, which
// is what the walk reports. Measured both ways against this mount.
func TestPushResources_ServesTheCanonicalCodecOnTheJSONWire(t *testing.T) {
	h := newTestHarness(t)
	wire := h.jsonWireClients()

	resp := seedOneArticle(t, h, wire.catalog, "/wire-names/push")
	body := wire.catalogCapture.Body(t)
	testutil.AssertWireCarries(t, body, resp, "rejected")
	testutil.AssertCanonicalWireNames(t, body, resp)
}

// seedOneArticle pushes one priced article through catalogClient and returns
// the response, so both tests above use the same catalog shape.
func seedOneArticle(
	t *testing.T, h *testHarness, catalogClient rampconnect.CatalogServiceClient, path string,
) *rampv1.PushResourcesResponse {
	t.Helper()
	resp, err := catalogClient.PushResources(h.ctx, connect.NewRequest(
		newPushRequest(h.tenantID, "agent-test", []*rampv1.ResourceEntry{{
			Domain: h.tenantDomain,
			Path:   path,
			Terms:  []*rampv1.LicenseTerm{seedPricedTermEst(50)},
		}}),
	))
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 {
		t.Fatalf("push accepted = %d, want 1", resp.Msg.GetAccepted())
	}
	return resp.Msg
}
