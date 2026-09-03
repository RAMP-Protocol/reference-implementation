//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"
)

// TestPushResources_ProtovalidateOwnedReject proves the protovalidate
// interceptor is wired into the integration harness exactly as production wires
// it (cmd/server/main.go::registerConnect), and that it owns a class of
// rejection NO service guard owns. The Pricing message carries buf.validate CEL
// (ramp.proto Pricing: PER_UNIT⇒unit, FREE⇒rate 0); the interceptor runs BEFORE
// the handler, so a CEL violation fails the WHOLE RPC with InvalidArgument —
// distinct from the per-entry verdict the service's gate chain (the SDK's
// ingest-tier term checks and the Exchange-owned gates) returns. Without the
// interceptor in startExchangeServer (RAMP-obtjf)
// these requests reached the handler and produced a different outcome than
// production, making the harness only a partial mirror.
//
// Both legs are observed solely through the public surface: the RPC error code
// for the rejection, and DiscoverResources offer-count for the absence of any
// side effect (Testing Doctrine pt 9 — no DB/repo/sqlc access). A protovalidate
// reject must leave zero discoverable offers.
func TestPushResources_ProtovalidateOwnedReject(t *testing.T) {
	h := newPushHarness(t)
	callerID := "caller.example"
	client := setupTermContributor(t, h, callerID)

	// A valid PER_UNIT pricing so the restriction-token case clears the pricing
	// CEL and isolates the restriction.permitted.format violation.
	pricedUnit := &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.02", Currency: "USD", Unit: proto.String("accesses")}

	cases := []struct {
		name         string
		path         string
		pricing      *rampv1.Pricing
		restrictions []*rampv1.Restriction
	}{
		{
			// pricing.per_unit.requires_unit: PER_UNIT with no unit is a
			// structural CEL violation the interceptor rejects before the
			// service's ingest-tier term checks run.
			name:    "PER_UNIT without unit fails protovalidate",
			path:    "/protovalidate/per-unit-no-unit",
			pricing: &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD"},
		},
		{
			// pricing.free.zero_rate: FREE with a non-zero rate is contradictory
			// and likewise CEL-rejected at the boundary.
			name:    "FREE with non-zero rate fails protovalidate",
			path:    "/protovalidate/free-nonzero-rate",
			pricing: &rampv1.Pricing{Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "5", Currency: "USD"},
		},
		{
			// restriction.permitted.format: a whitespace/control-char token is a
			// structural CEL violation rejected at the wire BEFORE the service
			// canonicalizes tokens (the SDK's NormalizeResourceEntry, which would
			// trim it). The trimming itself is the SDK's, pinned by the protocol
			// module's license-term vector corpus (its fold list); through the RPC
			// the contract requires already-clean tokens — a publisher must
			// canonicalize before pushing (the ingest mapper does, via
			// helpers.NormalizeLicenseTerm).
			name:         "whitespace restriction token fails protovalidate",
			path:         "/protovalidate/restriction-whitespace",
			pricing:      pricedUnit,
			restrictions: []*rampv1.Restriction{{Kind: rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY, Permitted: []string{" de "}}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
				Domain: h.publisherDom,
				Path:   tc.path,
				Terms: []*rampv1.LicenseTerm{{
					Semantics:    rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
					Pricing:      tc.pricing,
					Restrictions: tc.restrictions,
				}},
			}})))
			// The interceptor fails the whole RPC — not a 200 with rejected=1.
			assertConnectCode(t, err, connect.CodeInvalidArgument)
			// And nothing persisted: the rejected push leaves zero offers.
			if got := discoverOfferCount(t, h, "https://"+h.publisherDom+tc.path); got != 0 {
				t.Fatalf("DiscoverResources offers = %d, want 0 (protovalidate reject must not persist)", got)
			}
		})
	}
}

// TestDiscoverResources_ProtovalidateRejectsWhitespaceAcceptableRestriction is
// the discover-side mirror of the restriction-token format rule. The proto
// overhaul unified the restriction vocabulary, so AcceptableRestriction.values
// carries the SAME acceptable_restriction.values.format CEL as
// Restriction.permitted. Even though acceptable_restrictions are advisory and
// the Exchange ignores them for selection (ADR-014), a whitespace value is a
// structural wire violation rejected by the interceptor before the handler —
// locking the format contract on both request shapes the overhaul unified.
func TestDiscoverResources_ProtovalidateRejectsWhitespaceAcceptableRestriction(t *testing.T) {
	h := newPushHarness(t)
	query := newResourceQuery(newRequester("agent-discover", "agent.example"),
		[]string{"https://" + h.publisherDom + "/protovalidate/acceptable-whitespace"})
	query.AcceptableRestrictions = []*rampv1.AcceptableRestriction{{
		Axis:   rampv1.RestrictionKind_RESTRICTION_KIND_GEOGRAPHY,
		Values: []string{" de "},
	}}
	_, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(query))
	assertConnectCode(t, err, connect.CodeInvalidArgument)
}
