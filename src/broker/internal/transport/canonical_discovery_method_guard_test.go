// Structural guard for the discovery-method presence contract: toWireOfferGroup
// writes OfferGroup.discovery_method ONLY when the resolve layer stamped it.
// resolve stamps every group it returns, so an unstamped group arriving here is
// a bug in resolve — and it must reach the agent as an ABSENT field rather than
// as the literal DISCOVERY_METHOD_UNSPECIFIED, which reads like an answer.
//
// The distinction is invisible to GetDiscoveryMethod(), which returns
// UNSPECIFIED for a field that is absent and for one explicitly written as zero.
// Only the pointer separates them, so these guards assert on it. That is what
// makes them worth having: discovery_method is a proto3 optional and the Broker
// serves this response with EmitUnpopulated, which omits an unset optional and
// emits the literal for an explicitly-written zero. Remove the guard in
// toWireOfferGroup and every RPC-level test still passes while agents start
// receiving "DISCOVERY_METHOD_UNSPECIFIED".
//
// White-box (package transport) unit test of the pure mapper toDiscoveryResponse,
// permitted by Testing Doctrine pt 2 (pure mapper logic), matching the
// canonical_absence_guard_test.go precedent it sits beside.

package transport

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
)

// TestDiscoveryMethodOmittedWhenUnstamped is the negative guard: a group the
// resolve layer left unstamped emits no discovery_method field at all.
func TestDiscoveryMethodOmittedWhenUnstamped(t *testing.T) {
	t.Parallel()
	out := toDiscoveryResponse(&resolve.Response{
		Groups: []resolve.OfferGroup{{URI: "https://acme.example/article-42"}},
	})

	groups := out.GetOfferGroups()
	if len(groups) != 1 {
		t.Fatalf("offer_groups = %d, want 1", len(groups))
	}
	if groups[0].DiscoveryMethod != nil {
		t.Errorf("discovery_method present (%v) on an unstamped group, want the field omitted — "+
			"an explicit zero reaches the agent as the string DISCOVERY_METHOD_UNSPECIFIED",
			groups[0].GetDiscoveryMethod())
	}
}

// TestDiscoveryMethodEmittedWhenStamped is the positive guard: a stamped group
// carries its value through to the wire, for every method the protocol defines.
// Driven from the generated enum map so a value added to the protocol is covered
// without editing this test.
func TestDiscoveryMethodEmittedWhenStamped(t *testing.T) {
	t.Parallel()
	for v, name := range rampv1.DiscoveryMethod_name {
		method := rampv1.DiscoveryMethod(v)
		if method == rampv1.DiscoveryMethod_DISCOVERY_METHOD_UNSPECIFIED {
			continue // the unset sentinel — covered by the omission guard above.
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := toDiscoveryResponse(&resolve.Response{
				Groups: []resolve.OfferGroup{{
					URI:             "https://acme.example/article-42",
					DiscoveryMethod: method,
				}},
			})

			groups := out.GetOfferGroups()
			if len(groups) != 1 {
				t.Fatalf("offer_groups = %d, want 1", len(groups))
			}
			if groups[0].DiscoveryMethod == nil {
				t.Fatal("discovery_method omitted on a stamped group, want the value emitted")
			}
			if got := groups[0].GetDiscoveryMethod(); got != method {
				t.Errorf("discovery_method = %v, want %v", got, method)
			}
		})
	}
}
