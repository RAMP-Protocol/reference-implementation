package resolve

// The Broker authors each fan-out leg, so it states who that leg is for. The
// value comes from the registry row, which is operator input, and this is what
// happens when that input cannot be a recipient.

import (
	"context"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

// TestQueryExchange_RegisteredDomainThatCannotBeARecipientIsNotDialled pins that
// a registry row holding a value the wire does not admit fails here, naming the
// registration, rather than at the far end. The exchange would refuse the leg as
// malformed, and that refusal names the Broker's registry nowhere — the operator
// sees an exchange that returns nothing.
//
// It drives the leg builder directly rather than a whole resolve. The property
// is "nothing was dialled", and the recording caller below is what can say so;
// through the public surface the same registry row also decides routing, so a
// failure there could not be told apart from the leg never being routed.
func TestQueryExchange_RegisteredDomainThatCannotBeARecipientIsNotDialled(t *testing.T) {
	t.Parallel()
	for name, domain := range map[string]string{
		"underscored container alias": "ex_change.internal",
		"origin rather than a domain": "https://exchange.example",
		"port zero":                   "exchange.example:0",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			calls := &recordingExchangeCaller{}
			h := NewService(Deps{Exchange: calls})

			_, err := h.queryExchange(context.Background(), Request{},
				repo.Exchange{Domain: domain, Endpoint: "http://exchange.invalid"}, nil)

			if err == nil {
				t.Fatalf("a leg was addressed to %q, which no exchange can answer to", domain)
			}
			if !strings.Contains(err.Error(), domain) {
				t.Errorf("error %q does not name the registered domain", err)
			}
			if calls.discovers != 0 {
				t.Errorf("the exchange was dialled %d time(s); the leg must fail before it is "+
					"signed and sent", calls.discovers)
			}
		})
	}
}

// recordingExchangeCaller counts the legs that reach the wire. It answers none:
// every case here must fail before it is called, and a case that did call it
// would otherwise pass on the stub's own reply.
type recordingExchangeCaller struct {
	xclient.ExchangeCaller
	discovers int
}

func (r *recordingExchangeCaller) DiscoverResources(
	context.Context, string, *rampv1.ResourceQuery,
) (*rampv1.ResourceResponse, error) {
	r.discovers++
	return &rampv1.ResourceResponse{Ver: helpers.ProtocolVersion}, nil
}
