package offerkeys

// The shapes this resolver must refuse before it dials anything, and the proof
// that it dials nothing when it does.

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// TestResolve_RefusesADomainTheWireWouldNot pins the rule this resolver applies
// to the value an offer names: helpers.IsBareDomain, the same bytes
// protovalidate stamps on the field. The domain decides WHOSE key directory is
// fetched, so a value the wire would never admit must not send this process
// anywhere.
//
// The cases come from testutil.NonBareDomains, the one table of values this rule
// refuses, rather than from a list of this package's own. Several of its entries
// separate helpers.IsBareDomain from the weaker question of whether a value
// merely looks like a host, which is what stops the narrow rule being swapped
// for the weak one with every test still passing. A local list cannot hold that
// property, because it drifts: this package's own list carried six of the
// table's fifteen shapes and named no query, no fragment and no userinfo — and
// userinfo is the one that sends a fetch to a host the offer did not name.
func TestResolve_RefusesADomainTheWireWouldNot(t *testing.T) {
	t.Parallel()
	const host = "exchange.example"
	for _, tc := range testutil.NonBareDomains {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			domain := tc.Of(host)
			dials := &countingTransport{}
			r := New(Config{Client: &http.Client{Transport: dials}, Scheme: "http"})

			_, err := r.Resolve(context.Background(), domain)

			if !errors.Is(err, helpers.ErrUnknownKey) {
				t.Errorf("Resolve(%q) error = %v, want the unknown-key sentinel", domain, err)
			}
			if got := dials.count.Load(); got != 0 {
				t.Errorf("Resolve(%q) made %d request(s); a refused domain must be "+
					"refused before anything is dialled", domain, got)
			}
		})
	}
}

// countingTransport records every request that reaches it and answers none. A
// test that expects no fetch has to be able to tell "refused before dialling"
// from "dialled and the fetch failed".
type countingTransport struct{ count atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.count.Add(1)
	return nil, errors.New("countingTransport: no request should reach the network")
}
