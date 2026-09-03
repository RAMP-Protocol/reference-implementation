package rampclient

import (
	"context"
	"fmt"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// The per-origin client pool has no behaviour an outside caller can observe: it
// changes how many Connect clients exist, never what any call does. Its two
// properties are still worth pinning, because both fail silently — one as a
// connection built per call, the other as a map an authenticated caller can grow
// without limit — so they are asserted from inside the package, which is the
// only place they are visible at all.

// TestExchangePool_ReusesTheClientForOneOrigin pins that a repeated call to the
// same Exchange does not build a second client, which is what would otherwise
// abandon a transport per call.
func TestExchangePool_ReusesTheClientForOneOrigin(t *testing.T) {
	client := poolClient(t)
	ctx := context.Background()

	first, err := client.exchangeClient(ctx, "exchange.example", "register")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := client.exchangeClient(ctx, "exchange.example", "register")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Error("a second call to one Exchange built a second client")
	}
	if got := client.pool.Len(); got != 1 {
		t.Errorf("pool holds %d entries for one Exchange, want 1", got)
	}
}

// TestExchangePool_IsBoundedAtTheCap pins the bound. Which origins appear is
// driven by what authenticated agents ask for, so an unbounded map here is
// somewhere a caller can make this process grow.
func TestExchangePool_IsBoundedAtTheCap(t *testing.T) {
	client := poolClient(t)
	ctx := context.Background()

	for i := range maxPooledExchanges + 10 {
		domain := fmt.Sprintf("exchange-%d.example", i)
		if _, err := client.exchangeClient(ctx, domain, "register"); err != nil {
			t.Fatalf("resolve %s: %v", domain, err)
		}
	}
	if got := client.pool.Len(); got != maxPooledExchanges {
		t.Errorf("pool holds %d entries after %d distinct Exchanges, want the cap %d",
			got, maxPooledExchanges+10, maxPooledExchanges)
	}
}

// poolClient builds a client whose resolver answers for every domain, so the
// pool is the only thing under test.
func poolClient(t *testing.T) *Client {
	t.Helper()
	client, err := New(Config{
		Keys:         testutil.AgentKeySource(t, "https://agent.example"),
		BrokerURL:    "http://broker.example",
		Endpoints:    everyDomainResolver{},
		ExchangeBase: resolvers.NewGuardedTransport(nil),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

// everyDomainResolver gives each domain its own endpoint, so distinct domains
// produce distinct pool keys and nothing is dialled.
type everyDomainResolver struct{}

func (everyDomainResolver) ResolveEndpoint(_ context.Context, host string) (string, error) {
	return "https://" + host, nil
}
