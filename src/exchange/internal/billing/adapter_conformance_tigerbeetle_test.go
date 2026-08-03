//go:build integration

package billing_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tbtest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

const (
	tbConfLedger uint32 = 840 // ISO 4217 USD; the conformance amounts are USD.
	tbConfScale  uint8  = 8   // matches the adapter's default asset scale.
)

var (
	tbShared    *testutil.SharedTigerBeetle
	tbClient    *tigerbeetle.Client
	tbNSCounter atomic.Uint64
)

// TestMain brings up one TigerBeetle container for the whole billing_test package
// under -tags integration. The in-memory conformance suite runs in the fast lane
// (no build tag) with the default test main, so this does not slow test-fast.
func TestMain(m *testing.M) {
	os.Exit(runBillingIntegrationMain(m))
}

func runBillingIntegrationMain(m *testing.M) int {
	ctx := context.Background()
	shared, cleanup, err := testutil.StartSharedTigerBeetle(ctx, testutil.DiscardLogger())
	if err != nil {
		fmt.Fprintf(os.Stderr, "start shared tigerbeetle: %v\n", err)
		return 1
	}
	defer cleanup()
	tbShared = shared

	client, closeClient, err := tbtest.BootClient(shared.Address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tigerbeetle client: %v\n", err)
		return 1
	}
	defer closeClient()
	tbClient = client
	return m.Run()
}

// TestTigerBeetleConformance runs the shared adapter conformance suite against a real
// TigerBeetle ledger. Each subtest gets a fresh, uniquely-namespaced adapter — so the
// suite's fixed agent id and idempotency keys never collide on the one shared cluster
// — and its seed balance is funded as a real ledger credit. The factory sets
// supportsRefund=true, so every refund case runs against the real ledger.
func TestTigerBeetleConformance(t *testing.T) {
	runAdapterConformance(t, tigerBeetleFactory())
}

func tigerBeetleFactory() adapterFactory {
	return adapterFactory{
		name:                   "TigerBeetleAdapter",
		supportsRefund:         true,
		requiresIdempotencyKey: true,
		new: func(seed conformanceSeed) billing.Adapter {
			adapter, ns := newTBAdapter("conf", time.Minute)
			if err := fundSeed(context.Background(), ns, seed); err != nil {
				panic(fmt.Sprintf("tigerbeetle conformance: fund seed: %v", err))
			}
			return adapter
		},
	}
}

// newTBAdapter builds a TigerBeetleAdapter on the shared cluster under a fresh,
// uniquely-namespaced id salt (prefix + a monotonic counter), with the package's
// constant ledger / currency / asset scale. A zero holdTimeout takes the adapter
// default. Returns the adapter and its id namespace — the salt callers pass to
// fundSeed and to account-id derivation. Centralizes the construction the four TB
// integration sites otherwise repeat.
func newTBAdapter(prefix string, holdTimeout time.Duration) (billing.Adapter, string) {
	ns := fmt.Sprintf("%s%d:", prefix, tbNSCounter.Add(1))
	adapter := billing.NewTigerBeetleAdapter(billing.TigerBeetleOptions{
		Client:      tbClient,
		Ledger:      tbConfLedger,
		Currency:    "USD",
		AssetScale:  tbConfScale,
		HoldTimeout: holdTimeout,
		IDNamespace: ns,
	})
	return adapter, ns
}

// fundSeed simulates the operator's out-of-band manual credit (ADR-009 D2): it
// posts a settled credit into each seeded agent account so the prepaid balance the
// suite draws down actually exists on the ledger. The funding shape lives in
// tbtest, shared with the transport E2E suite. Test-only wiring — production
// funding is not part of the adapter. t-free so the factory closure can call it.
func fundSeed(ctx context.Context, ns string, seed conformanceSeed) error {
	led := confLedger()
	for agent, amt := range seed.Balances {
		if err := led.FundAgent(ctx, ns, agent, amt.Value); err != nil {
			return err
		}
	}
	return nil
}

// confLedger is the shared TigerBeetle test handle for the billing_test package,
// bound to the conformance ledger + asset scale. Used by fundSeed and the
// settlement-split assertions.
func confLedger() tbtest.Ledger {
	return tbtest.Ledger{Client: tbClient, ID: tbConfLedger, Scale: tbConfScale}
}
