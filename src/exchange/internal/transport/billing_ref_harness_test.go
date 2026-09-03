//go:build integration

package transport_test

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
)

// defaultCallerBillingRef is the billing_ref the default transport harness
// registers agent-test under (ADR-021 D5). The harness injects a
// deterministic billing_ref generator returning this value, so the account key
// is known at adapter-construction time and the seeded balance can be keyed by
// the ref before Register's EnsureAgentAccount runs. It is deliberately DISTINCT
// from the agent id ("agent-test") so a test asserting the charge landed on the
// ref-keyed account cannot pass by accident against the old agent-id-keyed one.
const defaultCallerBillingRef = "billing-agent-test"

// registerCaller registers an agent through the public Register RPC — the same
// production path (ADR-021) a real agent takes to mint its billing_ref, create
// its ledger account, and store the ref on its agents row. It returns the minted
// ref without asserting its value; harnesses whose billing_ref generator is a
// plain uuid (no seeded balance to match) use this. The client must sign as the
// agent being registered — Register keys on the verified caller identity, and a
// broker caller is refused.
func registerCaller(t *testing.T, ctx context.Context, client rampconnect.ExchangeServiceClient) string {
	t.Helper()
	resp, err := client.Register(ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("register caller: %v", err)
	}
	return resp.Msg.GetBillingRef()
}

// registerDefaultCaller registers the harness's default agent and asserts the
// minted ref equals the deterministic generator's value, so a caller that seeded
// the balance under defaultCallerBillingRef can rely on the account key matching.
func registerDefaultCaller(t *testing.T, ctx context.Context, client rampconnect.ExchangeServiceClient) string {
	t.Helper()
	ref := registerCaller(t, ctx, client)
	if ref != defaultCallerBillingRef {
		t.Fatalf("registered billing_ref = %q, want %q (deterministic generator)", ref, defaultCallerBillingRef)
	}
	return ref
}
