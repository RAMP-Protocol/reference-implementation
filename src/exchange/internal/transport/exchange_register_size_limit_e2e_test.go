//go:build integration

package transport_test

import (
	"fmt"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// This file covers the Register RPC's size limits: the coarse
// whole-body read cap (connect.WithReadMaxBytes) and the tighter, semantic bound
// on registration_data at the gate. Kept separate from exchange_register_e2e_test.go
// (the core registration flow) so each file stays a single scenario.

// assertNoAccount proves a rejected Register wrote no account: the agents row
// carries no billing_ref (observed through AgentRepo, the production read
// surface — Testing Doctrine §9), and so the SoR/ledger were never reached. The
// row itself may exist from lazy self-signup; what must be absent is the account
// (billing_ref + SoR + ledger), which the rejected gate never wrote.
func assertNoAccount(t *testing.T, h *registerHarness, agentID string) {
	t.Helper()
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, agentID)
	if err != nil {
		t.Fatalf("AgentRepo.ByID(%q): %v", agentID, err)
	}
	if agent.BillingRef != "" {
		t.Fatalf("billing_ref = %q, want empty (a rejected register must write none)", agent.BillingRef)
	}
}

// TestExchangeRegister_RegistrationDataBounds drives the Register gate's size
// limits through the real router: a registration_data payload over the byte
// budget, and one over the key-count budget, are each rejected InvalidArgument
// with no account written. The bound is what stops a validly-signed caller from
// writing an unbounded blob into the account's extra JSONB column.
func TestExchangeRegister_RegistrationDataBounds(t *testing.T) {
	t.Run("over the byte budget is InvalidArgument", func(t *testing.T) {
		h := newRegisterHarness(t)
		a := h.newAgent(t, "oversize.example")
		// One value past the per-registration byte gate but well under the
		// whole-message read cap, so it reaches the handler and the gate rejects it.
		big := strings.Repeat("x", 20*1024)
		_, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{
			Ver:              "1.0",
			RegistrationData: mustRegistrationStruct(t, map[string]any{"blob": big}),
		}))
		if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
		}
		assertNoAccount(t, h, a.id)
	})

	t.Run("over the key-count budget is InvalidArgument", func(t *testing.T) {
		h := newRegisterHarness(t)
		a := h.newAgent(t, "toomanykeys.example")
		m := make(map[string]any, 65)
		for i := 0; i < 65; i++ {
			m[fmt.Sprintf("k%d", i)] = "v"
		}
		_, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{
			Ver:              "1.0",
			RegistrationData: mustRegistrationStruct(t, m),
		}))
		if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
		}
		assertNoAccount(t, h, a.id)
	})
}

// TestExchangeRegister_BodyOverReadCap proves the Connect handlers' read cap
// (connect.WithReadMaxBytes) rejects a message larger than the configured max
// before the handler runs. A signed caller sending a body past the cap gets
// ResourceExhausted — the coarse outer wall that stands behind the tighter,
// semantic registration_data gate.
func TestExchangeRegister_BodyOverReadCap(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "overcap.example")
	// One value past the whole-message read cap, so the server rejects it during
	// read — before any handler, self-signup, or the registration_data gate runs.
	huge := strings.Repeat("x", transport.MaxRPCReadBytes+4096)
	_, err := a.client.Register(h.ctx, connect.NewRequest(&rampv1.RegisterRequest{
		Ver:              "1.0",
		RegistrationData: mustRegistrationStruct(t, map[string]any{"blob": huge}),
	}))
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted (err=%v)", got, err)
	}
}
