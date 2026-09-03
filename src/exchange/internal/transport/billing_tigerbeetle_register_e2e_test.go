//go:build integration

package transport_test

import (
	"testing"
)

// Registration-time default credit against a real TigerBeetle ledger: the
// grant is a real posted transfer from platform:liquidity, keyed on the shared
// welcome-slot transfer id (billing.WelcomeCreditKey), so a repeat Register —
// or an operator prefund that already occupies the slot — can never credit
// twice. The spend-side money movement for the granted credit is covered by
// the balance-bearing in-memory flow (register_default_credit_e2e_test.go)
// and by the adapter conformance suite, which runs the same Credit contract
// on this ledger.

// TestTigerBeetleRegister_DefaultCreditGrantedOnce: with a tenant default of
// 25.00, Register grants a real ledger credit once; a repeat Register takes
// the fast path and the balance stays 25.00.
func TestTigerBeetleRegister_DefaultCreditGrantedOnce(t *testing.T) {
	salt := sharedTB.Salt(t)
	h := newRegisterHarnessWith(t, registerHarnessOptions{billing: newTBAdapter(salt)})
	setTenantDefaultCredit(t, h.arrange(), "25.00")

	a := h.newAgent(t, "tb-credit-agent.example")
	ref := registerCaller(t, h.ctx, a.client)
	assertBalanceThrough(t, h.ctx, h.billing, ref, "25.00")

	if again := registerCaller(t, h.ctx, a.client); again != ref {
		t.Fatalf("repeat billing_ref = %q, want %q", again, ref)
	}
	assertBalanceThrough(t, h.ctx, h.billing, ref, "25.00")
}

// TestTigerBeetleRegister_ScriptPrefundSharesWelcomeSlot: an agent already
// funded by the operator script under the reserved service-welcome label is
// NOT double-credited by Register. The prefund posts the exact transfer id the
// service derives (salt + WelcomeCreditKey), so the service's grant finds the slot
// occupied and no-ops — the balance stays the prefund amount, not prefund +
// tenant default. The billing_ref generator is deterministic ("billing-ref-1"),
// which is what lets the prefund land before the agent registers, exactly like
// an operator funding a known account ahead of onboarding.
func TestTigerBeetleRegister_ScriptPrefundSharesWelcomeSlot(t *testing.T) {
	salt := sharedTB.Salt(t)
	h := newRegisterHarnessWith(t, registerHarnessOptions{billing: newTBAdapter(salt)})
	setTenantDefaultCredit(t, h.arrange(), "100.00")

	const expectedRef = "billing-ref-1"
	tbLedger().MustFundAgentWelcome(t, salt, expectedRef, "55.00")

	ref := registerCaller(t, h.ctx, h.newAgent(t, "tb-prefunded-agent.example").client)
	if ref != expectedRef {
		t.Fatalf("billing_ref = %q, want %q (deterministic generator)", ref, expectedRef)
	}
	assertBalanceThrough(t, h.ctx, h.billing, ref, "55.00")
}
