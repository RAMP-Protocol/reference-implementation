package billing_test

import (
	"context"
	"testing"
)

// Account-registration cases of the adapter conformance suite (registered in
// runAdapterConformance, adapter_conformance_test.go): EnsureAgentAccount is
// the Register flow's ledger-account creation, keyed by billing_ref.

// confEnsureAgentAccount: EnsureAgentAccount succeeds, a repeat is a no-op, and
// the fresh account holds a zero balance. GetBalance and Authorize both key on
// the billing_ref now (ADR-021 D5), so reading with the same ref sees the
// account EnsureAgentAccount created (InMemory: the balances map key;
// TigerBeetle: AccountID(PrefixAgent, ns+ref)).
func confEnsureAgentAccount(t *testing.T, f adapterFactory) {
	ctx := context.Background()
	a := f.new(conformanceSeed{})
	const ref = "billing-ref-fresh"
	if err := a.EnsureAgentAccount(ctx, ref); err != nil {
		t.Fatalf("EnsureAgentAccount: %v", err)
	}
	if err := a.EnsureAgentAccount(ctx, ref); err != nil {
		t.Fatalf("repeat EnsureAgentAccount must be a no-op success, got %v", err)
	}
	bal, err := a.GetBalance(ctx, ref)
	if err != nil {
		t.Fatalf("GetBalance(%q): %v", ref, err)
	}
	if bal.Value.Sign() != 0 {
		t.Errorf("fresh agent account balance = %s, want 0", bal.Value.FloatString(4))
	}
}

// confEnsureAgentAccountFunded: ensuring over an account that already holds a
// funded balance is success AND leaves the balance untouched — a repeated
// registration must never zero an account. (The seeded "ag" account and a
// billing_ref are looked up under the same kind of key — the account handle.)
func confEnsureAgentAccountFunded(t *testing.T, f adapterFactory) {
	a := seedTen(t, f)
	if err := a.EnsureAgentAccount(context.Background(), "ag"); err != nil {
		t.Fatalf("EnsureAgentAccount over funded account: %v", err)
	}
	assertBalance(t, a, "10.00")
}

// confEnsureAgentAccountEmptyRef: an empty billing_ref is a caller bug and is
// rejected with an error, creating nothing.
func confEnsureAgentAccountEmptyRef(t *testing.T, f adapterFactory) {
	a := f.new(conformanceSeed{})
	if err := a.EnsureAgentAccount(context.Background(), ""); err == nil {
		t.Fatal(`EnsureAgentAccount("") = nil, want error`)
	}
}
