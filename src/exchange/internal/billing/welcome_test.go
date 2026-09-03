package billing_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing/tigerbeetle"
)

// TestWelcomeCreditKey_PinnedTransferVector pins the full welcome-slot
// derivation — key string and the transfer id hashed from it — against a
// checked-in vector. The same derivation is hand-written in shell in
// deploy/terraform/scripts/fund-staging-agent.sh (the "service-welcome" label
// branch), which no compiler checks: if this test fails, the Go side moved and
// that script MUST be updated in the same change, or a script prefund and the
// Register grant would land in different ledger slots and double-credit the
// agent.
func TestWelcomeCreditKey_PinnedTransferVector(t *testing.T) {
	const ref = "00000000-0000-4000-8000-000000000000"

	key := billing.WelcomeCreditKey(ref)
	if want := "service-welcome:" + ref; key != want {
		t.Fatalf("WelcomeCreditKey(%q) = %q, want %q — update fund-staging-agent.sh in the same change",
			ref, key, want)
	}

	id, err := tigerbeetle.TransferID(key)
	if err != nil {
		t.Fatalf("TransferID(%q): %v", key, err)
	}
	// The little-endian low 16 bytes of sha256(key): the hex form is what
	// EncodeID renders; the decimal form is what fund-staging-agent.sh's tb_id
	// computes and hands to the tigerbeetle repl.
	if got, want := tigerbeetle.EncodeID(id), "c4a169c39a64f2e4738a2836b54331de"; got != want {
		t.Fatalf("welcome transfer id = %s, want %s — the ledger-slot derivation moved; "+
			"update fund-staging-agent.sh in the same change", got, want)
	}
	if got, want := id.BigInt().String(), "295344410888821591469791452966301573572"; got != want {
		t.Fatalf("welcome transfer id (decimal) = %s, want %s — must match fund-staging-agent.sh's tb_id",
			got, want)
	}
}
