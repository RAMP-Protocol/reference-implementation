package tigerbeetle

import "testing"

// TestReasonToken pins the refund audit token: empty → 0, non-empty → a stable
// non-zero value, distinct reasons → distinct tokens.
func TestReasonToken(t *testing.T) {
	if got := ReasonToken(""); got != 0 {
		t.Errorf(`ReasonToken("") = %d, want 0`, got)
	}
	d := ReasonToken("dispute")
	if d == 0 {
		t.Error(`ReasonToken("dispute") = 0, want non-zero`)
	}
	if ReasonToken("dispute") != d {
		t.Error("ReasonToken must be deterministic")
	}
	if ReasonToken("fraud") == d {
		t.Error("distinct reasons must yield distinct tokens")
	}
}
