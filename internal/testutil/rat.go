package testutil

import (
	"math/big"
	"testing"
)

// MustRat parses a decimal string into a *big.Rat, failing the test on a bad
// string. The one parse-or-fatal helper for test amounts — the repo, boot,
// transport, and tbtest suites all route through it, so the operation has one
// name across the tree.
func MustRat(tb testing.TB, s string) *big.Rat {
	tb.Helper()
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		tb.Fatalf("bad decimal amount %q", s)
	}
	return r
}
