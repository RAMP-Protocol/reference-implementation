// Package transactionkey owns how the Exchange names one item of a multi-item
// request in the transaction log.
//
// Three places need the same answer: the write path that stores the row, the
// idempotent-replay probe that looks the row up again, and the operator ledger
// that verifies the stored key rebuilds from the key the agent signed. They live
// in two different binaries, so a fourth hand-written copy of the expression is
// how they drift apart.
//
// Drift here does not surface as a mismatch. The ledger reports its
// transaction-log assertion as FAILED for every transaction it renders, which
// reads as evidence of tampering rather than as two components disagreeing about
// a string.
//
// This is a COMPATIBILITY CONTRACT, not an internal helper. One shared function
// removes the risk of two call sites in one revision disagreeing; it does
// nothing about version skew between a deployed Exchange and a newer ledger
// binary, which can still disagree and still produce that false verdict.
// Changing the formula therefore breaks every ledger run against an Exchange
// that has already written rows under the old one. The pinned vector in the test
// beside this file exists to make such a change fail loudly rather than ship.
package transactionkey

// DerivedItemKey names one item of a request: the request-level idempotency key
// the agent signed, then the offer id of the item.
//
// Distinct offer ids give distinct keys, which is what keeps the
// idempotency_key UNIQUE backstop and the billing dedup from collapsing the
// items of one multi-item request into a single row.
func DerivedItemKey(requestKey, offerID string) string {
	return requestKey + ":" + offerID
}
