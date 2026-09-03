package tigerbeetle

import (
	"testing"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// TestLinkedOutcome pins the linked-batch status reduction, including the
// pending-resolved statuses (already-posted / already-voided / expired) that a late
// Record on a linked settlement must surface as LinkedPendingResolved so the adapter
// maps it to ErrUnknownBillingID — the same classification the single post-pending
// path gives ResolveAlreadyResolved.
func TestLinkedOutcome(t *testing.T) {
	tests := []struct {
		name    string
		status  tb.CreateTransferStatus
		want    LinkedOutcome
		wantErr bool
	}{
		{"created", tb.TransferCreated, LinkedApplied, false},
		{"exists", tb.TransferExists, LinkedApplied, false},
		{"exceeds_credits", tb.TransferExceedsCredits, LinkedExceedsCredits, false},
		{"exceeds_debits", tb.TransferExceedsDebits, LinkedExceedsCredits, false},
		{"already_posted", tb.TransferPendingTransferAlreadyPosted, LinkedPendingResolved, false},
		{"already_voided", tb.TransferPendingTransferAlreadyVoided, LinkedPendingResolved, false},
		{"expired", tb.TransferPendingTransferExpired, LinkedPendingResolved, false},
		{"exists_different_amount", tb.TransferExistsWithDifferentAmount, LinkedExistsMismatch, false},
		{"exists_different_flags", tb.TransferExistsWithDifferentFlags, LinkedExistsMismatch, false},
		{"exists_different_debit", tb.TransferExistsWithDifferentDebitAccountID, LinkedExistsMismatch, false},
		{"exists_different_credit", tb.TransferExistsWithDifferentCreditAccountID, LinkedExistsMismatch, false},
		{"exists_different_pending", tb.TransferExistsWithDifferentPendingID, LinkedExistsMismatch, false},
		{"exists_different_ud128", tb.TransferExistsWithDifferentUserData128, LinkedExistsMismatch, false},
		{"exists_different_ud64", tb.TransferExistsWithDifferentUserData64, LinkedExistsMismatch, false},
		{"exists_different_ud32", tb.TransferExistsWithDifferentUserData32, LinkedExistsMismatch, false},
		{"exists_different_timeout", tb.TransferExistsWithDifferentTimeout, LinkedExistsMismatch, false},
		{"exists_different_ledger", tb.TransferExistsWithDifferentLedger, LinkedExistsMismatch, false},
		{"exists_different_code", tb.TransferExistsWithDifferentCode, LinkedExistsMismatch, false},
		{"unexpected", tb.TransferPendingTransferNotFound, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := linkedOutcome([]tb.CreateTransferResult{{Status: tc.status}})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("status %v: want error, got outcome %v", tc.status, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("status %v: unexpected error: %v", tc.status, err)
			}
			if got != tc.want {
				t.Errorf("status %v: outcome = %v, want %v", tc.status, got, tc.want)
			}
		})
	}
}
