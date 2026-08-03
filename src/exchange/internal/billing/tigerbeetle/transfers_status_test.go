package tigerbeetle

import (
	"errors"
	"testing"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// The status→outcome mappers are pure state logic with >3 branches, so they are
// unit-tested directly (Testing Doctrine point 2); the round-trip against a real
// ledger is exercised in transfers_integration_test.go.

func TestPendingOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   tb.CreateTransferStatus
		want PendingOutcome
		err  bool
	}{
		{"created", tb.TransferCreated, PendingCreated, false},
		{"exists", tb.TransferExists, PendingExists, false},
		{"exceeds_credits", tb.TransferExceedsCredits, PendingInsufficientFunds, false},
		{"unmapped", tb.TransferPendingTransferNotFound, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := pendingOutcome(tc.in)
			if tc.err {
				if !errors.Is(err, ErrCreateTransfer) {
					t.Fatalf("pendingOutcome(%v) err = %v, want ErrCreateTransfer", tc.in, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("pendingOutcome(%v) = (%v, %v), want (%v, nil)", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestResolveOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   tb.CreateTransferStatus
		want ResolveOutcome
		err  bool
	}{
		{"applied", tb.TransferCreated, ResolveApplied, false},
		{"exists", tb.TransferExists, ResolveExists, false},
		{"not_found", tb.TransferPendingTransferNotFound, ResolveNotFound, false},
		{"already_posted", tb.TransferPendingTransferAlreadyPosted, ResolveAlreadyResolved, false},
		{"already_voided", tb.TransferPendingTransferAlreadyVoided, ResolveAlreadyResolved, false},
		{"expired", tb.TransferPendingTransferExpired, ResolveAlreadyResolved, false},
		{"unmapped", tb.TransferExceedsCredits, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveOutcome(tc.in)
			if tc.err {
				if !errors.Is(err, ErrCreateTransfer) {
					t.Fatalf("resolveOutcome(%v) err = %v, want ErrCreateTransfer", tc.in, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("resolveOutcome(%v) = (%v, %v), want (%v, nil)", tc.in, got, err, tc.want)
			}
		})
	}
}
