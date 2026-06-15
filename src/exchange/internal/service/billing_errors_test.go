package service

import (
	"errors"
	"fmt"
	"testing"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// TestBillingErrorKind pins the adapter-sentinel → domain-Kind → connect.Code
// contract. Every sentinel must map to a stable code, wrapped sentinels must
// still match (errors.Is traversal), and a non-sentinel falls through to
// Internal.
func TestBillingErrorKind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		kind exchange.Kind
		code connect.Code
	}{
		{"unsupported", billing.ErrRefundUnsupported, exchange.KindUnimplemented, connect.CodeUnimplemented},
		{"unknown_id", billing.ErrUnknownBillingID, exchange.KindNotFound, connect.CodeNotFound},
		{"before_record", billing.ErrRefundBeforeRecord, exchange.KindFailedPrecondition, connect.CodeFailedPrecondition},
		{"exceeds_record", billing.ErrRefundExceedsRecord, exchange.KindFailedPrecondition, connect.CodeFailedPrecondition},
		{"invalid_amount", billing.ErrInvalidAmount, exchange.KindInvalidRequest, connect.CodeInvalidArgument},
		{"insufficient", billing.ErrInsufficientBalance, exchange.KindBillingDenied, connect.CodePermissionDenied},
		{"wrapped_sentinel", fmt.Errorf("refund: %w", billing.ErrRefundUnsupported), exchange.KindUnimplemented, connect.CodeUnimplemented},
		{"non_sentinel", errors.New("boom"), exchange.KindInternal, connect.CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := billingErrorKind(tc.err)
			if got != tc.kind {
				t.Fatalf("kind = %v, want %v", got, tc.kind)
			}
			if got.ConnectCode() != tc.code {
				t.Errorf("code = %v, want %v", got.ConnectCode(), tc.code)
			}
		})
	}
}
