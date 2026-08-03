package service

import (
	"fmt"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

func TestSorErrorKind(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want exchange.Kind
	}{
		{"account not found is NotFound", sor.ErrAccountNotFound, exchange.KindNotFound},
		{"empty subdomain is an Exchange bug, Internal", sor.ErrSubdomainRequired, exchange.KindInternal},
		{"empty billing_ref is an Exchange bug, Internal", sor.ErrBillingRefRequired, exchange.KindInternal},
		{"wrapped sentinel is still classified", fmt.Errorf("sor call: %w", sor.ErrAccountNotFound), exchange.KindNotFound},
		{"unknown error falls through to Internal", fmt.Errorf("boom"), exchange.KindInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sorErrorKind(tc.err); got != tc.want {
				t.Fatalf("sorErrorKind(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
