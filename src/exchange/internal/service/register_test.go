package service

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestNewExchangeService_BillingRefGenDefaultsToUUID(t *testing.T) {
	// A nil BillingRefGen must default to uuid.NewString: the generator is always
	// callable and yields distinct, parseable UUIDs.
	svc := NewExchangeService(ExchangeDeps{})
	if svc.billingRefGen == nil {
		t.Fatal("billingRefGen is nil after default")
	}
	first := svc.billingRefGen()
	second := svc.billingRefGen()
	if first == second {
		t.Fatalf("generator returned the same value twice: %q", first)
	}
	if _, err := uuid.Parse(first); err != nil {
		t.Fatalf("default generator did not produce a UUID: %q (%v)", first, err)
	}
}

func TestNewExchangeService_BillingRefGenInjectedIsUsed(t *testing.T) {
	// An injected generator is used verbatim, not overridden by the default.
	var n int
	svc := NewExchangeService(ExchangeDeps{
		BillingRefGen: func() string { n++; return fmt.Sprintf("ref-%d", n) },
	})
	if got := svc.billingRefGen(); got != "ref-1" {
		t.Fatalf("injected generator not used: got %q", got)
	}
}
