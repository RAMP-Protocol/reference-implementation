package exchange_test

import (
	"errors"
	"testing"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

func TestKindConnectCodeMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind exchange.Kind
		code connect.Code
	}{
		{exchange.KindInvalidRequest, connect.CodeInvalidArgument},
		{exchange.KindNotFound, connect.CodeNotFound},
		{exchange.KindSignatureInvalid, connect.CodeUnauthenticated},
		{exchange.KindBillingDenied, connect.CodePermissionDenied},
		{exchange.KindIdempotent, connect.CodeAlreadyExists},
		{exchange.KindInternal, connect.CodeInternal},
		{exchange.KindUnspecified, connect.CodeUnknown},
	}
	for _, c := range cases {
		if got := c.kind.ConnectCode(); got != c.code {
			t.Errorf("%s -> %v, want %v", c.kind, got, c.code)
		}
	}
}

func TestToConnectWrapsDomainError(t *testing.T) {
	t.Parallel()
	err := exchange.Newf(exchange.KindBillingDenied, "insufficient balance")
	ce := exchange.ToConnect(err)
	if ce.Code() != connect.CodePermissionDenied {
		t.Fatalf("code = %v", ce.Code())
	}
}

func TestToConnectFallsBackToInternal(t *testing.T) {
	t.Parallel()
	ce := exchange.ToConnect(errors.New("boom"))
	if ce.Code() != connect.CodeInternal {
		t.Fatalf("code = %v", ce.Code())
	}
}

func TestToConnectNilInput(t *testing.T) {
	t.Parallel()
	if ce := exchange.ToConnect(nil); ce != nil {
		t.Fatalf("expected nil, got %v", ce)
	}
}

func TestWrapUnwrap(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("cause")
	err := exchange.Wrap(exchange.KindInternal, sentinel, "load tenant")
	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is should unwrap to cause")
	}
	if err.Error() == "" {
		t.Fatal("empty error string")
	}
}
