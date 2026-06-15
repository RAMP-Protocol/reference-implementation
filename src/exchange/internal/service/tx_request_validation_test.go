package service

import (
	"errors"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// TestValidateTxRequest_RejectsOverLongID pins the tx_request_id length cap: the
// id becomes the billing idempotency key, so an unbounded id must be rejected at
// ingress with InvalidArgument before it reaches the adapter dedup maps.
func TestValidateTxRequest_RejectsOverLongID(t *testing.T) {
	t.Parallel()
	s := &ExchangeService{}
	req := &rampv1.TransactionRequest{Id: strings.Repeat("x", maxTxRequestIDLen+1)}

	err := s.validateTxRequest(req)

	var de *exchange.Error
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *exchange.Error", err)
	}
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
	if !strings.Contains(de.Message, "exceeds") {
		t.Errorf("message = %q, want it to mention the limit", de.Message)
	}
}

// TestValidateTxRequest_AcceptsBoundaryID confirms an id exactly at the cap is
// accepted (the check is strictly greater-than).
func TestValidateTxRequest_AcceptsBoundaryID(t *testing.T) {
	t.Parallel()
	s := &ExchangeService{}
	req := &rampv1.TransactionRequest{
		Id:             strings.Repeat("x", maxTxRequestIDLen),
		OfferId:        strPtr("offer-1"),
		OfferSignature: strPtr("sig-1"),
		Requester:      &rampv1.Requester{Id: "agent-1"},
	}

	if err := s.validateTxRequest(req); err != nil {
		t.Fatalf("boundary-length id rejected: %v", err)
	}
}
