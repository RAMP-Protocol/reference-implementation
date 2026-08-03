package service

import (
	"errors"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// validBatchItem is the minimal item that clears validateBatchRequest's per-item
// presence checks (offer signature + agent_acceptance signature), so the
// envelope-level cases can isolate the field under test.
func validBatchItem() *rampv1.TransactionItem {
	return &rampv1.TransactionItem{
		Offer:           &rampv1.Offer{OfferId: "offer-1", Signature: "sig-1"},
		AgentAcceptance: &rampv1.AgentAcceptance{Signature: "acc-sig"},
	}
}

// TestValidateBatchRequest_RejectsOverLongID pins the idempotency_key length
// cap: the key becomes the billing idempotency key, so an unbounded value must
// be rejected at ingress with InvalidArgument before it reaches the adapter
// dedup maps. validateBatchRequest is the sole envelope validator after the C4
// items-only collapse. The reject also carries the offending field name as
// structured metadata (ADR-019 WithField), naming the WIRE field idempotency_key.
func TestValidateBatchRequest_RejectsOverLongID(t *testing.T) {
	t.Parallel()
	s := &ExchangeService{}
	req := &rampv1.TransactionRequest{
		IdempotencyKey: strings.Repeat("x", maxIdempotencyKeyLen+1),
		Requester:      &rampv1.Requester{Id: "agent-1"},
		Items:          []*rampv1.TransactionItem{validBatchItem()},
	}

	err := s.validateBatchRequest(req)

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
	if strings.Contains(de.Message, "tx_request_id") {
		t.Errorf("message = %q leaks the stale internal name tx_request_id", de.Message)
	}
	if de.Metadata["field"] != "idempotency_key" {
		t.Errorf("metadata[field] = %q, want idempotency_key (ADR-019 WithField)", de.Metadata["field"])
	}
}

// TestValidateBatchRequest_AcceptsBoundaryID confirms an id exactly at the cap
// is accepted (the check is strictly greater-than).
func TestValidateBatchRequest_AcceptsBoundaryID(t *testing.T) {
	t.Parallel()
	s := &ExchangeService{}
	req := &rampv1.TransactionRequest{
		IdempotencyKey: strings.Repeat("x", maxIdempotencyKeyLen),
		Requester:      &rampv1.Requester{Id: "agent-1"},
		Items:          []*rampv1.TransactionItem{validBatchItem()},
	}

	if err := s.validateBatchRequest(req); err != nil {
		t.Fatalf("boundary-length id rejected: %v", err)
	}
}

// TestValidateBatchRequest_RejectsOverLongRequesterDomain pins the
// requester.domain length cap. The domain is an AgentAcceptancePayload input, so
// it lands verbatim in an append-once evidence row that has no removal path, and
// nothing upstream bounds it: the proto validates only requester.type, and the
// acceptance signature is no mitigation because the agent signs the requester it
// chose, with its own key. The reject carries the offending field name as
// structured metadata (ADR-019 WithField), naming the WIRE field requester.domain.
//
// Both shapes are driven because the cap is counted in BYTES. A multi-byte domain
// well inside any character bound can still exceed the octet bound, and that is
// the case a character-counting implementation would wave through — at either
// this layer or the column's CHECK, which mirrors it.
func TestValidateBatchRequest_RejectsOverLongRequesterDomain(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		domain string
	}{
		{"one byte over the cap", strings.Repeat("d", maxRequesterDomainLen+1)},
		// 200 two-byte characters: 200 characters, 400 bytes.
		{"multi-byte, under the character bound but over the byte bound", strings.Repeat("é", 200)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &ExchangeService{}
			req := &rampv1.TransactionRequest{
				IdempotencyKey: "tx-domain",
				Requester:      &rampv1.Requester{Id: "agent-1", Domain: tc.domain},
				Items:          []*rampv1.TransactionItem{validBatchItem()},
			}

			err := s.validateBatchRequest(req)

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
			if de.Metadata["field"] != "requester.domain" {
				t.Errorf("metadata[field] = %q, want requester.domain (ADR-019 WithField)", de.Metadata["field"])
			}
		})
	}
}

// TestValidateBatchRequest_AcceptsBoundaryRequesterDomain confirms a domain
// exactly at the cap is accepted (the check is strictly greater-than). The
// fixture is ASCII, so its character count and byte count coincide at the bound.
func TestValidateBatchRequest_AcceptsBoundaryRequesterDomain(t *testing.T) {
	t.Parallel()
	s := &ExchangeService{}
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "tx-domain-boundary",
		Requester: &rampv1.Requester{
			Id:     "agent-1",
			Domain: strings.Repeat("d", maxRequesterDomainLen),
		},
		Items: []*rampv1.TransactionItem{validBatchItem()},
	}

	if err := s.validateBatchRequest(req); err != nil {
		t.Fatalf("boundary-length domain rejected: %v", err)
	}
}

// TestValidateBatchRequest_RejectsEmptyItems pins the empty-items envelope guard
// A body carrying no items is malformed, not an empty-but-valid batch, and
// must be rejected with InvalidArgument rather than returning an empty response.
func TestValidateBatchRequest_RejectsEmptyItems(t *testing.T) {
	t.Parallel()
	s := &ExchangeService{}
	req := &rampv1.TransactionRequest{
		IdempotencyKey: "tx-empty",
		Requester:      &rampv1.Requester{Id: "agent-1"},
		Items:          nil,
	}

	err := s.validateBatchRequest(req)

	var de *exchange.Error
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *exchange.Error", err)
	}
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
	if !strings.Contains(de.Message, "at least one item") {
		t.Errorf("message = %q, want it to mention the missing items", de.Message)
	}
}
