package rampcanonical_test

import (
	"bytes"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampcanonical"
)

func TestCanonicalHash_BodyChangeDetected(t *testing.T) {
	offerA := "offer-a"
	offerB := "offer-b"
	a := &rampv1.TransactionRequest{OfferId: &offerA}
	b := &rampv1.TransactionRequest{OfferId: &offerB}
	ha, err := rampcanonical.CanonicalHash(a)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	hb, err := rampcanonical.CanonicalHash(b)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if bytes.Equal(ha, hb) {
		t.Errorf("distinct bodies produced identical hash: %x", ha)
	}
}

func TestCanonicalHash_NilRejected(t *testing.T) {
	_, err := rampcanonical.CanonicalHash(nil)
	if err == nil {
		t.Fatal("expected error for nil message")
	}
}

func TestCanonicalHash_Deterministic(t *testing.T) {
	offerID := "stable"
	msg := &rampv1.TransactionRequest{OfferId: &offerID}
	h1, err := rampcanonical.CanonicalHash(msg)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	h2, err := rampcanonical.CanonicalHash(msg)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !bytes.Equal(h1, h2) {
		t.Errorf("non-deterministic hashes: %x vs %x", h1, h2)
	}
}
