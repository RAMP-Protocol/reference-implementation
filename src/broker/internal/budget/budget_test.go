package budget_test

import (
	"context"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
)

func TestMemoryService_CheckThenRecord(t *testing.T) {
	s := budget.NewMemory(nil)
	ctx := context.Background()

	dec, err := s.Check(ctx, "lic-1", 1000)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !dec.Allowed {
		t.Fatal("expected allowed with 0 consumed")
	}
	if dec.Remaining != 1000 {
		t.Errorf("remaining = %d", dec.Remaining)
	}

	if err := s.Record(ctx, "lic-1", 600); err != nil {
		t.Fatalf("Record: %v", err)
	}
	dec, err = s.Check(ctx, "lic-1", 1000)
	if err != nil {
		t.Fatalf("Check 2: %v", err)
	}
	if !dec.Allowed || dec.Remaining != 400 {
		t.Errorf("got %+v", dec)
	}
}

func TestMemoryService_Exhaustion(t *testing.T) {
	s := budget.NewMemory(nil)
	ctx := context.Background()
	if err := s.Record(ctx, "lic-2", 1200); err != nil {
		t.Fatalf("Record: %v", err)
	}
	dec, err := s.Check(ctx, "lic-2", 1000)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if dec.Allowed {
		t.Fatal("expected disallowed after over-spend")
	}
	if dec.Remaining >= 0 {
		t.Errorf("remaining = %d, want negative", dec.Remaining)
	}
}

func TestSelect_NilClientPicksMemory(t *testing.T) {
	got := budget.Select(nil, 0, nil)
	if _, ok := got.(*budget.MemoryService); !ok {
		t.Fatalf("expected MemoryService, got %T", got)
	}
}
