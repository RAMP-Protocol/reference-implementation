package service

import (
	"testing"
)

func TestLRURing_Push_BelowCapacity(t *testing.T) {
	r := newLRURing(3)
	for i, key := range []string{"a", "b", "c"} {
		evicted, ok := r.push(key)
		if ok {
			t.Fatalf("step %d: unexpected eviction %q", i, evicted)
		}
	}
	if r.n != 3 {
		t.Fatalf("n = %d, want 3", r.n)
	}
}

func TestLRURing_Push_Eviction(t *testing.T) {
	r := newLRURing(3)
	r.push("a")
	r.push("b")
	r.push("c")

	evicted, ok := r.push("d")
	if !ok {
		t.Fatal("expected eviction on full ring")
	}
	if evicted != "a" {
		t.Fatalf("evicted = %q, want %q", evicted, "a")
	}

	evicted, ok = r.push("e")
	if !ok || evicted != "b" {
		t.Fatalf("evicted = %q ok = %v, want b true", evicted, ok)
	}
}

func TestLRURing_ZeroCapacity(t *testing.T) {
	r := newLRURing(0)
	evicted, ok := r.push("x")
	if ok || evicted != "" {
		t.Fatal("zero-cap ring should never report eviction")
	}
}

func TestIdempotencyLRU_Eviction(t *testing.T) {
	t.Parallel()
	const cap = 4
	svc := &MarketplaceService{
		idemHit:  map[string]string{},
		idemRing: newLRURing(cap),
	}

	for i := range cap {
		key := string(rune('A' + i))
		svc.idempotencyRecord(key, "tx-"+key)
	}

	if _, ok := svc.idempotencyHit("A"); !ok {
		t.Fatal("A should still be in cache")
	}

	// Push one more to evict "A" (oldest).
	svc.idempotencyRecord("E", "tx-E")
	if _, ok := svc.idempotencyHit("A"); ok {
		t.Fatal("A should have been evicted")
	}
	if _, ok := svc.idempotencyHit("E"); !ok {
		t.Fatal("E should be in cache")
	}
}

func TestIdempotencyRecord_Duplicate(t *testing.T) {
	t.Parallel()
	svc := &MarketplaceService{
		idemHit:  map[string]string{},
		idemRing: newLRURing(4),
	}
	svc.idempotencyRecord("req-1", "tx-first")
	svc.idempotencyRecord("req-1", "tx-second") // duplicate, must not overwrite
	got, ok := svc.idempotencyHit("req-1")
	if !ok {
		t.Fatal("key should be present")
	}
	if got != "tx-first" {
		t.Fatalf("got %q, want tx-first", got)
	}
}
