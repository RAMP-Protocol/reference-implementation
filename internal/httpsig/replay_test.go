package httpsig

import (
	"context"
	"testing"
	"time"
)

func TestMemoryReplayStore_SeenOrAdd(t *testing.T) {
	clock := time.Unix(1700000000, 0)
	nowFn := func() time.Time { return clock }
	s := NewMemoryReplayStore(nowFn)

	seen, err := s.SeenOrAdd(context.Background(), "agent1", "sig-abc", 5*time.Minute)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if seen {
		t.Fatalf("first SeenOrAdd returned seen=true, want false")
	}

	seen, err = s.SeenOrAdd(context.Background(), "agent1", "sig-abc", 5*time.Minute)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !seen {
		t.Fatalf("second SeenOrAdd returned seen=false, want true")
	}
}

func TestMemoryReplayStore_DifferentKeyIDIndependent(t *testing.T) {
	s := NewMemoryReplayStore(func() time.Time { return time.Unix(1700000000, 0) })
	if seen, _ := s.SeenOrAdd(context.Background(), "a1", "sig", time.Minute); seen {
		t.Fatalf("agent a1 should be fresh")
	}
	if seen, _ := s.SeenOrAdd(context.Background(), "a2", "sig", time.Minute); seen {
		t.Fatalf("agent a2 should be fresh even with same sig bytes")
	}
}

func TestMemoryReplayStore_Seen(t *testing.T) {
	var now time.Time
	s := NewMemoryReplayStore(func() time.Time { return now })
	now = time.Unix(1700000000, 0)

	// Seen is read-only: it must NOT record the pair.
	if seen, _ := s.Seen(context.Background(), "a", "sig"); seen {
		t.Fatalf("Seen on a fresh pair returned true")
	}
	if seen, _ := s.SeenOrAdd(context.Background(), "a", "sig", time.Minute); seen {
		t.Fatalf("SeenOrAdd after Seen returned true — Seen must not have added the pair")
	}
	// Now it is recorded; Seen reports true without mutating expiry.
	if seen, _ := s.Seen(context.Background(), "a", "sig"); !seen {
		t.Fatalf("Seen on a recorded pair returned false")
	}
	// Expired entries read as fresh.
	now = now.Add(2 * time.Minute)
	if seen, _ := s.Seen(context.Background(), "a", "sig"); seen {
		t.Fatalf("Seen on an expired pair returned true")
	}
}

func TestMemoryReplayStore_ExpiredEntryIsFresh(t *testing.T) {
	var now time.Time
	s := NewMemoryReplayStore(func() time.Time { return now })
	now = time.Unix(1700000000, 0)
	if seen, _ := s.SeenOrAdd(context.Background(), "a", "sig", time.Minute); seen {
		t.Fatalf("unexpected seen=true on first add")
	}
	// Advance past the TTL. The second call must treat it as fresh.
	now = now.Add(2 * time.Minute)
	if seen, _ := s.SeenOrAdd(context.Background(), "a", "sig", time.Minute); seen {
		t.Fatalf("expected fresh after TTL expiry; got seen=true")
	}
}
