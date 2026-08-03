package keypolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub
}

// TestTimedStaticResolver_ValidityWindow pins that a key carrying a half-open
// [notBefore, notAfter) window is enforced on Resolve: inside the window it
// resolves; outside it yields resolvers.ErrKeyExpired — an AUTHORITATIVE negative
// (NOT ErrUnknownKey), so a CompositeResolver halts rather than falling through
// to a later, more permissive source. This is the static-bootstrap
// gate the SDK's helpers.StaticKeyResolver (Put only) does not provide.
func TestTimedStaticResolver_ValidityWindow(t *testing.T) {
	pub := mustKey(t)
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	clk := clock.NewDeterministic(base)
	r := NewTimedStaticResolver(clk)
	r.PutTimed("windowed", pub, base.Add(-time.Hour), base.Add(time.Hour))
	r.Put("unbounded", pub)

	// Inside the window and the unbounded key both resolve.
	if _, err := r.Resolve(context.Background(), "windowed"); err != nil {
		t.Fatalf("within window: unexpected err %v", err)
	}
	if _, err := r.Resolve(context.Background(), "unbounded"); err != nil {
		t.Fatalf("unbounded: unexpected err %v", err)
	}

	// Past not_after → ErrKeyExpired, specifically NOT ErrUnknownKey.
	clk.SetNow(base.Add(2 * time.Hour))
	_, err := r.Resolve(context.Background(), "windowed")
	if !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("lapsed key: want ErrKeyExpired, got %v", err)
	}
	if errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatal("lapsed key must NOT be ErrUnknownKey (composite must not fall through)")
	}
	if _, err := r.Resolve(context.Background(), "unbounded"); err != nil {
		t.Fatalf("unbounded after clock advance: unexpected err %v", err)
	}

	// Before not_before → ErrKeyExpired too (not-yet-valid).
	clk.SetNow(base.Add(-2 * time.Hour))
	if _, err := r.Resolve(context.Background(), "windowed"); !errors.Is(err, resolvers.ErrKeyExpired) {
		t.Fatalf("not-yet-valid key: want ErrKeyExpired, got %v", err)
	}
}

// TestTimedStaticResolver_UnknownKey pins that an absent keyid yields
// ErrUnknownKey (the composite falls through to the next delegate).
func TestTimedStaticResolver_UnknownKey(t *testing.T) {
	r := NewTimedStaticResolver(clock.System{})
	if _, err := r.Resolve(context.Background(), "absent"); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("absent key: want ErrUnknownKey, got %v", err)
	}
}

// TestParseWindow pins fail-closed window parsing: empty bounds are unbounded
// (zero time, ok); a present-but-unparseable bound reports ok=false so the
// loader skips the malformed entry rather than treating a typo as unbounded
// (which would make an out-of-window key silently always-valid).
func TestParseWindow(t *testing.T) {
	if nb, na, ok := ParseWindow("", ""); !ok || !nb.IsZero() || !na.IsZero() {
		t.Fatalf("empty window: want zero,zero,true; got %v,%v,%v", nb, na, ok)
	}
	if _, _, ok := ParseWindow("2020-01-01T00:00:00Z", "2020-06-01T00:00:00Z"); !ok {
		t.Fatal("valid RFC 3339 window: want ok=true")
	}
	if _, _, ok := ParseWindow("not-a-time", ""); ok {
		t.Fatal("unparseable not_before: want ok=false (fail-closed)")
	}
	if _, _, ok := ParseWindow("", "also-bad"); ok {
		t.Fatal("unparseable not_after: want ok=false (fail-closed)")
	}
}
