package ramphttpsig

import (
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// TestMonotonicWindow_StrictlyIncreasingExpires verifies that a burst of calls
// landing in the same wall-clock second yields strictly increasing expires
// cutoffs — the replay-store dodge that keeps identical back-to-back relay
// signatures unique. created tracks now() and is not required to increase.
func TestMonotonicWindow_StrictlyIncreasingExpires(t *testing.T) {
	clk := clock.NewDeterministic(time.Unix(1_700_000_000, 0))
	ttl := 30 * time.Second
	w := MonotonicWindow(clk, ttl)

	var prevExpires int64
	for i := range 5 {
		created, expires := w()
		if created != 1_700_000_000 {
			t.Errorf("call %d: created = %d, want frozen now", i, created)
		}
		if i > 0 && expires <= prevExpires {
			t.Errorf("call %d: expires %d not strictly greater than prev %d", i, expires, prevExpires)
		}
		prevExpires = expires
	}

	// The first cutoff sits at now+ttl; four further same-second calls each add 1s.
	if want := int64(1_700_000_000) + int64(ttl.Seconds()) + 4; prevExpires != want {
		t.Errorf("final expires = %d, want %d", prevExpires, want)
	}
}

// TestMonotonicWindow_TracksClockAdvance verifies that once wall-clock time
// moves past the accumulated floor, expires follows now+ttl again rather than
// staying pinned to the incremented burst value.
func TestMonotonicWindow_TracksClockAdvance(t *testing.T) {
	clk := clock.NewDeterministic(time.Unix(1_700_000_000, 0))
	ttl := 30 * time.Second
	w := MonotonicWindow(clk, ttl)

	_, first := w()
	clk.Advance(10 * time.Second)
	_, second := w()

	if want := int64(1_700_000_000) + 10 + int64(ttl.Seconds()); second != want {
		t.Errorf("after advance, expires = %d, want %d (now+ttl)", second, want)
	}
	if second <= first {
		t.Errorf("expires did not increase after clock advance: first %d, second %d", first, second)
	}
}

// TestMonotonicWindow_DriftIsCapped is the regression guard for an unbounded
// ratchet. The +1s bump compounds under sustained load: without a ceiling, a
// burst above one request per second pushes the cutoff permanently ahead of the
// clock, and a signature's real lifetime stops being ttl and becomes a function
// of the request rate. The replay store only remembers a signature for
// ReplayTTL, so past that window a captured request becomes replayable again.
//
// A whole minute of same-second calls at 30s ttl would drift the cutoff to
// now+3600 unbounded; capped, it stops at now+2*ttl.
func TestMonotonicWindow_DriftIsCapped(t *testing.T) {
	now := int64(1_700_000_000)
	clk := clock.NewDeterministic(time.Unix(now, 0))
	ttl := 30 * time.Second
	w := MonotonicWindow(clk, ttl)

	ceiling := now + 2*int64(ttl.Seconds())
	var expires int64
	for range 3600 {
		_, expires = w()
		if expires > ceiling {
			t.Fatalf("expires %d exceeded the ceiling %d (drift is unbounded)", expires, ceiling)
		}
	}
	if expires != ceiling {
		t.Errorf("after saturation expires = %d, want the ceiling %d", expires, ceiling)
	}

	// The cap must not freeze the window: once the clock moves past it, the
	// cutoff tracks the clock again rather than staying pinned.
	clk.Advance(10 * time.Minute)
	if _, moved := w(); moved <= ceiling {
		t.Errorf("after the clock advanced, expires = %d, want it past the old ceiling %d", moved, ceiling)
	}
}
