package clock_test

import (
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

func TestSystemNowIsUTC(t *testing.T) {
	t.Parallel()
	got := clock.System{}.Now()
	if got.Location() != time.UTC {
		t.Fatalf("System.Now() location = %v, want UTC", got.Location())
	}
}

func TestDeterministicAdvanceMovesNow(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewDeterministic(start)
	if !c.Now().Equal(start) {
		t.Fatalf("Now() before advance = %v, want %v", c.Now(), start)
	}
	c.Advance(15 * time.Minute)
	want := start.Add(15 * time.Minute)
	if !c.Now().Equal(want) {
		t.Fatalf("Now() after advance = %v, want %v", c.Now(), want)
	}
}

func TestDeterministicSetNowPins(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewDeterministic(start)
	target := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	c.SetNow(target)
	if !c.Now().Equal(target) {
		t.Fatalf("Now() after SetNow = %v, want %v", c.Now(), target)
	}
}

func TestDeterministicNegativeAdvanceClampedToZero(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewDeterministic(start)
	c.Advance(-time.Hour)
	if !c.Now().Equal(start) {
		t.Fatalf("Now() after negative advance = %v, want %v (clamp to 0)", c.Now(), start)
	}
}

func TestDeterministicAfterFiresOnAdvance(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c := clock.NewDeterministic(start)
	ch := c.After(5 * time.Minute)
	select {
	case <-ch:
		t.Fatal("After channel fired before advance")
	default:
	}
	c.Advance(5 * time.Minute)
	select {
	case got := <-ch:
		want := start.Add(5 * time.Minute)
		if !got.Equal(want) {
			t.Fatalf("After fired with %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("After channel did not fire after advance")
	}
}

func TestDeterministicAfterZeroDurationFiresImmediately(t *testing.T) {
	t.Parallel()
	c := clock.NewDeterministic(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	select {
	case <-c.After(0):
	default:
		t.Fatal("After(0) did not fire immediately")
	}
}
