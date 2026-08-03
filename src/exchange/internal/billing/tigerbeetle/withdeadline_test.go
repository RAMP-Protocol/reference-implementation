package tigerbeetle

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestWithDeadline_ReturnsResult — a call that finishes before the deadline
// returns its value and nil error unchanged.
func TestWithDeadline_ReturnsResult(t *testing.T) {
	t.Parallel()
	v, err := withDeadline(context.Background(), time.Second, func() (int, error) {
		return 42, nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v != 42 {
		t.Errorf("v = %d, want 42", v)
	}
}

// TestWithDeadline_PropagatesError — a call that fails fast surfaces its own
// error, not ErrUnavailable (only a deadline yields ErrUnavailable).
func TestWithDeadline_PropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	_, err := withDeadline(context.Background(), time.Second, func() (int, error) {
		return 0, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Error("a fast failure must not be classified as ErrUnavailable")
	}
}

// TestWithDeadline_TimesOut — a call that blocks past the deadline returns
// ErrUnavailable, and the still-running goroutine sends into the size-1 buffer
// (no leak) once unblocked. Run under -race, a shared-state race would surface.
func TestWithDeadline_TimesOut(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	defer close(block) // unblocks the probe goroutine so it can send-and-exit
	_, err := withDeadline(context.Background(), 20*time.Millisecond, func() (int, error) {
		<-block
		return 1, nil
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}
