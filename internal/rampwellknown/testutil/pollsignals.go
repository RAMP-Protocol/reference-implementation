package testutil

import (
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// PollSignals bridges the rampwellknown loader's OnPollArmed / OnPollCycle
// determinism seams to a deterministic-clock test, letting it cross exactly one
// revocation-poll boundary without sleeping or a wall-clock deadline. Wire Armed
// and Cycled into LoaderOptions (or agentkeys.Config), publish the state the next
// poll must observe, then call CrossOne.
//
// The channels are buffered (cap 1) and the hooks send non-blocking, so the
// poller goroutine never blocks inside a hook even when the test is between
// waits — the poller stays free to observe ctx cancellation and exit cleanly.
type PollSignals struct {
	armedCh  chan struct{}
	cycledCh chan struct{}
}

// NewPollSignals returns a ready PollSignals.
func NewPollSignals() *PollSignals {
	return &PollSignals{
		armedCh:  make(chan struct{}, 1),
		cycledCh: make(chan struct{}, 1),
	}
}

// Armed is the OnPollArmed hook: a non-blocking signal that the poller has
// registered its next tick timer and is about to block on it.
func (p *PollSignals) Armed() { nonBlockingSend(p.armedCh) }

// Cycled is the OnPollCycle hook: a non-blocking signal that one refresh cycle
// completed.
func (p *PollSignals) Cycled() { nonBlockingSend(p.cycledCh) }

// CrossOne deterministically advances the poller across one tick: it waits for
// the tick timer to be armed, advances clk by adv to fire it, then waits for the
// resulting refresh to complete. adv MUST exceed the jittered poll interval so
// the advance fires the armed timer.
func (p *PollSignals) CrossOne(t *testing.T, clk *clock.DeterministicClock, adv time.Duration) {
	t.Helper()
	<-p.armedCh
	clk.Advance(adv)
	<-p.cycledCh
}

func nonBlockingSend(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
