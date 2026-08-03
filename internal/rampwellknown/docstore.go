package rampwellknown

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// docStore is the shared host→document cache core used by both Cache and
// Loader: a single-flighted, RWMutex-guarded map of entries with per-entry
// expiry. Cache instantiates it with *Manifest (the commercial overlay) and
// wraps it with a negative (404) map plus Cache-Control handling; Loader
// instantiates it with *WBAFile (the WBA directory) and wraps it with a
// revocation snapshot plus a background poller. Keeping the expiry comparison,
// lock discipline, and singleflight double-check here avoids two near-identical
// copies drifting apart.
type docStore[T any] struct {
	clk     clock.Clock
	sf      singleflight.Group
	mu      sync.RWMutex
	entries map[string]docEntry[T]
}

type docEntry[T any] struct {
	doc       T
	expiresAt time.Time
}

func newDocStore[T any](clk clock.Clock) *docStore[T] {
	return &docStore[T]{clk: clk, entries: map[string]docEntry[T]{}}
}

// get returns host's document when present and strictly before its expiry.
func (s *docStore[T]) get(host string) (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[host]
	if !ok || !s.clk.Now().Before(e.expiresAt) {
		var zero T
		return zero, false
	}
	return e.doc, true
}

// put stores host's document with a lifetime of ttl measured from now.
func (s *docStore[T]) put(host string, doc T, ttl time.Duration) {
	s.mu.Lock()
	s.entries[host] = docEntry[T]{doc: doc, expiresAt: s.clk.Now().Add(ttl)}
	s.mu.Unlock()
}

// drop removes host's entry, if any.
func (s *docStore[T]) drop(host string) {
	s.mu.Lock()
	delete(s.entries, host)
	s.mu.Unlock()
}

// single resolves host through the singleflight group, re-checking the cache
// inside the critical section (the double-check) before invoking load on a
// genuine miss so concurrent callers collapse onto one origin fetch.
func (s *docStore[T]) single(host string, load func() (T, error)) (T, error) {
	v, err, _ := s.sf.Do(host, func() (any, error) {
		if doc, ok := s.get(host); ok {
			return doc, nil
		}
		return load()
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return v.(T), nil
}
