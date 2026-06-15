package rampwellknown

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// manifestStore is the shared host→manifest cache core used by both Cache and
// Loader: a single-flighted, RWMutex-guarded map of entries with per-entry
// expiry. Cache wraps it with a negative (404) map plus Cache-Control handling;
// Loader wraps it with a revocation snapshot plus a background poller. Keeping
// the expiry comparison, lock discipline, and singleflight double-check here
// avoids two near-identical copies drifting apart.
type manifestStore struct {
	clk     clock.Clock
	sf      singleflight.Group
	mu      sync.RWMutex
	entries map[string]storeEntry
}

type storeEntry struct {
	manifest  *Manifest
	expiresAt time.Time
}

func newManifestStore(clk clock.Clock) *manifestStore {
	return &manifestStore{clk: clk, entries: map[string]storeEntry{}}
}

// get returns host's manifest when present and strictly before its expiry.
func (s *manifestStore) get(host string) (*Manifest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[host]
	if !ok || !s.clk.Now().Before(e.expiresAt) {
		return nil, false
	}
	return e.manifest, true
}

// put stores host's manifest with a lifetime of ttl measured from now.
func (s *manifestStore) put(host string, m *Manifest, ttl time.Duration) {
	s.mu.Lock()
	s.entries[host] = storeEntry{manifest: m, expiresAt: s.clk.Now().Add(ttl)}
	s.mu.Unlock()
}

// drop removes host's entry, if any.
func (s *manifestStore) drop(host string) {
	s.mu.Lock()
	delete(s.entries, host)
	s.mu.Unlock()
}

// hosts returns the currently-stored hosts; used by the revocation poller to
// enumerate which manifests to refresh.
func (s *manifestStore) hosts() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.entries))
	for h := range s.entries {
		out = append(out, h)
	}
	return out
}

// single resolves host through the singleflight group, re-checking the cache
// inside the critical section (the double-check) before invoking load on a
// genuine miss so concurrent callers collapse onto one origin fetch.
func (s *manifestStore) single(host string, load func() (*Manifest, error)) (*Manifest, error) {
	v, err, _ := s.sf.Do(host, func() (any, error) {
		if m, ok := s.get(host); ok {
			return m, nil
		}
		return load()
	})
	if err != nil {
		return nil, err
	}
	return v.(*Manifest), nil
}
