package transport

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// emptyRevocationDoc is the "nothing revoked" snapshot served when no revocation
// file is configured or present. Its as_of is the epoch so the consumer's
// monotonic guard never lets it override a real, later revocation; on a first
// fetch (no prior snapshot) it applies cleanly as an empty set.
const emptyRevocationDoc = `{"as_of":"1970-01-01T00:00:00Z"}`

// RevocationSource yields the Broker's validated KeyRevocationList document,
// caching the file bytes and re-reading only when the file's mtime changes. This
// mirrors the cache-and-serve shape of rampwellknown/server.Handler (an
// atomic-pointer snapshot serving lock-free), specialized for a file whose
// freshness is tracked by mtime rather than an explicit Rebuild: the steady-state
// hot path does a cheap os.Stat instead of a full os.ReadFile + schema
// validation per request, while an operator editing the file still takes effect
// without a restart (the admin plane was removed; an operator-owned re-read
// file is the provisioning surface).
//
// The operator owns as_of monotonicity (ADR-003 Consequences): each published
// snapshot MUST carry an as_of strictly newer than the last, or the consumer's
// rollback guard ignores it. A malformed file yields an error (caller → 500), so
// a typo cannot silently un-revoke a key by serving a fresh empty snapshot.
type RevocationSource struct {
	path  string
	cache atomic.Pointer[revocationSnapshot]
}

// revocationSnapshot is the cached (validated) document tagged with the source
// file's mtime; a request whose stat matches modTime serves doc without re-read.
type revocationSnapshot struct {
	modTime time.Time
	doc     []byte
}

// NewRevocationSource builds a source over the file at path. An empty path means
// "no operator revocation file": Document serves the epoch-dated empty snapshot.
// No I/O happens here — the first Document call primes the cache — so a malformed
// file surfaces as a request-time error, not a construction failure.
func NewRevocationSource(path string) *RevocationSource {
	return &RevocationSource{path: path}
}

// Document returns the bytes to serve: the validated file content (from cache
// when the file is unchanged since the last read), or the epoch-empty snapshot
// when no file is configured or the file is absent. A present-but-unreadable or
// schema-invalid file is an error.
func (s *RevocationSource) Document() ([]byte, error) {
	if s.path == "" {
		return []byte(emptyRevocationDoc), nil
	}
	info, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return []byte(emptyRevocationDoc), nil
	}
	if err != nil {
		return nil, fmt.Errorf("stat revocation file: %w", err)
	}
	if snap := s.cache.Load(); snap != nil && snap.modTime.Equal(info.ModTime()) {
		return snap.doc, nil
	}
	data, err := os.ReadFile(s.path) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("read revocation file: %w", err)
	}
	if err := rampwellknown.ValidateRevocation(data); err != nil {
		return nil, fmt.Errorf("revocation file invalid: %w", err)
	}
	s.cache.Store(&revocationSnapshot{modTime: info.ModTime(), doc: data})
	return data, nil
}
