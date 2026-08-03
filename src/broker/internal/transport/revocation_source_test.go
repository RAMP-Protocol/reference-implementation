package transport_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// TestRevocationSource_CachesAndRefreshesOnMtime verifies the source serves a
// cached snapshot while the file is unchanged and re-reads only when the file's
// mtime advances — the caching behavior that keeps ReadFile + schema validation
// off the steady-state request path without losing restart-free operator edits.
func TestRevocationSource_CachesAndRefreshesOnMtime(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.json")
	first := []byte(`{"as_of":"2026-06-04T00:00:00Z","revoked":["k1"]}`)
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatalf("write first: %v", err)
	}
	base := time.Date(2026, 6, 4, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, base, base); err != nil {
		t.Fatalf("chtimes first: %v", err)
	}

	src := transport.NewRevocationSource(path)

	got, err := src.Document()
	if err != nil {
		t.Fatalf("first Document: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("first Document = %s, want %s", got, first)
	}

	// Overwrite the CONTENT but keep the SAME mtime: the source must still serve
	// the cached bytes (it keys freshness on mtime, not content).
	stale := []byte(`{"as_of":"2026-06-05T00:00:00Z","revoked":["k2"]}`)
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatalf("rewrite same mtime: %v", err)
	}
	if err := os.Chtimes(path, base, base); err != nil {
		t.Fatalf("chtimes same: %v", err)
	}
	got, err = src.Document()
	if err != nil {
		t.Fatalf("cached Document: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Errorf("cached Document = %s, want cached %s (same mtime must not refresh)", got, first)
	}

	// Advance the mtime: now the source must re-read and serve the new content.
	newer := base.Add(time.Hour)
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatalf("chtimes newer: %v", err)
	}
	got, err = src.Document()
	if err != nil {
		t.Fatalf("refreshed Document: %v", err)
	}
	if !bytes.Equal(got, stale) {
		t.Errorf("refreshed Document = %s, want %s (advanced mtime must refresh)", got, stale)
	}
}

// TestRevocationSource_AbsentAndUnconfigured verifies both the empty-path and
// missing-file cases serve the epoch-dated empty snapshot rather than erroring.
func TestRevocationSource_AbsentAndUnconfigured(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing.json")} {
		src := transport.NewRevocationSource(path)
		got, err := src.Document()
		if err != nil {
			t.Fatalf("Document(%q): %v", path, err)
		}
		if !bytes.Contains(got, []byte("1970-01-01T00:00:00Z")) {
			t.Errorf("Document(%q) = %s, want epoch-empty snapshot", path, got)
		}
	}
}
