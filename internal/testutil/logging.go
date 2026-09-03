// Package testutil hosts cross-cutting test helpers shared by services and
// internal packages. Helpers here MUST NOT import service-side code; they are
// consumed by both Exchange- and Broker-side test trees, so the dependency
// must flow inward only.
package testutil

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// DiscardLogger returns a *slog.Logger that drops every record — the standard
// quiet logger for tests that need a non-nil logger but no output. Replaces the
// `slog.New(slog.NewTextHandler(io.Discard, nil))` literal previously copy-pasted
// across the broker test tree (testing doctrine §7: shared fixtures, not
// copy-paste).
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// LogCapture is a logger whose records a test can read back, for the case where
// what a service RECORDS is the property under test rather than a side effect of
// it.
//
// That case is real and not rare: a service that answers a caller one thing and
// records another has made a deliberate split, and only reading both halves
// shows the split held. A test that reads only the answer proves half of it.
//
// The buffer is guarded because the services under test log from whatever
// goroutine served the request, and the reader is the test's own.
type LogCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// NewLogCapture returns a capture and the logger that writes into it. JSON,
// because a test asserting on a specific attribute should look for the key
// rather than for a substring of a formatted line.
func NewLogCapture() (*LogCapture, *slog.Logger) {
	c := &LogCapture{}
	return c, slog.New(slog.NewJSONHandler(c, nil))
}

// Write makes the capture the handler's destination. It is not called by tests.
func (c *LogCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// Lines returns the records written so far, one JSON object per entry.
func (c *LogCapture) Lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Split(strings.TrimSuffix(c.buf.String(), "\n"), "\n")
}

// Find returns the captured records whose msg is exactly event. A test asserting
// on one log line says which line it means, rather than searching the whole
// stream for a substring that some other record might also carry.
func (c *LogCapture) Find(event string) []string {
	var out []string
	for _, line := range c.Lines() {
		if strings.Contains(line, `"msg":"`+event+`"`) {
			out = append(out, line)
		}
	}
	return out
}
