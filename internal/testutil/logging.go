// Package testutil hosts cross-cutting test helpers shared by services and
// internal packages. Helpers here MUST NOT import service-side code; they are
// consumed by both Exchange- and Broker-side test trees, so the dependency
// must flow inward only.
package testutil

import (
	"io"
	"log/slog"
)

// DiscardLogger returns a *slog.Logger that drops every record — the standard
// quiet logger for tests that need a non-nil logger but no output. Replaces the
// `slog.New(slog.NewTextHandler(io.Discard, nil))` literal previously copy-pasted
// across the broker test tree (testing doctrine §7: shared fixtures, not
// copy-paste).
func DiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
