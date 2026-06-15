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
