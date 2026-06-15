package reqctx_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

func TestFromContext_ReturnsAttachedLogger(t *testing.T) {
	t.Parallel()
	want := slog.New(slog.NewTextHandler(io.Discard, nil)).With("request_id", "req-123")
	ctx := reqctx.IntoContext(context.Background(), want)
	if got := reqctx.FromContext(ctx); got != want {
		t.Fatalf("FromContext returned a different logger than was attached")
	}
}

func TestFromContext_DefaultsWhenAbsent(t *testing.T) {
	t.Parallel()
	if got := reqctx.FromContext(context.Background()); got != slog.Default() {
		t.Fatalf("FromContext should return slog.Default() when no logger attached")
	}
}

func TestFromContext_DefaultsOnNilLogger(t *testing.T) {
	t.Parallel()
	ctx := reqctx.IntoContext(context.Background(), nil)
	if got := reqctx.FromContext(ctx); got != slog.Default() {
		t.Fatalf("FromContext should fall back to slog.Default() when a nil logger was attached")
	}
}

// reqIDKey is a local context key the test's withID setter uses, so the test can
// assert the middleware stored the id under the caller-supplied key.
type reqIDKey struct{}

// TestRequestIDMiddleware pins the shared body both services delegate to: it
// mints an id when absent, echoes a caller-supplied id, threads it through the
// caller's withID setter, and attaches a request_id-scoped logger retrievable
// via FromContext.
func TestRequestIDMiddleware(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	withID := func(ctx context.Context, id string) context.Context {
		return context.WithValue(ctx, reqIDKey{}, id)
	}
	var stored string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		stored, _ = r.Context().Value(reqIDKey{}).(string)
		reqctx.FromContext(r.Context()).InfoContext(r.Context(), "handled")
	})
	h := reqctx.RequestIDMiddleware(logger, withID, next)

	// Absent inbound id → minted, echoed on the response, stored via withID, and
	// stamped into the scoped logger's output.
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", http.NoBody)
	h.ServeHTTP(rec, req)
	minted := rec.Header().Get("X-Request-ID")
	if minted == "" {
		t.Fatal("expected a minted X-Request-ID on the response")
	}
	if stored != minted {
		t.Fatalf("withID stored %q, response carried %q", stored, minted)
	}
	if want := `"request_id":"` + minted + `"`; !strings.Contains(buf.String(), want) {
		t.Fatalf("scoped logger did not stamp %s; log=%s", want, buf.String())
	}

	// Inbound id present → echoed verbatim, not re-minted.
	buf.Reset()
	rec = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", http.NoBody)
	req.Header.Set("X-Request-ID", "corr-xyz")
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("X-Request-ID"); got != "corr-xyz" {
		t.Fatalf("X-Request-ID = %q, want corr-xyz (echoed)", got)
	}
	if stored != "corr-xyz" {
		t.Fatalf("withID stored %q, want corr-xyz", stored)
	}
}
