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
		t.Fatalf("FromContext should fall back to slog.Default() when a nil logger attached")
	}
}

// middlewareRun is everything one request through RequestIDMiddleware produced:
// the id echoed on the response, the id and provenance readable from the context,
// and the scoped logger's output.
type middlewareRun struct {
	responseID string
	ctxID      string
	minted     bool
	mintedOK   bool
	logOutput  string
}

// assertCorrelation asserts the facts that must agree on every request: the id
// echoed to the caller is the id downstream layers read, and the provenance
// recorded beside it says how that id came to be.
//
// They are asserted together because each is worthless alone. An id nobody
// downstream can read correlates nothing; an id whose provenance went unrecorded
// cannot be told from one an attacker chose, since a minted UUID lies entirely
// inside the charset a caller-supplied id must satisfy.
func assertCorrelation(t *testing.T, got middlewareRun, wantMinted bool) {
	t.Helper()
	if got.responseID == "" {
		t.Fatal("no X-Request-ID on the response")
	}
	if got.ctxID != got.responseID {
		t.Errorf("reqctx.RequestID = %q, response carried %q", got.ctxID, got.responseID)
	}
	if !got.mintedOK || got.minted != wantMinted {
		t.Errorf("provenance = (minted=%v, ok=%v), want (%v, true)", got.minted, got.mintedOK, wantMinted)
	}
}

// runMiddleware drives one request carrying inbound as X-Request-ID (or no header
// at all when inbound is absent) and reports everything the middleware produced.
func runMiddleware(t *testing.T, inbound *string) middlewareRun {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	var out middlewareRun
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		out.ctxID = reqctx.RequestID(r.Context())
		out.minted, out.mintedOK = reqctx.RequestIDMinted(r.Context())
		reqctx.FromContext(r.Context()).InfoContext(r.Context(), "handled")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", http.NoBody)
	if inbound != nil {
		req.Header.Set("X-Request-ID", *inbound)
	}
	reqctx.RequestIDMiddleware(logger, next).ServeHTTP(rec, req)

	out.responseID = rec.Header().Get("X-Request-ID")
	out.logOutput = buf.String()
	return out
}

// TestRequestIDMiddleware_MintsWhenAbsent pins the no-inbound-header path: an id
// is minted, echoed, readable from the context, and stamped into the scoped
// logger.
func TestRequestIDMiddleware_MintsWhenAbsent(t *testing.T) {
	t.Parallel()
	got := runMiddleware(t, nil)

	assertCorrelation(t, got, true)
	if want := `"request_id":"` + got.responseID + `"`; !strings.Contains(got.logOutput, want) {
		t.Errorf("scoped logger did not stamp %s; log=%s", want, got.logOutput)
	}
}

// TestRequestIDMiddleware_EchoesConformingInboundID pins the opposite path: a
// caller-supplied id that satisfies the charset is carried verbatim, and recorded
// as caller-supplied rather than minted.
func TestRequestIDMiddleware_EchoesConformingInboundID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{
		"corr-xyz",
		"a",                                    // shortest accepted
		strings.Repeat("x", 128),               // longest accepted
		"AZaz09._-",                            // every accepted character class
		"01234567-89ab-cdef-0123-456789abcdef", // a UUID, the shape the mint path emits
	} {
		t.Run(id[:min(len(id), 24)], func(t *testing.T) {
			t.Parallel()
			got := runMiddleware(t, &id)
			if got.responseID != id {
				t.Errorf("X-Request-ID = %q, want %q echoed verbatim", got.responseID, id)
			}
			assertCorrelation(t, got, false)
		})
	}
}

// TestRequestIDMiddleware_ReplacesHostileInboundID is the control's own reason for
// existing: X-Request-ID is attacker-authored, covered by no signature, bounded
// only by MaxHeaderBytes, and on the Exchange it is written into an append-once
// evidence row and attached to every log line. Anything outside the accepted
// charset and length must be DISCARDED in favour of a minted id rather than
// carried into those sinks — never echoed back, never stored, never logged.
//
// The middleware body is shared, so this covers the Broker identically.
func TestRequestIDMiddleware_ReplacesHostileInboundID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		inbound string
	}{
		{"empty", ""},
		{"one over the length cap", strings.Repeat("x", 129)},
		{"far over the length cap", strings.Repeat("x", 8192)},
		{"crlf header injection", "abc\r\nX-Injected: 1"},
		{"bare newline", "abc\ndef"},
		{"nul byte", "abc\x00def"},
		{"space", "has space"},
		{"log-forging quotes", `abc","request_id":"forged`},
		{"percent encoding", "a%2fb"},
		{"path traversal", "../../etc/passwd"},
		{"sql-ish punctuation", "abc'; DROP TABLE--"},
		{"angle brackets", "<script>"},
		{"non-ascii", "abcédef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := runMiddleware(t, &tc.inbound)

			if got.responseID == tc.inbound {
				t.Fatalf("hostile id %q was echoed back verbatim", tc.inbound)
			}
			// Provenance must say "minted", not "caller-supplied": the caller's
			// value was rejected, so nothing about the stored id came from them.
			assertCorrelation(t, got, true)
			// The rejected value must not survive anywhere downstream. A logged
			// copy would re-open the injection the charset check exists to close.
			if tc.inbound != "" && strings.Contains(got.logOutput, tc.inbound) {
				t.Errorf("rejected id %q reached the log line: %s", tc.inbound, got.logOutput)
			}
		})
	}
}

// TestRequestIDMinted_UnsetWhenNoMiddlewareRan pins the third state: with nothing
// routed into the context there is no id, so its provenance is UNDEFINED rather
// than "caller-supplied". Callers persist the pair together and must be able to
// tell the two apart.
func TestRequestIDMinted_UnsetWhenNoMiddlewareRan(t *testing.T) {
	t.Parallel()
	if got := reqctx.RequestID(context.Background()); got != "" {
		t.Errorf("RequestID = %q, want empty with no middleware", got)
	}
	minted, ok := reqctx.RequestIDMinted(context.Background())
	if ok {
		t.Errorf("RequestIDMinted reported ok=true (minted=%v) with no middleware", minted)
	}
}
