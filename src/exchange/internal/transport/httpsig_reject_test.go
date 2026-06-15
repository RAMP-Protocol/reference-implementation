package transport_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestLogHTTPSigReject_CarriesRequestID pins the request-id correlation of the
// global httpsig gate's reject log. An unsigned request to a gated /ramp.* path
// fails RFC 9421 verification, so the middleware invokes the production OnError
// (transport.LogHTTPSigReject) before writing 401. RequestIDMiddleware is
// outermost, so the reject line MUST carry the X-Request-ID the caller sent —
// these are the highest-value lines to correlate. A bare, unscoped logger.Warn
// would drop it; this asserts it survives.
func TestLogHTTPSigReject_CarriesRequestID(t *testing.T) {
	t.Parallel()

	const reqID = "corr-sig-1"
	buf := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))

	// Real gate: no registered keys, predicate gates every path. An unsigned
	// request never clears verification → OnError fires.
	resolver := httpsig.NewStaticResolver(nil)
	replay := httpsig.NewMemoryReplayStore(time.Now)
	gated := httpsig.Middleware(resolver, replay, httpsig.InterceptorOptions{
		RequestPredicate: func(*http.Request) bool { return true },
		OnError:          transport.LogHTTPSigReject,
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(transport.RequestIDMiddleware(logger, gated))
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/ramp.v1.ExchangeService/Foo", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Request-ID", reqID)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (unsigned request must be rejected)", resp.StatusCode)
	}
	logged := buf.String()
	if !strings.Contains(logged, "httpsig: reject") {
		t.Fatalf("missing reject log; got: %s", logged)
	}
	if want := `"request_id":"` + reqID + `"`; !strings.Contains(logged, want) {
		t.Fatalf("reject log lacks %s; got: %s", want, logged)
	}
}
