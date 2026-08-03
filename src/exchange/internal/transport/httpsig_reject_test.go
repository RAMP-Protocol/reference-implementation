package transport_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// TestLogHTTPSigReject_CarriesRequestID pins the request-id correlation of
// transport.LogHTTPSigReject. The function is the OnError hook for the RFC 9421
// signature gate; it MUST log with the request_id stamped by RequestIDMiddleware
// (outermost) so every auth-rejection line is correlatable.
//
// The test drives this through a minimal inline middleware that calls
// LogHTTPSigReject and returns 401, wrapped in RequestIDMiddleware. The inline
// middleware stands in for the old httpsig.Middleware; the behavior under test
// is LogHTTPSigReject itself — not the verify pass — so replacing the deleted
// httpsig.Middleware with a direct call is the honest surface.
func TestLogHTTPSigReject_CarriesRequestID(t *testing.T) {
	t.Parallel()

	const reqID = "corr-sig-1"
	buf := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))

	// Inline reject middleware: unconditionally calls LogHTTPSigReject then 401.
	// This drives the exact same log call that the real gate would invoke on an
	// unsigned request, isolating LogHTTPSigReject's request-id-propagation contract
	// from the (now-deleted) httpsig.Middleware verification path.
	sigErr := errors.New("no signature present")
	rejectMiddleware := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		transport.LogHTTPSigReject(r, sigErr)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(transport.RequestIDMiddleware(logger, rejectMiddleware))
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
	if !strings.Contains(logged, "exchange.httpsig.reject") {
		t.Fatalf("missing reject log; got: %s", logged)
	}
	if want := `"request_id":"` + reqID + `"`; !strings.Contains(logged, want) {
		t.Fatalf("reject log lacks %s; got: %s", want, logged)
	}
}

// TestLogHTTPSigReject_ClassifiesOutcomePerReason pins the restored 4-token audit
// vocabulary: each distinct verify-gate reject sentinel logs a distinct outcome
// token, sourced from the SDK's connectserver.ClassifyReject (the app owns no
// copy of the mapping). On the old collapsed path replay/chain both logged
// "REJECTED_SIGNATURE"; this asserts they are distinct again.
func TestLogHTTPSigReject_ClassifiesOutcomePerReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		err   error
		token string
	}{
		{"hop budget", helpers.ErrTooManyHops, `"outcome":"hop_budget"`},
		{"replay", connectserver.ErrReplayed, `"outcome":"replay"`},
		{"broken chain", helpers.ErrBrokenSignatureChain, `"outcome":"broken_chain"`},
		{"signature", helpers.ErrSignatureVerify, `"outcome":"signature"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := &safeBuffer{}
			logger := slog.New(slog.NewJSONHandler(buf, nil))
			reject := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				transport.LogHTTPSigReject(r, tc.err)
				w.WriteHeader(http.StatusUnauthorized)
			})
			srv := httptest.NewServer(transport.RequestIDMiddleware(logger, reject))
			defer srv.Close()

			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				srv.URL+"/ramp.v1.ExchangeService/Foo", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("do: %v", err)
			}
			_ = resp.Body.Close()

			if logged := buf.String(); !strings.Contains(logged, tc.token) {
				t.Fatalf("reject log lacks %s; got: %s", tc.token, logged)
			}
		})
	}
}
