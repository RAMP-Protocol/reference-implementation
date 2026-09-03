package transportconnect

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

func TestRejectCode(t *testing.T) {
	hop := fmt.Errorf("%w: got 3 max 2", httpsig.ErrTooManyHops)
	if got := RejectCode(hop); got != connect.CodeResourceExhausted {
		t.Errorf("RejectCode(hop) = %v, want ResourceExhausted", got)
	}
	// Wrapped the way a capture read reports it: io.ReadAll returns the
	// *http.MaxBytesError itself, and a caller may wrap it once more.
	tooLarge := fmt.Errorf("read body: %w", &http.MaxBytesError{Limit: 1})
	if got := RejectCode(tooLarge); got != connect.CodeResourceExhausted {
		t.Errorf("RejectCode(over-cap body) = %v, want ResourceExhausted", got)
	}
	for _, err := range []error{httpsig.ErrReplayed, httpsig.ErrBrokenSignatureChain, errors.New("bad sig")} {
		if got := RejectCode(err); got != connect.CodeUnauthenticated {
			t.Errorf("RejectCode(%v) = %v, want Unauthenticated", err, got)
		}
	}
}

// TestRejectAuditOutcome pins the token the reject loggers emit.
//
// The errors are the SDK's own sentinels, not this package's: the loggers are
// registered as connectserver.WithOnReject, so what reaches them comes from the
// SDK's verify seam. The httpsig.* sentinels are a different family, produced
// by the app-owned reference verifier that no production path runs, and the two
// are distinct objects — errors.Is against the wrong family is false, so a
// classifier keyed on it answers the default for every rejection it sees. That
// is what this test's cases are chosen to catch.
//
// The four authentication outcomes are asserted so a rename in the SDK's
// classifier surfaces here rather than as a silently changed audit value. The
// over-cap case is the one the SDK's enum has no value for, and naming it is
// what this function exists for: a body past the read cap logged as a signature
// failure sends an operator after a key rotation for a caller that sent too
// much.
func TestRejectAuditOutcome(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: got 3 max 2", helpers.ErrTooManyHops), "hop_budget"},
		{connectserver.ErrReplayed, "replay"},
		{helpers.ErrBrokenSignatureChain, "broken_chain"},
		{errors.New("invalid signature"), "signature"},
		{fmt.Errorf("read body: %w", &http.MaxBytesError{Limit: 1}), OutcomeBodyTooLarge},
	}
	for _, tc := range cases {
		if got := RejectAuditOutcome(tc.err); got != tc.want {
			t.Errorf("RejectAuditOutcome(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	if OutcomeBodyTooLarge == connectserver.ReasonSignature.String() {
		t.Error("the over-cap token is the signature token; the two outcomes would be indistinguishable in an audit log")
	}
}

func TestWriteError_HopBudget(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, fmt.Errorf("%w: got 3 max 2", httpsig.ErrTooManyHops))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "resource_exhausted") {
		t.Errorf("body = %q, want resource_exhausted code", body)
	}
	if !strings.Contains(body, "hop budget") {
		t.Errorf("body = %q, want hop-budget message", body)
	}
}

func TestWriteError_Unauthenticated(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, errors.New("signature verification failed"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "unauthenticated") {
		t.Errorf("body = %q, want unauthenticated code", body)
	}
}

// TestWriteError_BodyTooLarge pins the over-cap refusal apart from the other
// ResourceExhausted cause: it is a 413, not a 429, because it asks the caller to
// send less rather than fewer.
func TestWriteError_BodyTooLarge(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, &http.MaxBytesError{Limit: 1 << 20})

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "resource_exhausted") {
		t.Errorf("body = %q, want resource_exhausted code", body)
	}
}
