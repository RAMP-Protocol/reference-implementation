package transportconnect

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

func TestRejectCode(t *testing.T) {
	hop := fmt.Errorf("%w: got 3 max 2", httpsig.ErrTooManyHops)
	if got := RejectCode(hop); got != connect.CodeResourceExhausted {
		t.Errorf("RejectCode(hop) = %v, want ResourceExhausted", got)
	}
	for _, err := range []error{httpsig.ErrReplayed, httpsig.ErrBrokenSignatureChain, errors.New("bad sig")} {
		if got := RejectCode(err); got != connect.CodeUnauthenticated {
			t.Errorf("RejectCode(%v) = %v, want Unauthenticated", err, got)
		}
	}
}

func TestRejectOutcome(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: got 3 max 2", httpsig.ErrTooManyHops), "REJECTED_HOP_BUDGET"},
		{httpsig.ErrReplayed, "REJECTED_REPLAY"},
		{httpsig.ErrBrokenSignatureChain, "REJECTED_CHAIN"},
		{errors.New("invalid signature"), "REJECTED_SIGNATURE"},
	}
	for _, tc := range cases {
		if got := RejectOutcome(tc.err); got != tc.want {
			t.Errorf("RejectOutcome(%v) = %q, want %q", tc.err, got, tc.want)
		}
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
