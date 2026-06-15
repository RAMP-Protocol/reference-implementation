package rampwellknown_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

func TestGuardedClient_SchemeGuard(t *testing.T) {
	t.Parallel()
	// Default (secure) mode rejects http before any network activity.
	secure := rampwellknown.NewGuardedClient(rampwellknown.GuardOptions{})
	if _, err := secure.Get("http://example.test/x"); !errors.Is(err, rampwellknown.ErrBlockedTarget) { //nolint:noctx,bodyclose // guard rejects pre-dial
		t.Fatalf("secure client must block http scheme; got %v", err)
	}
	// Insecure mode permits http (the request proceeds to a dial, which fails
	// against a non-existent host — the point is it is NOT scheme-blocked).
	insecure := rampwellknown.NewGuardedClient(rampwellknown.GuardOptions{Insecure: true})
	if _, err := insecure.Get("http://127.0.0.1:1/x"); errors.Is(err, rampwellknown.ErrBlockedTarget) { //nolint:noctx,bodyclose // expect a dial error, not a guard block
		t.Fatal("insecure client must not scheme-block http")
	}
}

func TestGuardedClient_BlocksLoopbackDestination(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	// Secure client: the loopback origin must never be reached (scheme is http
	// AND the IP is loopback — either gate refuses it).
	secure := rampwellknown.NewGuardedClient(rampwellknown.GuardOptions{})
	if _, err := secure.Get(srv.URL); err == nil { //nolint:noctx,bodyclose // expect a guard refusal
		t.Fatal("secure client must refuse a loopback origin")
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("loopback origin was reached %d time(s) despite the guard", n)
	}

	// Insecure client (compose/dev): the same loopback origin is reachable.
	insecure := rampwellknown.NewGuardedClient(rampwellknown.GuardOptions{Insecure: true})
	resp, err := insecure.Get(srv.URL) //nolint:noctx // test client
	if err != nil {
		t.Fatalf("insecure client should reach a loopback origin: %v", err)
	}
	_ = resp.Body.Close()
	if n := hits.Load(); n != 1 {
		t.Fatalf("insecure client expected 1 hit, got %d", n)
	}
}

func TestGuardedClient_IPGuardOverHTTPS(t *testing.T) {
	t.Parallel()
	// https passes the scheme gate, so this isolates the dial-time IP check: a
	// loopback destination is refused before TLS/connect is attempted.
	secure := rampwellknown.NewGuardedClient(rampwellknown.GuardOptions{})
	_, err := secure.Get("https://127.0.0.1:1/x") //nolint:noctx,bodyclose // expect a guard refusal
	if !errors.Is(err, rampwellknown.ErrBlockedTarget) {
		t.Fatalf("https loopback must be IP-blocked at dial; got %v", err)
	}
}
