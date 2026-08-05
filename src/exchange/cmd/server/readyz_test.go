package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// healthAdapter is a billing backend that answers a health question, standing in
// for the TigerBeetle adapter. The embedded interface is nil — the domain methods
// are never called on this path — so only Health is implemented.
type healthAdapter struct {
	billing.Adapter
	err error
}

func (h healthAdapter) Health(context.Context) error { return h.err }

// errPing is a pool whose Ping always fails, standing in for an unreachable
// catalog database.
type errPing struct{ err error }

func (p errPing) Ping(context.Context) error { return p.err }

// okPing is a pool that answers, standing in for a reachable database.
type okPing struct{}

func (okPing) Ping(context.Context) error { return nil }

// buildProbeMux assembles the public mux with only the fields the health and
// readiness routes read. The Connect-Go handlers register against nil services and
// are never invoked here, exactly as TestAdminRoutesReturn404 does it.
func buildProbeMux(t *testing.T, d muxDeps) http.Handler {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	offerSigner, err := signing.NewEd25519Signer(pub, priv)
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}
	d.agentRegistry = noopRegistry{}
	d.offerSigner = offerSigner
	mux, _, err := buildMux(d)
	if err != nil {
		t.Fatalf("build mux: %v", err)
	}
	return mux
}

// statusOf issues a GET against path and returns the response status.
func statusOf(t *testing.T, srv *httptest.Server, path string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestReadyzCoversTheLedger pins the split between the two probes, which is the
// whole point of having both: /readyz reports the ledger, /healthz does not.
//
// The third case is the one that matters. A ledger outage must take the Exchange
// out of rotation via /readyz while /healthz stays green, so that a routine ledger
// restart does not read as a dead process and get the container restarted — and so
// that free resources, which need no ledger, keep being served throughout.
func TestReadyzCoversTheLedger(t *testing.T) {
	t.Parallel()

	ledgerDown := func(context.Context) error { return errors.New("cluster unavailable") }
	ledgerUp := func(context.Context) error { return nil }

	cases := []struct {
		name        string
		deps        muxDeps
		wantHealthz int
		wantReadyz  int
	}{
		{
			// The free and in-memory billing backends have no ledger, so the
			// composition root hands buildMux a nil probe and readiness collapses
			// onto liveness.
			name:        "no ledger configured",
			deps:        muxDeps{pool: okPing{}, ledgerHealth: nil},
			wantHealthz: http.StatusOK,
			wantReadyz:  http.StatusOK,
		},
		{
			name:        "ledger answering",
			deps:        muxDeps{pool: okPing{}, ledgerHealth: ledgerUp},
			wantHealthz: http.StatusOK,
			wantReadyz:  http.StatusOK,
		},
		{
			name:        "ledger unreachable",
			deps:        muxDeps{pool: okPing{}, ledgerHealth: ledgerDown},
			wantHealthz: http.StatusOK,
			wantReadyz:  http.StatusServiceUnavailable,
		},
		{
			// A database outage fails both: it is the one dependency neither probe
			// can serve without.
			name:        "database unreachable",
			deps:        muxDeps{pool: errPing{err: errors.New("no route")}, ledgerHealth: ledgerUp},
			wantHealthz: http.StatusServiceUnavailable,
			wantReadyz:  http.StatusServiceUnavailable,
		},
		{
			// Both nil is the shape the existing route tests build, and it must stay
			// ready rather than fail closed on absent wiring.
			name:        "nothing wired",
			deps:        muxDeps{pool: nil, ledgerHealth: nil},
			wantHealthz: http.StatusOK,
			wantReadyz:  http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(buildProbeMux(t, tc.deps))
			t.Cleanup(srv.Close)

			if got := statusOf(t, srv, "/healthz"); got != tc.wantHealthz {
				t.Errorf("GET /healthz = %d, want %d", got, tc.wantHealthz)
			}
			if got := statusOf(t, srv, "/readyz"); got != tc.wantReadyz {
				t.Errorf("GET /readyz = %d, want %d", got, tc.wantReadyz)
			}
		})
	}
}

// TestLedgerHealthCheckOnlyForBackendsWithALedger pins the composition-root
// assertion: an adapter that cannot answer a health question yields no probe, so
// /readyz does not invent a dependency the deployment does not have.
func TestLedgerHealthCheckOnlyForBackendsWithALedger(t *testing.T) {
	t.Parallel()

	// The real free adapter — the default backend — has no ledger and no Health.
	if got := ledgerHealthCheck(billing.FreeAdapter{}); got != nil {
		t.Error("free adapter yielded a probe; want nil")
	}

	probe := ledgerHealthCheck(healthAdapter{err: nil})
	if probe == nil {
		t.Fatal("adapter with Health yielded no probe")
	}
	if err := probe(context.Background()); err != nil {
		t.Errorf("probe() = %v, want nil", err)
	}

	sentinel := errors.New("ledger down")
	probe = ledgerHealthCheck(healthAdapter{err: sentinel})
	if probe == nil {
		t.Fatal("adapter with Health yielded no probe")
	}
	if err := probe(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("probe() = %v, want %v", err, sentinel)
	}
}
