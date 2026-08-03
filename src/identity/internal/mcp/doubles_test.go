//go:build integration

package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
)

// rampPeer is a stand-in Broker or Exchange that gates every RPC behind the
// PRODUCTION RFC 9421 middleware (internal/httpsig.Middleware) — the same gate the
// real Exchange runs.
//
// That is the point of these tests. A double that merely accepted the call would
// prove the tool assembled a request; running the real verifier proves the request
// was signed with the calling agent's own custodied key, over the covered
// components the protocol requires, inside a live freshness window. An unsigned or
// wrongly-signed call is rejected here exactly as it would be in production.
//
// What this does NOT traverse, named honestly: the key the verifier checks against
// is seeded from custody (see fixture.trust), not fetched from the agent's hosted
// WBA directory over HTTP. So a passing test is a CUSTODY round-trip — the
// signature really came from the agent's stored key — not a DIRECTORY round-trip.
// The directory↔custody link has its own coverage in the publisher suite.
type rampPeer struct {
	// The generated Unimplemented handlers supply the RPCs this adapter never
	// calls, so an accidental call to one fails loudly as unimplemented rather
	// than silently succeeding against a stub.
	rampv1connect.UnimplementedExchangeServiceHandler
	rampv1connect.UnimplementedBrokerServiceHandler

	srv *httptest.Server

	mu    sync.Mutex
	calls []peerCall

	// Programmable responses. A nil error means the canned response is returned.
	registerResp *rampv1.RegisterResponse
	statusResp   *rampv1.GetAccountStatusResponse
	resolveResp  *rampv1.DiscoveryResponse
	reportResp   *rampv1.UsageReportResponse
	err          error

	// Execute relay (a bespoke route, not a Connect RPC). relayResp is the 200
	// body; relayErrStatus/relayErrBody, when set, make it answer non-2xx with
	// that raw body — the broker's protojson ErrorDetail shape.
	relayResp      *rampv1.TransactionResponse
	relayErrStatus int
	relayErrBody   []byte

	// Last request per RPC, so a test can assert what the tool actually put on
	// the wire — not merely that something arrived.
	lastRegistration map[string]any
	lastDiscovery    *rampv1.DiscoveryRequest
	lastReport       *rampv1.UsageReport
	lastExecute      *rampv1.TransactionRequest

	// manifestEndpoint, when set, overrides the endpoint this peer advertises in
	// its well-known manifest (default: its own origin). A test points it at a
	// different host to drive the host-anchoring refusal in ReportUsage.
	manifestEndpoint string

	// manifestFetches counts reads of this peer's well-known document. The
	// manifest is served OUTSIDE the signature gate, so those reads never appear
	// in calls; a test that needs to prove a refusal landed BEFORE the fetch — the
	// SSRF property, where the fetch itself is the thing being prevented — has to
	// count them separately.
	manifestFetches int
}

// peerCall records one RPC that made it past the signature gate.
type peerCall struct {
	Path string
	// KeyID is the RFC 9421 keyid the middleware verified — the RFC 7638
	// thumbprint of the key that signed. Asserting on it is how a test proves the
	// call went out as one agent rather than another.
	KeyID string
	// SignatureAgent is the signed directory origin the signer claims, i.e. the
	// agent's own subdomain.
	SignatureAgent string
	// Authorization is whatever arrived in the outbound Authorization header —
	// which must always be EMPTY. The package's central claim is that the inbound
	// bearer never travels outbound, and the peers are third parties (for
	// ramp_report, one an offer named), so a bearer reaching them is credential
	// disclosure. Recorded on every call so assertNoBearerLeaked can check the
	// property everywhere rather than in one test that has to remember to.
	Authorization string
}

// newRAMPPeer starts a peer serving both RAMP services behind the signature gate.
// Serving both on one origin keeps the fixture small; a tool only ever calls the
// service it is wired to, and the recorded path says which was used.
func newRAMPPeer(t *testing.T, resolver httpsig.KeyResolver) *rampPeer {
	t.Helper()
	p := &rampPeer{}

	mux := http.NewServeMux()
	exchangePath, exchangeHandler := rampv1connect.NewExchangeServiceHandler(p)
	brokerPath, brokerHandler := rampv1connect.NewBrokerServiceHandler(p)
	mux.Handle(exchangePath, exchangeHandler)
	mux.Handle(brokerPath, brokerHandler)

	// The manifest an Exchange serves about itself. ramp_report finds where to
	// send a report by reading this — never from our configuration — so the peer
	// has to publish one for that path to work at all. It is deliberately outside
	// the signature gate: the default predicate only covers /ramp.* paths, and a
	// public discovery document is unsigned in production too.
	mux.HandleFunc("GET /.well-known/ramp.json", func(w http.ResponseWriter, _ *http.Request) {
		p.countManifestFetch()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"endpoint": p.advertisedEndpoint()})
	})

	// The Broker's bespoke execute-relay route. It is not a Connect path, so it is
	// handled by hand; it IS signed traffic, so the predicate below routes it
	// through the same signature gate as the /ramp.* RPCs.
	mux.HandleFunc("POST /broker/v1/exchange/execute", p.serveRelay)

	gated := httpsig.Middleware(resolver, httpsig.NewMemoryReplayStore(nil),
		httpsig.InterceptorOptions{
			OnVerified: p.record,
			// Verify the relay route in addition to the default /ramp.* set, so a
			// relay POST is held to the same signature standard as an RPC. The
			// well-known document stays unverified — it matches neither clause.
			PathPredicate: func(path string) bool {
				return strings.HasPrefix(path, "/ramp.") || path == "/broker/v1/exchange/execute"
			},
		}, mux)

	p.srv = httptest.NewServer(gated)
	t.Cleanup(p.srv.Close)
	return p
}

// record notes a verified call. It runs as the middleware's OnVerified hook, so it
// only ever sees requests whose signature already passed.
func (p *rampPeer) record(r *http.Request, v *httpsig.VerifiedRequest) *http.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, peerCall{
		Path:           r.URL.Path,
		KeyID:          v.KeyID,
		SignatureAgent: v.SignatureAgent,
		Authorization:  r.Header.Get("Authorization"),
	})
	return r
}

// assertNoBearerLeaked checks the invariant the package doc calls its reason for
// existing: the caller's OAuth bearer authenticates them to US and must never
// travel outbound. Every peer the tools talk to is a third party, so a bearer
// arriving at one is credential disclosure to a party that should never see it.
//
// Called from every happy path. Cheap, and without it a transport change that
// forwarded the header would pass the entire suite.
func assertNoBearerLeaked(t *testing.T, peers ...*rampPeer) {
	t.Helper()
	for _, p := range peers {
		for _, c := range p.Calls() {
			if c.Authorization != "" {
				t.Errorf("outbound call to %s carried an Authorization header (%q); "+
					"the inbound bearer must never travel outbound", c.Path, c.Authorization)
			}
		}
	}
}

// LastReport / LastExecute / LastDiscovery / LastRegistration read the recorded
// requests under the peer's mutex. The handler goroutine writes them, the test
// goroutine reads them, and there is no happens-before edge between the two — so
// a bare field read is a race the -race detector will eventually catch on someone
// else's afternoon.
func (p *rampPeer) LastReport() *rampv1.UsageReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastReport
}

func (p *rampPeer) LastExecute() *rampv1.TransactionRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastExecute
}

func (p *rampPeer) LastDiscovery() *rampv1.DiscoveryRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastDiscovery
}

func (p *rampPeer) LastRegistration() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastRegistration
}

// URL is the peer's origin.
func (p *rampPeer) URL() string { return p.srv.URL }

// advertisedEndpoint is the endpoint this peer names in its well-known manifest.
// It defaults to the peer's own origin — the host-anchored case — so tests that do
// not touch it exercise a manifest that points at itself.
func (p *rampPeer) advertisedEndpoint() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.manifestEndpoint != "" {
		return p.manifestEndpoint
	}
	return p.srv.URL
}

// setManifestEndpoint makes this peer advertise a different endpoint than its own
// origin, so a test can stage a manifest that redirects a report to another host.
func (p *rampPeer) setManifestEndpoint(endpoint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.manifestEndpoint = endpoint
}

// countManifestFetch notes one read of the well-known document.
func (p *rampPeer) countManifestFetch() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.manifestFetches++
}

// ManifestFetches is how many times this peer's well-known document has been
// read. Zero proves a report was refused before the resolver dialed anything.
func (p *rampPeer) ManifestFetches() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.manifestFetches
}

// Calls returns the verified calls so far.
func (p *rampPeer) Calls() []peerCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]peerCall(nil), p.calls...)
}

// failWith makes every subsequent RPC return err, for driving the RAMP-side
// refusal paths.
func (p *rampPeer) failWith(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *rampPeer) outcome() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// --- ExchangeService ---

func (p *rampPeer) Register(
	_ context.Context, req *connect.Request[rampv1.RegisterRequest],
) (*connect.Response[rampv1.RegisterResponse], error) {
	if err := p.outcome(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.lastRegistration = req.Msg.GetRegistrationData().AsMap()
	resp := p.registerResp
	p.mu.Unlock()
	if resp == nil {
		resp = &rampv1.RegisterResponse{Ver: rampproto.Ver}
	}
	return connect.NewResponse(resp), nil
}

func (p *rampPeer) GetAccountStatus(
	_ context.Context, _ *connect.Request[rampv1.GetAccountStatusRequest],
) (*connect.Response[rampv1.GetAccountStatusResponse], error) {
	if err := p.outcome(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	resp := p.statusResp
	p.mu.Unlock()
	if resp == nil {
		resp = &rampv1.GetAccountStatusResponse{Ver: rampproto.Ver}
	}
	return connect.NewResponse(resp), nil
}

func (p *rampPeer) ReportUsage(
	_ context.Context, req *connect.Request[rampv1.UsageReport],
) (*connect.Response[rampv1.UsageReportResponse], error) {
	if err := p.outcome(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.lastReport = req.Msg
	resp := p.reportResp
	p.mu.Unlock()
	if resp == nil {
		resp = &rampv1.UsageReportResponse{Ver: rampproto.Ver}
	}
	return connect.NewResponse(resp), nil
}

// serveRelay stands in for the Broker's execute-relay endpoint. By the time it
// runs the signature gate has already verified sig1, so it records the request
// and answers with whatever the test programmed: the 200 TransactionResponse, or
// a non-2xx protojson ErrorDetail (the broker's error-envelope shape).
func (p *rampPeer) serveRelay(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req rampv1.TransactionRequest
	// DiscardUnknown mirrors the real relay's tolerance for forward-compatible bodies.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.lastExecute = &req
	errStatus, errBody, resp := p.relayErrStatus, p.relayErrBody, p.relayResp
	p.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if errStatus != 0 {
		w.WriteHeader(errStatus)
		_, _ = w.Write(errBody)
		return
	}
	if resp == nil {
		resp = &rampv1.TransactionResponse{Ver: rampproto.Ver}
	}
	out, _ := protojson.Marshal(resp)
	_, _ = w.Write(out)
}

// --- BrokerService ---

func (p *rampPeer) Resolve(
	_ context.Context, req *connect.Request[rampv1.DiscoveryRequest],
) (*connect.Response[rampv1.DiscoveryResponse], error) {
	if err := p.outcome(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.lastDiscovery = req.Msg
	resp := p.resolveResp
	p.mu.Unlock()
	if resp == nil {
		resp = &rampv1.DiscoveryResponse{Ver: rampproto.Ver}
	}
	return connect.NewResponse(resp), nil
}

// newTrustStore is the key directory the peers verify against: thumbprint →
// public key, seeded from custody as agents are provisioned.
//
// It is httpsig.StaticResolver, the resolver the library already ships for
// exactly this ("intended for test seeding and dynamic registration paths") and
// which the broker suites already use. A hand-rolled equivalent here would also
// have dropped its validity-window check, so this suite could not express a
// key-window negative without re-adding that logic a third time.
func newTrustStore() *httpsig.StaticResolver {
	return httpsig.NewStaticResolver(nil)
}
