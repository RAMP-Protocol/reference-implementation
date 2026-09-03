//go:build integration

package mcp_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	audiencetest "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// The validity window every fixture peer publishes its offer-signing key over.
// Wide enough that no suite run can fall outside it, which is the only property
// these tests need from it — key-window handling has its own coverage.
var (
	wbaNotBefore = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	wbaNotAfter  = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)
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

	// registration, when set, is the account_registration block and terms pair
	// this peer publishes. Zero means an Exchange that asks for nothing in
	// particular, which is the pass-through state every Exchange was in before
	// the block existed and is still the majority case.
	registration rwtestutil.Registration

	// manifestEndpoint, when set, overrides the endpoint this peer advertises in
	// its well-known manifest (default: its own origin). A test points it at a
	// different host to drive the host-anchoring refusal in ReportUsage.
	manifestEndpoint string
	// manifestFailStatus makes the well-known handler answer this status instead
	// of the document. Zero serves it.
	manifestFailStatus int

	// lastTermsDigest is the terms_digest the most recent Register echoed, kept
	// as a pointer so an ABSENT digest stays distinguishable from a published
	// empty one — the protocol treats those as different cases.
	lastTermsDigest *string

	// manifestFetches counts reads of this peer's well-known document. The
	// manifest is served OUTSIDE the signature gate, so those reads never appear
	// in calls; a test that needs to prove a refusal landed BEFORE the fetch — the
	// SSRF property, where the fetch itself is the thing being prevented — has to
	// count them separately.
	manifestFetches int

	// httpRequests counts EVERY request that reached this peer's server, on any
	// path and whatever the response. The counters above are per-document and
	// per-path, so neither can answer "was this host dialled at all" — a request
	// to a path the mux does not serve increments no document counter and still
	// arrived. A test proving a refusal landed before anything left the process
	// needs the broad count, because a refusal that failed would send a request
	// to exactly such a path.
	httpRequests int

	// offerPriv signs the offers this peer issues, and its public half is what the
	// peer publishes in its own Web Bot Auth directory.
	//
	// The peer needs a real one because discovery verifies: every offer that
	// reaches an agent is checked against the key the issuing exchange publishes,
	// so an offer signed with a made-up value is REJECTED rather than returned. A
	// fixture that hands out unsigned offers can no longer describe a working
	// discovery at all — which is the point, and is why the key lives on the peer
	// that issues the offers rather than in a helper beside them.
	offerPriv ed25519.PrivateKey
	offerPub  ed25519.PublicKey
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
	offerPub, offerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate peer offer key: %v", err)
	}
	p := &rampPeer{offerPriv: offerPriv, offerPub: offerPub}

	// Started later than it is built, because the peer's own published identity
	// is the address it ends up listening on and the recipient check needs that
	// value before the first request arrives.
	srv := httptest.NewUnstartedServer(nil)
	self := srv.Listener.Addr().String()

	mux := http.NewServeMux()
	// The peer refuses a request addressed to somebody else, exactly as a real
	// Exchange does. Without it the double is weaker than the peer it stands for:
	// every account call could leave with a missing or wrong recipient and the
	// suite would pass while production refused all of them. Mounted on the
	// ExchangeService alone — it is the only service here whose messages name a
	// recipient, and the relay POST below is not a Connect route at all.
	// Both doubles serve through the canonical codec, because both stand in for a
	// peer that does. The MCP adapter decodes these replies; feeding it the
	// camelCase alias would test a wire form no RAMP service produces.
	exchangePath, exchangeHandler := rampv1connect.NewExchangeServiceHandler(p,
		connect.WithInterceptors(audiencetest.MustInterceptor(t, self)),
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()))
	brokerPath, brokerHandler := rampv1connect.NewBrokerServiceHandler(p,
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()))
	mux.Handle(exchangePath, exchangeHandler)
	mux.Handle(brokerPath, brokerHandler)

	// The manifest an Exchange serves about itself. ramp_report finds where to
	// send a report by reading this — never from our configuration — so the peer
	// has to publish one for that path to work at all. It is deliberately outside
	// the signature gate: the default predicate only covers /ramp.* paths, and a
	// public discovery document is unsigned in production too.
	mux.HandleFunc("GET /.well-known/ramp.json", func(w http.ResponseWriter, r *http.Request) {
		p.countManifestFetch()
		if status := p.manifestStatus(); status != 0 {
			http.Error(w, "the manifest is unavailable", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(rwtestutil.ExchangeManifestWithRegistration(
			r.Host, p.advertisedEndpoint(), p.publishedRegistration()))
	})

	// The Web Bot Auth directory carrying this peer's OFFER-signing key. After the
	// WBA split that key lives only here, and it is what discovery resolves an
	// offer's signature against, so a peer without this document issues offers
	// nobody can verify. Unsigned for the same reason as the manifest above: a
	// public key-discovery document is unauthenticated in production too.
	mux.HandleFunc("GET /.well-known/http-message-signatures-directory",
		func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/jwk-set+json")
			// Built through the shared key builder, which stamps the RFC 8037 JWK
			// header quartet in exactly one place. A literal here would be a second
			// copy of that quartet, unchecked against the schema and free to drift
			// from what the resolver reads.
			_, _ = w.Write(rwtestutil.MarshalWBA(rwtestutil.WBAFile(
				rampwellknown.NewKey(p.offerPub, wbaNotBefore, wbaNotAfter))))
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

	// Counting sits OUTSIDE the signature gate and outside the mux, so it sees a
	// request whatever happens to it afterwards — refused for its signature,
	// answered 404 by the mux, or served. That is the whole point: the question
	// it answers is whether this host was dialled, not whether it liked what
	// arrived.
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.countHTTPRequest()
		gated.ServeHTTP(w, r)
	})
	srv.Start()
	p.srv = srv
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

// Domain is the peer's canonical exchange domain — its host:port, the value an
// Offer carries in its exchange field. The port is part of it: a manifest may
// only advertise an endpoint on the host AND port that served it, and the
// directory lookup concatenates this value, so a bare host would look elsewhere.
//
// It takes t and goes through hostOf so a peer's domain is derived exactly once,
// with the check that the origin is the plain http the fixture builds. Trimming
// the prefix inline returns the whole URL when it is absent, and a test then
// carries a scheme into a field that must hold a host — which fails much later,
// somewhere else.
func (p *rampPeer) Domain(t *testing.T) string {
	t.Helper()
	return hostOf(t, p.srv.URL)
}

// Offer builds an offer this peer has genuinely issued: stamped with its own
// exchange domain and signed with the key its directory publishes.
//
// Tests call it instead of writing an Offer literal because discovery verifies
// what it returns. An offer assembled by hand carries a signature over nothing,
// and now arrives at the agent as a REJECTION rather than as an offer — so a
// literal no longer describes a working discovery, whatever it says.
func (p *rampPeer) Offer(t *testing.T, offerID string) *rampv1.Offer {
	t.Helper()
	// An offer with no expiry is an EXPIRED offer: the zero timestamp is in the
	// past, and the protocol requires rejecting an offer whose expires_at has
	// passed. So a fixture offer has to carry a real one or it never reaches the
	// agent, whatever else is right about it.
	//
	// The window is read against the wall clock rather than the fixture's
	// deterministic one, because the verifier the SDK builds takes its own time
	// source. Far enough out that it cannot expire mid-suite.
	return p.OfferAt(t, offerID, time.Now().Add(24*time.Hour))
}

// OfferAt is Offer with the expiry chosen, for the tests that drive the freshness
// rule. A past instant produces an offer that is correctly signed and correctly
// issued and still refused, which is the only way to reach that arm — the
// signature covers expires_at, so an expiry cannot be edited onto a signed offer
// afterwards without turning the case into a signature failure instead.
func (p *rampPeer) OfferAt(t *testing.T, offerID string, expiresAt time.Time) *rampv1.Offer {
	t.Helper()
	offer := &rampv1.Offer{
		OfferId:   offerID,
		Exchange:  p.Domain(t),
		ExpiresAt: timestamppb.New(expiresAt),
	}
	sig, err := helpers.SignOffer(p.offerPriv, offer)
	if err != nil {
		t.Fatalf("sign offer %q: %v", offerID, err)
	}
	offer.Signature = sig
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm
	return offer
}

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

// publishedRegistration reports what this peer publishes about registering.
func (p *rampPeer) publishedRegistration() rwtestutil.Registration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.registration
}

// setRegistration makes this peer publish a registration schema, a terms pair,
// or both. Called between calls, so a test can stage an Exchange that revises
// what it asks for and drive what the adapter does about it.
func (p *rampPeer) setRegistration(reg rwtestutil.Registration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.registration = reg
}

// LastTermsDigest is the terms_digest the most recent Register echoed, and
// whether it carried one at all. Two return values because an ABSENT digest is
// its own case in the protocol — the Exchange publishes none — and "" would
// make it indistinguishable from a published empty one.
func (p *rampPeer) LastTermsDigest() (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastTermsDigest == nil {
		return "", false
	}
	return *p.lastTermsDigest, true
}

// failManifest makes this peer answer its well-known document with status
// instead of serving it, so a test can stage the one outbound failure that has
// nothing to do with the RPC: the Exchange is reachable but its manifest is not
// readable. Zero restores normal serving.
func (p *rampPeer) failManifest(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.manifestFailStatus = status
}

// manifestStatus is the status the well-known handler should answer with, or 0
// to serve the document.
func (p *rampPeer) manifestStatus() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.manifestFailStatus
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

// countHTTPRequest notes one request reaching this peer's server, on any path.
func (p *rampPeer) countHTTPRequest() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpRequests++
}

// HTTPRequests is how many requests have reached this peer on any path, served
// or refused. Zero proves nothing was dialled here at all.
func (p *rampPeer) HTTPRequests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.httpRequests
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
	p.lastTermsDigest = req.Msg.TermsDigest
	resp := p.registerResp
	p.mu.Unlock()
	if resp == nil {
		resp = &rampv1.RegisterResponse{Ver: helpers.ProtocolVersion}
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
		resp = &rampv1.GetAccountStatusResponse{Ver: helpers.ProtocolVersion}
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
		resp = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion}
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
		resp = &rampv1.TransactionResponse{Ver: helpers.ProtocolVersion}
	}
	out, _ := protojson.MarshalOptions{UseProtoNames: true}.Marshal(resp)
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
		resp = &rampv1.DiscoveryResponse{Ver: helpers.ProtocolVersion}
	}
	return connect.NewResponse(resp), nil
}

// newTrustStore is the key directory the peers verify against: thumbprint →
// public key, seeded from custody as agents are provisioned.
//
// It is the SDK's helpers.StaticKeyResolver — the in-memory map double the
// SDK ships "for preloaded key sets and tests", with Put for dynamic
// registration — the same double the broker suites use. It carries no
// validity-window logic, so a key-window negative cannot be expressed through
// this trust store; window enforcement is covered where it lives, in the
// well-known resolver suites.
func newTrustStore() *helpers.StaticKeyResolver {
	return helpers.NewStaticKeyResolver(nil)
}
