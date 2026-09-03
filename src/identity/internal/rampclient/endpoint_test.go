package rampclient_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	rampsdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	audiencetest "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/rampclient"
)

// The identity a stand-in Exchange publishes about itself. It is deliberately
// NOT the address the test dials: an account call is addressed to the Exchange's
// published identity and DIALLED at whatever endpoint that Exchange's manifest
// advertises, and the two coming apart is what these tests are about.
const publishedExchange = "exchange.example"

// TestRegister_GoesToTheEndpointTheNamedExchangeAdvertises is the routing rule.
// The caller names a domain; the endpoint comes from the resolver, which reads
// it out of that domain's own manifest; the request arrives there still naming
// the domain, which is what the receiving Exchange checks it against.
func TestRegister_GoesToTheEndpointTheNamedExchangeAdvertises(t *testing.T) {
	rec := &recordingExchange{}
	srv := serveExchange(t, rec, publishedExchange)

	req := &rampv1.RegisterRequest{Ver: helpers.ProtocolVersion, Exchange: publishedExchange}
	if _, err := newClient(t, staticResolver{publishedExchange: srv.URL}).
		Register(t.Context(), req); err != nil {
		t.Fatalf("register: %v", err)
	}
	if rec.Calls() != 1 {
		t.Fatalf("the advertised endpoint saw %d calls, want 1", rec.Calls())
	}
	if rec.Exchange() != publishedExchange {
		t.Errorf("call addressed to %q, want the domain the caller named %q", rec.Exchange(), publishedExchange)
	}
	// The caller's own message is what went out. This client no longer stamps the
	// recipient, so there is nothing for it to have rewritten — and a future
	// change that started stamping would be visible here.
	if req.GetExchange() != publishedExchange {
		t.Errorf("the caller's request was edited: exchange = %q", req.GetExchange())
	}
}

// TestRegister_IsSignedWhenTheEndpointCarriesAPathPrefix drives the one endpoint
// shape that took the account calls out of the signed set.
//
// The signing transport picks its profile from the path, and its own rule reads
// the path's PREFIX. A bare origin gives "/ramp.v1.ExchangeService/Register" and
// the request is signed. An endpoint advertised as ".../api" gives
// "/api/ramp.v1.ExchangeService/Register", which that rule does not claim — so
// the registration carrying the operator's legal entity and tax identifiers left
// unsigned, silently, and the visible symptom was an Exchange behind a path
// prefix that could never be registered at.
//
// Such an endpoint is conformant: the endpoint rule constrains host, port and
// userinfo, and says nothing about a path. Every other case in this file
// resolves to a bare httptest URL, which has no path, so none of them can see
// this.
func TestRegister_IsSignedWhenTheEndpointCarriesAPathPrefix(t *testing.T) {
	rec := &recordingExchange{}
	// The codec a real Exchange serves through, so the client under test decodes
	// the spelling it will actually meet.
	path, handler := rampv1connect.NewExchangeServiceHandler(rec,
		connect.WithInterceptors(audiencetest.MustInterceptor(t, publishedExchange)),
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()))
	mux := http.NewServeMux()
	mux.Handle("/api"+path, http.StripPrefix("/api", handler))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req := &rampv1.RegisterRequest{Ver: helpers.ProtocolVersion, Exchange: publishedExchange}
	if _, err := newClient(t, staticResolver{publishedExchange: srv.URL + "/api"}).
		Register(t.Context(), req); err != nil {
		t.Fatalf("register: %v", err)
	}
	if rec.Calls() != 1 {
		t.Fatalf("the prefixed endpoint saw %d calls, want 1", rec.Calls())
	}
	if rec.Signature() == "" {
		t.Error("the registration arrived with no Signature header — an endpoint's path " +
			"prefix must not decide whether an account call is signed")
	}
}

// TestAccountStatus_RoutesLikeRegister pins that the two account RPCs resolve
// the same way. They are separate methods, so a fix applied to one and not the
// other is exactly the shape that survives review.
func TestAccountStatus_RoutesLikeRegister(t *testing.T) {
	rec := &recordingExchange{}
	srv := serveExchange(t, rec, publishedExchange)

	_, err := newClient(t, staticResolver{publishedExchange: srv.URL}).
		AccountStatus(t.Context(), &rampv1.GetAccountStatusRequest{
			Ver: helpers.ProtocolVersion, Exchange: publishedExchange,
		})
	if err != nil {
		t.Fatalf("account status: %v", err)
	}
	if rec.StatusExchange() != publishedExchange {
		t.Errorf("status addressed to %q, want %q", rec.StatusExchange(), publishedExchange)
	}
}

// TestAccountCalls_TwoExchangesEachGetTheirOwn is the whole point of the change:
// which Exchange an account call reaches is the request's choice, per call, and
// one client serves both without either leaking into the other.
func TestAccountCalls_TwoExchangesEachGetTheirOwn(t *testing.T) {
	const otherExchange = "exchange-b.example"
	first, second := &recordingExchange{}, &recordingExchange{}
	firstSrv := serveExchange(t, first, publishedExchange)
	secondSrv := serveExchange(t, second, otherExchange)

	client := newClient(t, staticResolver{
		publishedExchange: firstSrv.URL,
		otherExchange:     secondSrv.URL,
	})
	for _, domain := range []string{publishedExchange, otherExchange} {
		if _, err := client.Register(t.Context(), &rampv1.RegisterRequest{
			Ver: helpers.ProtocolVersion, Exchange: domain,
		}); err != nil {
			t.Fatalf("register at %s: %v", domain, err)
		}
	}
	if first.Calls() != 1 || second.Calls() != 1 {
		t.Fatalf("calls landed %d/%d, want one each", first.Calls(), second.Calls())
	}
	if first.Exchange() != publishedExchange || second.Exchange() != otherExchange {
		t.Errorf("each Exchange saw %q/%q, want its own identity",
			first.Exchange(), second.Exchange())
	}
}

// TestRegister_RefusalsThatSendNothing covers every way an account call is
// decided locally. Each reports the SDK's CallNotSent rather than
// CallUnreachable, because each is a verdict about the value: it will be the
// same verdict on a retry, and retrying only repeats the work.
//
// The token is asserted, not just the kind. It is what the tool layer renders as
// the agent-facing reason and what an operator alert keys on, so a change that
// kept the classification and altered the spelling would still break both.
func TestRegister_RefusalsThatSendNothing(t *testing.T) {
	cases := map[string]struct {
		domain   string
		resolver staticResolver
	}{
		"no Exchange named": {
			domain: "", resolver: staticResolver{},
		},
		"a value that is not a usable host": {
			domain: "https://exchange.example/accounts", resolver: staticResolver{},
		},
		"an Exchange that advertises no endpoint": {
			domain:   publishedExchange,
			resolver: staticResolver{publishedExchange: ""},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := newClient(t, tc.resolver).Register(t.Context(), &rampv1.RegisterRequest{
				Ver: helpers.ProtocolVersion, Exchange: tc.domain,
			})
			if err == nil {
				t.Fatalf("register succeeded naming %q", tc.domain)
			}
			var callErr *rampsdkconnect.CallError
			if !errors.As(err, &callErr) {
				t.Fatalf("error %v is not a *rampsdkconnect.CallError", err)
			}
			if callErr.Kind != rampsdkconnect.CallNotSent {
				t.Errorf("kind = %s, want not_sent — a local verdict does not change on a retry",
					callErr.Kind)
			}
			if got := callErr.ReasonOf(); got != "not_sent" {
				t.Errorf("reason token = %q, want %q — this is the string the agent and the "+
					"operator alert both read", got, "not_sent")
			}
		})
	}
}

// TestRegister_AnUnreachableExchangeIsRetryable is the other half of the split.
// A resolver that could not answer is not a verdict about the value, so it must
// NOT be reported as one — an operator alert keyed on "we decided not to send"
// would otherwise fire on every network blip.
func TestRegister_AnUnreachableExchangeIsRetryable(t *testing.T) {
	failing := failingResolver{err: errors.New("dial tcp: connection refused")}

	_, err := newClient(t, failing).Register(t.Context(), &rampv1.RegisterRequest{
		Ver: helpers.ProtocolVersion, Exchange: publishedExchange,
	})
	var callErr *rampsdkconnect.CallError
	if !errors.As(err, &callErr) {
		t.Fatalf("error %v is not a *rampsdkconnect.CallError", err)
	}
	if callErr.Kind != rampsdkconnect.CallUnreachable {
		t.Errorf("kind = %s, want unreachable", callErr.Kind)
	}
}

// TestRegister_TheExchangeChecksWhoTheCallerNamed keeps the property the old
// recipient tests existed for, now that the caller states the recipient rather
// than this client stamping it: a request naming somebody else is refused by the
// Exchange that receives it, through the same interceptor production mounts.
func TestRegister_TheExchangeChecksWhoTheCallerNamed(t *testing.T) {
	rec := &recordingExchange{}
	srv := serveExchange(t, rec, publishedExchange)

	// Resolved to the same endpoint, but addressed to a different party — which
	// is what a poisoned or stale resolution looks like from the Exchange's side.
	_, err := newClient(t, staticResolver{"other.example": srv.URL}).
		Register(t.Context(), &rampv1.RegisterRequest{
			Ver: helpers.ProtocolVersion, Exchange: "other.example",
		})
	if err == nil {
		t.Fatal("a request naming a different Exchange was accepted")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Errorf("refused with %v, want %v", got, connect.CodeInvalidArgument)
	}
	if rec.Calls() != 0 {
		t.Errorf("the handler ran %d times; the interceptor must refuse first", rec.Calls())
	}
}

// TestRegister_DialsUnderTheSSRFGuard is the guard itself under test, and it is
// the reason ExchangeBase exists.
//
// An account call now goes to a host an authenticated agent named, reached at an
// endpoint that host's own manifest advertised. That is a request-derived
// address, so the leg has to dial guarded — and the only way to see the guard
// from outside is to leave the deployment opt-outs alone and watch the dial be
// refused. With the plain transport this test passes silently, which is why it
// asserts the peer saw nothing rather than only that an error came back.
func TestRegister_DialsUnderTheSSRFGuard(t *testing.T) {
	// Explicitly cleared rather than assumed absent: this package's other tests
	// set them, and a value inherited from the environment would turn this into a
	// test that proves nothing.
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "")

	rec := &recordingExchange{}
	srv := serveExchange(t, rec, publishedExchange)
	client, err := rampclient.New(rampclient.Config{
		Keys:         testutil.AgentKeySource(t, "https://agent.example"),
		BrokerURL:    "http://broker.example",
		Endpoints:    staticResolver{publishedExchange: srv.URL},
		ExchangeBase: resolvers.NewGuardedTransport(nil),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = client.Register(t.Context(), &rampv1.RegisterRequest{
		Ver: helpers.ProtocolVersion, Exchange: publishedExchange,
	})
	if err == nil {
		t.Fatal("an account call reached a loopback plaintext endpoint with the guard armed")
	}
	if rec.Calls() != 0 {
		t.Errorf("the endpoint was dialled %d times; the guard must refuse before the request leaves", rec.Calls())
	}
}

// TestNew_RequiresTheInjectedRoutingCollaborators pins both fail-louds. A nil
// resolver would panic on the first account call; a nil guarded transport would
// silently downgrade every account call to an unguarded dial at a host the
// caller named, which is the one that would never show up in a log.
func TestNew_RequiresTheInjectedRoutingCollaborators(t *testing.T) {
	base := rampclient.Config{Keys: testutil.AgentKeySource(t, "https://agent.example"), BrokerURL: "http://broker.example"}

	withResolver := base
	withResolver.Endpoints = staticResolver{}
	if _, err := rampclient.New(withResolver); err == nil {
		t.Error("New accepted a nil ExchangeBase")
	} else if !strings.Contains(err.Error(), "SSRF-guarded") {
		t.Errorf("error %q does not say the transport must be guarded", err)
	}

	withTransport := base
	withTransport.ExchangeBase = resolvers.NewGuardedTransport(nil)
	if _, err := rampclient.New(withTransport); err == nil {
		t.Error("New accepted a nil Endpoints")
	}
}

// newClient builds the client under test over a stubbed resolver.
func newClient(t *testing.T, endpoints rampsdkconnect.EndpointResolver) *rampclient.Client {
	t.Helper()
	// Before rampclient.New, because the SDK reads the two opt-outs when it
	// builds the transport. That ordering is why this is a line in the
	// constructor rather than a fixture the test could call afterwards.
	testutil.AllowLoopbackFetch(t)
	client, err := rampclient.New(rampclient.Config{
		Keys:         testutil.AgentKeySource(t, "https://agent.example"),
		BrokerURL:    "http://broker.example",
		Endpoints:    endpoints,
		ExchangeBase: resolvers.NewGuardedTransport(nil),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

// staticResolver answers from a fixed table, so a test states where an Exchange
// lives without standing up a manifest for it. An entry mapping to "" is an
// Exchange that publishes no endpoint; a missing key is one whose manifest could
// not be read at all.
type staticResolver map[string]string

func (r staticResolver) ResolveEndpoint(_ context.Context, host string) (string, error) {
	endpoint, ok := r[host]
	switch {
	case !ok:
		return "", fmt.Errorf("%w: %s", helpers.ErrInvalidHost, host)
	case endpoint == "":
		return "", resolvers.ErrNoEndpoint
	default:
		return endpoint, nil
	}
}

// failingResolver stands in for a manifest read that did not complete: a dial
// failure, a timeout, a 5xx. None of those is a decision about the value.
type failingResolver struct{ err error }

func (r failingResolver) ResolveEndpoint(context.Context, string) (string, error) {
	return "", r.err
}

// serveExchange starts a stand-in Exchange answering to self, mounting the same
// recipient interceptor production mounts.
func serveExchange(t *testing.T, rec *recordingExchange, self string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle(rampv1connect.NewExchangeServiceHandler(rec,
		connect.WithInterceptors(audiencetest.MustInterceptor(t, self)),
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec())))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// recordingExchange answers both account RPCs and keeps the recipient each call
// named, plus whether the request arrived signed. Only the calls that reach it
// are recorded — a refusal happens in the interceptor, before the handler.
//
// Every recorded field is guarded, and read back through an accessor. The writes
// happen on the httptest server's goroutine and the reads on the test's, so a
// bare field is a race with no happens-before edge between them — one the -race
// detector that runs over every package here would eventually catch, on someone
// else's afternoon. Same shape, and the same reason, as the recording double in
// the MCP package.
type recordingExchange struct {
	rampv1connect.UnimplementedExchangeServiceHandler
	mu             sync.Mutex
	exchange       string
	statusExchange string
	signature      string
	calls          int
}

func (r *recordingExchange) Register(
	_ context.Context, req *connect.Request[rampv1.RegisterRequest],
) (*connect.Response[rampv1.RegisterResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.exchange = req.Msg.GetExchange()
	r.signature = req.Header().Get("Signature")
	return connect.NewResponse(&rampv1.RegisterResponse{Ver: helpers.ProtocolVersion}), nil
}

func (r *recordingExchange) GetAccountStatus(
	_ context.Context, req *connect.Request[rampv1.GetAccountStatusRequest],
) (*connect.Response[rampv1.GetAccountStatusResponse], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.statusExchange = req.Msg.GetExchange()
	r.signature = req.Header().Get("Signature")
	return connect.NewResponse(&rampv1.GetAccountStatusResponse{Ver: helpers.ProtocolVersion}), nil
}

// Calls is how many requests reached the handler.
func (r *recordingExchange) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// Exchange is the recipient the last register call named.
func (r *recordingExchange) Exchange() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exchange
}

// StatusExchange is the recipient the last account-status call named.
func (r *recordingExchange) StatusExchange() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.statusExchange
}

// Signature is the Signature header the last call arrived with, empty when it
// arrived unsigned.
func (r *recordingExchange) Signature() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.signature
}
