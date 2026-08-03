//go:build integration

package transport_test

// Connect+RFC9421 harness for the ramp.v1.BrokerService/Resolve endpoint.
// This file owns the REAL harness
// helpers the broker resolve integration suite drives through — a real
// http.ServeMux with the generated Connect handler, wrapped in the production
// RFC 9421 httpsig.Middleware + RequestIDMiddleware, served via
// httptest.NewServer, and exercised with rampv1connect.NewBrokerServiceClient
// over the canonical ramphttpsig signing transport. The shape is modeled on the
// Exchange harness (src/exchange/internal/transport/integration_helper_test.go:
// startExchangeServer / newSigningTransport / connect.WithGRPC client).
//
// Round-trip honesty: every leg is a genuine PROTOCOL round-trip — Connect
// client → real RFC 9421 signature → real httpsig middleware → the registered
// Connect handler → the shared h.resolve business core → toDiscoveryResponse → the
// typed DiscoveryResponse the client decodes. No raw DB/internal-state access is
// used to arrange or assert; the mockExchange (a true external, mocked at the
// adapter boundary) is the only mock.
//
// The proof tests that originally lived here (Licensed / BudgetExhausted /
// NoCaller / Impersonation) were folded into resolve_integration_test.go during
// the MIGRATE slice — that suite now drives the SAME Connect surface
// with equal-or-richer typed assertions, so only the harness helpers remain
// here.

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
)

// brokerConnectFixture bundles the in-process server, the underlying base
// transport that signing clients chain onto, the SDK static resolver (so
// negative-path tests can register additional caller keys via resolver.Put),
// and the mockExchange whose call counters pin the absence of upstream side
// effects.
type brokerConnectFixture struct {
	server   *httptest.Server
	base     http.RoundTripper
	resolver *helpers.StaticKeyResolver
	exchange *mockExchange
}

// startBrokerConnectServer reconstructs the Broker's public HTTP surface the way
// production buildBrokerMux does (cmd/server/main.go): it registers the generated
// Connect handler for ramp.v1.BrokerService via connectserver.NewBrokerServiceHandler
// (which wraps request-id + RFC 9421 verify + protovalidate interceptors) and
// serves it via httptest. The wiring mirrors production so the test exercises the
// SAME middleware chain (ADR-008 D1 parity; Testing Doctrine pt9).
//
// callerID/callerPub seed the resolver so the SIGNED happy/refusal paths verify;
// negative-path tests register extra keys via fx.resolver.Put after start.
func startBrokerConnectServer(t *testing.T, fx *fixture, callerID string, callerPub ed25519.PublicKey) *brokerConnectFixture {
	t.Helper()

	// The SDK resolver keys by RFC 9421 keyid — an RFC 7638 thumbprint after
	// the WBA split — not by the caller's directory identity (callerID).
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{rwtestutil.MustThumbprint(t, callerPub): callerPub})
	replayStore := replay.NewCoreAdapter(replay.NewMemoryStore(time.Now))
	// Production parity (cmd/server/main.go buildBrokerMux): the exact ServerOption
	// set the production BrokerService handler wires — no more, no less — so the
	// harness exercises the SAME middleware AND wire codec, not a look-alike.
	// WithValidation(Strict) ALONE installs the SDK's bidirectional protovalidate
	// interceptor (requests + responses + error details, via
	// sdkconnect.NewValidateInterceptor); a separate WithInterceptors(validate...)
	// would only re-add the same engine, so production does not wire one and neither
	// does this harness. WithEmitUnpopulated keeps zero-valued response fields on the
	// JSON wire (the platform JSON contract); dropping it silently forks the wire
	// shape — the divergence TestResolve_RefusalKeepsZeroValuedFieldsOnJSONWire pins.
	svrOpts := []connectserver.ServerOption{
		connectserver.WithKeyResolver(resolver),
		connectserver.WithReplayStore(replayStore),
		connectserver.WithValidation(sdkconnect.ValidationStrict),
		connectserver.WithEmitUnpopulated(),
		// Production parity (cmd/server/main.go): an unsigned /ramp. request
		// reaches the handler, which returns the typed Unauthenticated fault.
		connectserver.WithVerifyGate(func(r *http.Request) bool {
			return r.Header.Get("Signature-Input") != ""
		}),
		// Audit-log every gate rejection with its SDK-classified outcome, exactly
		// as production wires it.
		connectserver.WithOnReject(transport.LogHTTPSigReject),
	}
	// connectserver.NewBrokerServiceHandler wraps request-id (outermost) → RFC 9421
	// verify middleware → connect interceptors (protovalidate).
	connectPath, connectHandler := connectserver.NewBrokerServiceHandler(
		transport.NewBrokerConnectHandler(fx.resolveHandler),
		svrOpts...,
	)
	mux := http.NewServeMux()
	mux.Handle(connectPath, connectHandler)
	// RequestID middleware is built into connectserver; wrapping the WHOLE mux
	// again mirrors production run(), which routes every route through
	// WrapPublicSurface (request-id + URL normalization). Default options: the
	// proxy-trust opt-in is off, matching a directly-exposed broker.
	server := httptest.NewServer(transport.WrapPublicSurface(testutil.DiscardLogger(), mux, runhttp.PublicSurfaceOptions{}))
	t.Cleanup(server.Close)

	base := server.Client().Transport
	if base == nil {
		base = http.DefaultTransport
	}
	return &brokerConnectFixture{server: server, base: base, resolver: resolver, exchange: fx.exchange}
}

// captureBody tees the JSON response body so a test can assert the EXACT wire
// bytes the server emitted (i.e. whether the EmitUnpopulated codec is active)
// while the Connect client still decodes the typed message normally. It wraps
// the signing transport, so the request is signed BEFORE the response is teed.
type captureBody struct {
	base http.RoundTripper
	body []byte
}

func (c *captureBody) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(req)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	raw, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if rerr != nil {
		return nil, rerr
	}
	// Connect advertises gzip, so the server may compress the JSON response. Store
	// the DECODED bytes for wire-shape inspection, but re-serve the original raw
	// bytes to the client so its own decoder is unaffected.
	c.body = raw
	if resp.Header.Get("Content-Encoding") == "gzip" {
		if zr, zerr := gzip.NewReader(bytes.NewReader(raw)); zerr == nil {
			if dec, derr := io.ReadAll(zr); derr == nil {
				c.body = dec
			}
			_ = zr.Close()
		}
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}

// signingBrokerJSONClient is signingBrokerClient's Connect-JSON twin: it drives
// the SAME signed RFC 9421 transport but over the Connect protocol with the
// ProtoJSON codec (connect.WithProtoJSON) rather than gRPC/proto framing, and
// returns the capture so a test can inspect the raw JSON response the server's
// codec produced. JSON is the wire the EmitUnpopulated codec governs (gRPC/proto
// always carries every field), so the wire-shape parity assertion must go over
// JSON to observe it — the gRPC client used elsewhere cannot.
func signingBrokerJSONClient(
	base http.RoundTripper, baseURL, keyID string, priv ed25519.PrivateKey,
) (rampconnect.BrokerServiceClient, *captureBody) {
	cap := &captureBody{base: brokerSigningTransport(base, keyID, priv)}
	client := &http.Client{Transport: cap}
	return rampconnect.NewBrokerServiceClient(client, baseURL, connect.WithProtoJSON()), cap
}

// brokerSigningTransport builds the canonical RAMP RFC 9421 signing transport
// (sdk/go/core.NewSigningTransport) over base: it signs every /ramp.* call with
// keyID as the Signature-Agent directory and priv's RFC 7638 thumbprint as the
// RFC 9421 keyid, under a 3600s window that keeps `expires` inside the verifier's
// freshness check for the whole test run. Shared by both the gRPC and JSON client
// builders so the signing setup lives once.
func brokerSigningTransport(base http.RoundTripper, keyID string, priv ed25519.PrivateKey) http.RoundTripper {
	thumb, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	signer, err := helpers.NewEd25519Signer(thumb, priv)
	if err != nil {
		panic(err)
	}
	return core.NewSigningTransport(signer, base,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithSignatureAgent(keyID),
		core.WithWindow(core.ClockWindow(time.Now, 3600*time.Second)),
	)
}

// newBrokerKeyPair generates a fresh Ed25519 keypair for a caller.
func newBrokerKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	return pub, priv
}

// signingBrokerClient builds a BrokerService Connect client whose transport
// signs every /ramp.* call with keyID/priv using the canonical RAMP RFC 9421
// signing transport (sdk/go/core.NewSigningTransport). connect.WithGRPC matches
// the Exchange precedent that demonstrably passes on the identical httptest shape.
func signingBrokerClient(base http.RoundTripper, baseURL, keyID string, priv ed25519.PrivateKey) rampconnect.BrokerServiceClient {
	client := &http.Client{Transport: brokerSigningTransport(base, keyID, priv)}
	return rampconnect.NewBrokerServiceClient(client, baseURL, connect.WithGRPC())
}

// ---------------------------------------------------------------------------
// Local helpers shared by the broker resolve integration suite
// (resolve_integration_test.go), which drives the typed *rampv1.DiscoveryResponse
// the Connect client decodes.

func assertConnectCodeLocal(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", want)
	}
	if got := connect.CodeOf(err); got != want {
		t.Fatalf("code = %v, want %v (err: %v)", got, want, err)
	}
}

// assertBrokerErrorDetail fails unless err is a *connect.Error carrying a typed
// proto *rampv1.ErrorDetail whose Domain equals wantDomain. This pins the
// ADR-019 fault contract: a broker resolve fault travels as a Connect
// transport error carrying a typed ErrorDetail (read here through the generated
// SDK type, exactly as the Exchange suite reads it via assertDenialReason),
// never as a free-text ramp.broker.error ext key. Broker faults are the generic
// transport class, so the detail carries Message+Domain with NO reason oneof
// (per the proto ErrorDetail comment). Modeled on
// src/exchange/internal/transport/integration_helper_test.go:assertDenialReason.
func assertBrokerErrorDetail(t *testing.T, err error, wantDomain string) {
	t.Helper()
	ed := brokerErrorDetail(t, err)
	if got := ed.GetDomain(); got != wantDomain {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, wantDomain)
	}
}

// brokerErrorDetail locates the single typed *rampv1.ErrorDetail carried on a
// broker Connect fault, asserting err is a *connect.Error that carries one. The
// connect.Error/Details() walk lives here once so the three assert* helpers
// (Domain-only, metadata-field, metadata-absent) layer their specific checks on
// top without duplicating the boundary read (Testing Doctrine pt9 — the detail is
// read through the public Connect error envelope, never past the transport).
func brokerErrorDetail(t *testing.T, err error) *rampv1.ErrorDetail {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	for _, d := range ce.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		if ed, ok := msg.(*rampv1.ErrorDetail); ok {
			return ed
		}
	}
	t.Fatalf("no *rampv1.ErrorDetail on connect error: %v", err)
	return nil
}

// assertBrokerErrorField fails unless err is a *connect.Error carrying a typed
// proto *rampv1.ErrorDetail whose Domain is the broker AND whose
// metadata[key] == want. This pins the ADR-019 §1 obligation for the broker
// Connect sink: a broker input-validation reject carries its offending field
// (or other machine-readable axis) as TYPED ErrorDetail.metadata, NEVER baked
// into the non-authoritative Message string. It is the broker mirror of the
// exchange's assertReportRejectionField
// (src/exchange/internal/transport/integration_assert_test.go:126) and a
// metadata-aware sibling of assertBrokerErrorDetail above (Domain-only). The
// detail is read through the public Connect error envelope (Testing Doctrine
// pt9 — never past the transport boundary).
func assertBrokerErrorField(t *testing.T, err error, key, want string) {
	t.Helper()
	ed := brokerErrorDetail(t, err)
	if got := ed.GetDomain(); got != brokerServiceDomainWant {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, brokerServiceDomainWant)
	}
	if got := ed.GetMetadata()[key]; got != want {
		t.Fatalf("ErrorDetail.metadata[%q] = %q, want %q (metadata=%v)",
			key, got, want, ed.GetMetadata())
	}
}

// assertBrokerErrorMetadataAbsent fails unless err is a *connect.Error carrying a
// typed *rampv1.ErrorDetail whose Domain is the broker AND whose metadata map is
// empty/absent. It is the negative control for the metadata ride: a fault with no
// single offending field (Internal/Upstream/Unauthenticated) must NOT stamp any
// metadata key, proving the ride is conditional and not a blanket stamp.
func assertBrokerErrorMetadataAbsent(t *testing.T, err error) {
	t.Helper()
	ed := brokerErrorDetail(t, err)
	if got := ed.GetDomain(); got != brokerServiceDomainWant {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, brokerServiceDomainWant)
	}
	if md := ed.GetMetadata(); len(md) != 0 {
		t.Fatalf("expected empty/absent metadata on a non-field fault, got %v", md)
	}
}

// brokerServiceDomainWant is the ErrorDetail.Domain every broker fault stamps
// (mirrors the production brokerServiceDomain const). Declared in the test
// package so the metadata assertions do not import an unexported production
// const.
const brokerServiceDomainWant = "ramp.v1.BrokerService"
