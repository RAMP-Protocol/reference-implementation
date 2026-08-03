package ramphttpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yaronf/httpsign"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

const (
	rampTarget = "/ramp.v1.ExchangeService/DiscoverResources"
	wbaTarget  = "/article/2026/07"
)

// agentKeyFor builds a deterministic AgentKey with the directory an agent of that
// seed would publish. The keyid is left empty so the transport derives it — which
// is what a KeySource backed by key custody does.
func agentKeyFor(t *testing.T, seed byte, directory string) (AgentKey, ed25519.PublicKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return AgentKey{Directory: directory, Private: priv}, priv.Public().(ed25519.PublicKey)
}

func thumbprintOf(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return tp
}

// captureServer records every request it receives, body restored, so a test can
// verify the signature against the bytes that actually crossed the wire rather
// than the ones the transport thinks it sent.
func captureServer(t *testing.T) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	seen := make([]*http.Request, 0, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(context.Background())
		body, _ := io.ReadAll(r.Body)
		clone.Body = io.NopCloser(bytes.NewReader(body))
		seen = append(seen, clone)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// send drives one request through a transport built with opts; what the server
// received is read off the capture recorder.
func send(t *testing.T, method, url string, body []byte, opts ...Option) {
	t.Helper()
	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), opts...)
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(newRequest(t, method, url, body))
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_ = resp.Body.Close()
}

// sendExpectingFailure drives a request the transport is expected to refuse and
// returns the error, closing any response body the client did hand back.
func sendExpectingFailure(t *testing.T, transport http.RoundTripper, url string) error {
	t.Helper()
	resp, err := (&http.Client{Transport: transport}).Do(newRequest(t, http.MethodGet, url, nil))
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func newRequest(t *testing.T, method, url string, body []byte) *http.Request {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

// staticSource is the KeySource a single-identity caller wires: the same key for
// every request.
func staticSource(key AgentKey) Option {
	return WithKeySource(func(context.Context) (AgentKey, error) { return key, nil })
}

// verifyWBA checks a received request under the Web Bot Auth profile, holding it
// to the tag an origin filters on.
func verifyWBA(t *testing.T, req *http.Request, pub ed25519.PublicKey) error {
	t.Helper()
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false).SetAllowedTags([]string{httpsig.WBATag})
	verifier, err := httpsign.NewEd25519Verifier(pub, cfg, httpsign.Headers("@authority", "signature-agent"))
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	return httpsign.VerifyRequest("sig1", *verifier, req)
}

// TestRoundTrip_RAMPTargetKeepsRAMPProfile pins that enabling the Web Bot Auth
// branch does not touch RAMP traffic: a /ramp.* request still verifies under the
// production RAMP verifier, with the bare Signature-Agent that verifier reads and
// none of the WBA parameters. The Exchange mirrors these bytes, so a drift here is
// a production auth outage.
func TestRoundTrip_RAMPTargetKeepsRAMPProfile(t *testing.T) {
	srv, seen := captureServer(t)
	key, pub := agentKeyFor(t, 0x21, "https://alice.rampmcp.org")
	body := []byte(`{"urls":["https://publisher.example/a"]}`)

	req := newRequest(t, http.MethodPost, srv.URL+rampTarget, body)
	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second),
		staticSource(key), WithWBASigning())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_ = resp.Body.Close()

	got := (*seen)[0]
	resolver := httpsig.NewStaticResolver(map[string]ed25519.PublicKey{thumbprintOf(t, pub): pub})
	verified, err := httpsig.VerifyRequest(got, resolver)
	if err != nil {
		t.Fatalf("RAMP verify: %v", err)
	}
	if verified.KeyID != thumbprintOf(t, pub) {
		t.Errorf("keyid = %q, want the thumbprint %q", verified.KeyID, thumbprintOf(t, pub))
	}
	if verified.SignatureAgent != key.Directory {
		t.Errorf("Signature-Agent = %q, want the bare directory %q", verified.SignatureAgent, key.Directory)
	}
	params, err := httpsig.ParseSignatureLabels(got.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if params[0].Tag != "" {
		t.Errorf("RAMP signature carries tag=%q; the RAMP profile has none", params[0].Tag)
	}
}

// TestRoundTrip_BodylessRAMPTargetStaysUnsigned pins the RAMP branch's skip rule
// against the new WBA branch: a bodyless /ramp.* request is still forwarded
// unsigned, and does NOT fall through to the Web Bot Auth profile. A RAMP peer
// verifying the RAMP covered set would reject a WBA signature outright, so a
// fall-through would turn a silently-unsigned request into a loudly-rejected one.
func TestRoundTrip_BodylessRAMPTargetStaysUnsigned(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x27, "https://alice.rampmcp.org")

	send(t, http.MethodGet, srv.URL+rampTarget, nil, staticSource(key), WithWBASigning())

	if h := (*seen)[0].Header.Get("Signature"); h != "" {
		t.Errorf("bodyless RAMP request was signed: %q", h)
	}
}

// TestNew_RejectsUnusableKeyMaterial pins that a misconfigured composition root
// fails at construction. Since a caller may now legitimately leave the key nil and
// supply WithKeySource instead, a nil key with NO source has to be an error — it
// used to panic dereferencing the key inside the thumbprint derivation.
func TestNew_RejectsUnusableKeyMaterial(t *testing.T) {
	t.Parallel()
	cases := map[string]ed25519.PrivateKey{
		"nil key":   nil,
		"truncated": ed25519.PrivateKey("too short"),
	}
	for name, priv := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(nil, "https://alice.rampmcp.org", priv,
				ClockWindow(clock.System{}, 30*time.Second)); err == nil {
				t.Fatal("a transport was built with unusable key material")
			}
		})
	}
}

// TestRoundTrip_AppendSignerUsesTheResolvedKey covers the always-append branch
// with a per-request key: the relay caller's mode degrades to a plain sig1 when
// nothing is signed yet, and that sig1 must carry the key the source resolved, not
// one bound at construction.
func TestRoundTrip_AppendSignerUsesTheResolvedKey(t *testing.T) {
	srv, seen := captureServer(t)
	key, pub := agentKeyFor(t, 0x28, "https://alice.rampmcp.org")
	body := []byte(`{"urls":["https://publisher.example/a"]}`)

	send(t, http.MethodPost, srv.URL+rampTarget, body, staticSource(key), WithAppendSigner())

	got := (*seen)[0]
	resolver := httpsig.NewStaticResolver(map[string]ed25519.PublicKey{thumbprintOf(t, pub): pub})
	verified, err := httpsig.VerifyRequest(got, resolver)
	if err != nil {
		t.Fatalf("append-signed request did not verify: %v", err)
	}
	if verified.Label != "sig1" {
		t.Errorf("label = %q, want sig1 (nothing to chain onto)", verified.Label)
	}
	if verified.KeyID != thumbprintOf(t, pub) {
		t.Errorf("keyid = %q, want the resolved key's thumbprint %q", verified.KeyID, thumbprintOf(t, pub))
	}
}

// TestRoundTrip_ChainsOverAnIncomingSignature covers the default branch's relay
// path: a request that already carries a signature is CO-signed, not re-signed, so
// the ordered signatures form the forwarding chain a multisig verifier walks. The
// co-signature must carry the resolved key and must not disturb the incoming one.
func TestRoundTrip_ChainsOverAnIncomingSignature(t *testing.T) {
	srv, seen := captureServer(t)
	agent, agentPub := agentKeyFor(t, 0x29, "https://alice.rampmcp.org")
	relay, relayPub := agentKeyFor(t, 0x2a, "https://relay.rampmcp.org")
	body := []byte(`{"urls":["https://publisher.example/a"]}`)

	// The originating agent signs first, naming its own directory — the value its
	// sig1 covers and the relay must preserve.
	req := newRequest(t, http.MethodPost, srv.URL+rampTarget, body)
	req.Header.Set(httpsig.SignatureAgentHeader, agent.Directory)
	agentKeyID := thumbprintOf(t, agentPub)
	if err := httpsig.SignRequestRAMP(req, body, agentKeyID, agent.Private,
		time.Now().Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("agent sign: %v", err)
	}

	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), staticSource(relay))
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	_ = resp.Body.Close()

	got := (*seen)[0]
	relayKeyID := thumbprintOf(t, relayPub)
	resolver := httpsig.NewStaticResolver(map[string]ed25519.PublicKey{
		agentKeyID: agentPub,
		relayKeyID: relayPub,
	})
	verified, err := httpsig.VerifyMultisigRequest(got, resolver)
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("got %d signatures, want the agent's plus the relay's", len(verified))
	}
	if verified[0].KeyID != agentKeyID {
		t.Errorf("sig1 keyid = %q, want the agent's %q", verified[0].KeyID, agentKeyID)
	}
	if verified[1].KeyID != relayKeyID {
		t.Errorf("sig2 keyid = %q, want the resolved relay key %q", verified[1].KeyID, relayKeyID)
	}
	// The relay must not repoint discovery: sig1 covers the agent's directory.
	if got.Header.Get(httpsig.SignatureAgentHeader) != agent.Directory {
		t.Errorf("Signature-Agent = %q, want the agent's %q preserved",
			got.Header.Get(httpsig.SignatureAgentHeader), agent.Directory)
	}
}

// TestRoundTrip_NonRAMPTargetUnsignedByDefault pins the contract every existing
// caller was built against: traffic that is not a RAMP RPC leaves this transport
// untouched unless the WBA branch is explicitly enabled.
func TestRoundTrip_NonRAMPTargetUnsignedByDefault(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x22, "https://alice.rampmcp.org")

	send(t, http.MethodGet, srv.URL+wbaTarget, nil, staticSource(key))

	got := (*seen)[0]
	if h := got.Header.Get("Signature"); h != "" {
		t.Errorf("unsigned path emitted a Signature: %q", h)
	}
	if h := got.Header.Get("Signature-Input"); h != "" {
		t.Errorf("unsigned path emitted a Signature-Input: %q", h)
	}
	if h := got.Header.Get(httpsig.SignatureAgentHeader); h != "" {
		t.Errorf("unsigned path emitted a Signature-Agent: %q", h)
	}
}

// TestRoundTrip_BodylessGETSignedUnderWBA is the case the RAMP branch cannot
// serve: an ordinary Web Bot Auth request is a GET with no body, and the RAMP
// branch skips bodyless requests. With the WBA branch on it is signed and
// verifies at the origin.
func TestRoundTrip_BodylessGETSignedUnderWBA(t *testing.T) {
	srv, seen := captureServer(t)
	key, pub := agentKeyFor(t, 0x23, "https://alice.rampmcp.org")

	send(t, http.MethodGet, srv.URL+wbaTarget, nil, staticSource(key), WithWBASigning())

	got := (*seen)[0]
	if err := verifyWBA(t, got, pub); err != nil {
		t.Fatalf("WBA verify: %v", err)
	}
	if want := `"` + key.Directory + `"`; got.Header.Get(httpsig.SignatureAgentHeader) != want {
		t.Errorf("Signature-Agent = %s, want %s (quoted sf-string)",
			got.Header.Get(httpsig.SignatureAgentHeader), want)
	}
	params, err := httpsig.ParseSignatureLabels(got.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if params[0].KeyID != thumbprintOf(t, pub) {
		t.Errorf("keyid = %q, want the thumbprint %q", params[0].KeyID, thumbprintOf(t, pub))
	}
	if params[0].Tag != httpsig.WBATag {
		t.Errorf("tag = %q, want %q", params[0].Tag, httpsig.WBATag)
	}
	if got.Header.Get("Content-Digest") != "" {
		t.Error("bodyless request emitted a Content-Digest")
	}
}

// TestRoundTrip_WBABodiedRequestBindsTheBody covers the bodied WBA case: the
// digest is emitted and the signature commits to it, so an intermediary cannot
// swap the payload.
func TestRoundTrip_WBABodiedRequestBindsTheBody(t *testing.T) {
	srv, seen := captureServer(t)
	key, pub := agentKeyFor(t, 0x24, "https://alice.rampmcp.org")
	body := []byte(`{"intent":"read"}`)

	send(t, http.MethodPost, srv.URL+wbaTarget, body, staticSource(key), WithWBASigning())

	got := (*seen)[0]
	if err := verifyWBA(t, got, pub); err != nil {
		t.Fatalf("WBA verify: %v", err)
	}
	if got.Header.Get("Content-Digest") == "" {
		t.Fatal("bodied WBA request emitted no Content-Digest")
	}
	params, err := httpsig.ParseSignatureLabels(got.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var covered bool
	for _, c := range params[0].Covered {
		if c.Name == "content-digest" {
			covered = true
		}
	}
	if !covered {
		t.Error("bodied WBA signature does not cover content-digest")
	}
}

// TestRoundTrip_KeySourceSignsAsEachAgent is the registry's case: ONE transport,
// many agents. Two back-to-back requests resolve different keys and each is signed
// as — and verifies as — its own agent. A transport that cached the first key
// would sign the second agent's request as the first, which is an impersonation,
// not a bug in performance.
func TestRoundTrip_KeySourceSignsAsEachAgent(t *testing.T) {
	srv, seen := captureServer(t)
	alice, alicePub := agentKeyFor(t, 0x25, "https://alice.rampmcp.org")
	bob, bobPub := agentKeyFor(t, 0x26, "https://bob.rampmcp.org")

	keys := []AgentKey{alice, bob}
	var calls int
	src := WithKeySource(func(context.Context) (AgentKey, error) {
		key := keys[calls]
		calls++
		return key, nil
	})
	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), src, WithWBASigning())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	client := &http.Client{Transport: transport}
	for range keys {
		resp, doErr := client.Do(newRequest(t, http.MethodGet, srv.URL+wbaTarget, nil))
		if doErr != nil {
			t.Fatalf("round trip: %v", doErr)
		}
		_ = resp.Body.Close()
	}

	want := []struct {
		pub ed25519.PublicKey
		dir string
	}{{alicePub, alice.Directory}, {bobPub, bob.Directory}}
	for i, w := range want {
		got := (*seen)[i]
		if err := verifyWBA(t, got, w.pub); err != nil {
			t.Errorf("request %d did not verify under its own agent's key: %v", i, err)
		}
		if agent := got.Header.Get(httpsig.SignatureAgentHeader); agent != `"`+w.dir+`"` {
			t.Errorf("request %d Signature-Agent = %s, want %q", i, agent, w.dir)
		}
	}
}

// relayTarget is a non-/ramp.* route that carries a RAMP body — the shape
// WithRAMPTargets exists for (the Broker's execute relay).
const relayTarget = "/broker/v1/exchange/execute"

// matchPath builds the predicate shape a caller passes to WithRAMPTargets.
func matchPath(path string) func(*http.Request) bool {
	return func(req *http.Request) bool { return req.URL != nil && req.URL.Path == path }
}

// TestRoundTrip_WithRAMPTargetsSignsANonRAMPPathAsRAMP is the option's reason for
// existing: the execute relay is not a /ramp.* route, but the Broker verifies its
// body under the RAMP covered set, so it has to be signed as RAMP rather than left
// to the WBA branch or to no branch at all. Without the option the same request
// goes out unsigned (see TestRoundTrip_NonRAMPTargetUnsignedByDefault), so this
// pins the difference the option makes.
func TestRoundTrip_WithRAMPTargetsSignsANonRAMPPathAsRAMP(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x31, "https://alice.rampmcp.org")
	body := []byte(`{"items":[]}`)

	send(t, http.MethodPost, srv.URL+relayTarget, body,
		staticSource(key), WithRAMPTargets(matchPath(relayTarget)))

	got := (*seen)[0]
	if got.Header.Get("Signature") == "" {
		t.Fatal("relay POST went out unsigned; WithRAMPTargets did not claim it")
	}
	// The RAMP profile publishes a bare Signature-Agent; the WBA profile does not.
	// Asserting on it is how this distinguishes "signed as RAMP" from "signed".
	if got.Header.Get("Signature-Agent") == "" {
		t.Error("relay POST carries no Signature-Agent, so it was not signed under the RAMP profile")
	}
}

// A /ramp.* path stays RAMP even when the predicate rejects it. The option's doc
// says it "only adds targets, it never removes them", and a predicate that
// accidentally un-signed real RPCs would be an auth outage rather than a missing
// feature.
func TestRoundTrip_WithRAMPTargetsNeverRemovesRAMPPaths(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x32, "https://alice.rampmcp.org")

	send(t, http.MethodPost, srv.URL+rampTarget, []byte(`{}`),
		staticSource(key), WithRAMPTargets(func(*http.Request) bool { return false }))

	if (*seen)[0].Header.Get("Signature") == "" {
		t.Fatal("a /ramp.* request went unsigned because the predicate returned false")
	}
}

// A matched target with NO body falls to signNone rather than to WBA, mirroring
// the bodyless-/ramp.* rule. A peer verifying the RAMP covered set would reject a
// WBA signature outright, so falling through would turn a silently-unsigned
// request into a loudly-rejected one.
func TestRoundTrip_WithRAMPTargetsBodylessStaysUnsigned(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x33, "https://alice.rampmcp.org")

	send(t, http.MethodGet, srv.URL+relayTarget, nil,
		staticSource(key), WithRAMPTargets(matchPath(relayTarget)))

	if h := (*seen)[0].Header.Get("Signature"); h != "" {
		t.Errorf("bodyless matched target was signed: %q", h)
	}
}
