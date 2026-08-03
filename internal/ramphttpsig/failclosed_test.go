package ramphttpsig

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// The cases here all drive the same rule from different directions: a request the
// transport cannot sign correctly must not leave, and the caller must be told why.
// Signing is the only thing identifying the agent to the origin, so a request that
// slipped out unsigned would be read as an anonymous bot — the exact outcome this
// transport exists to prevent. Split out of dispatch_test.go, which covers which
// profile a target selects rather than what happens when signing cannot proceed.

// TestRoundTrip_KeySourceFailureNeverSends pins the fail-closed behavior: when the
// key cannot be resolved — custody down, no active key, an unauthenticated caller —
// the request must not go out unsigned. An origin that received it would treat it
// as an anonymous bot.
func TestRoundTrip_KeySourceFailureNeverSends(t *testing.T) {
	srv, seen := captureServer(t)
	sentinel := errors.New("no active key")
	src := WithKeySource(func(context.Context) (AgentKey, error) { return AgentKey{}, sentinel })

	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), src, WithWBASigning())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	err = sendExpectingFailure(t, transport, srv.URL+wbaTarget)

	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the key-source failure", err)
	}
	if len(*seen) != 0 {
		t.Errorf("server received %d requests; an unsignable request must not be sent", len(*seen))
	}
}

// closeRecordingBody is a request body that records whether it was closed. An
// in-memory body makes an unclosed reader invisible; a streamed one (a pipe, a
// file, an upstream response) leaks, which is why RoundTrip's contract requires
// the close on every path.
type closeRecordingBody struct {
	io.Reader
	closed bool
}

func (b *closeRecordingBody) Close() error { b.closed = true; return nil }

// TestRoundTrip_KeySourceFailureClosesTheBody pins the half of the RoundTripper
// contract the fail-closed path is most likely to break: "RoundTrip must always
// close the body, including on errors". Key resolution fails routinely — custody
// down, no active key, an unauthenticated caller — so this is the ordinary path,
// not an exotic one, and every signed RAMP request carries a body.
func TestRoundTrip_KeySourceFailureClosesTheBody(t *testing.T) {
	srv, seen := captureServer(t)
	sentinel := errors.New("no active key")
	src := WithKeySource(func(context.Context) (AgentKey, error) { return AgentKey{}, sentinel })

	body := &closeRecordingBody{Reader: bytes.NewReader([]byte(`{"q":"x"}`))}
	req := newRequest(t, http.MethodPost, srv.URL+rampTarget, nil)
	req.Body = body
	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), src)
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}

	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the key-source failure", err)
	}
	if !body.closed {
		t.Error("RoundTrip returned without closing the caller's body")
	}
	if len(*seen) != 0 {
		t.Errorf("server received %d requests; want none", len(*seen))
	}
}

// TestRoundTrip_RejectsAKeyIDThatDoesNotMatchTheKey pins that the keyid on the
// wire is the one derived from the key that actually signs. A custody bug pairing
// one agent's stored thumbprint with another's key would otherwise be invisible
// here and total at the origin: every signature rejected, for a reason nothing on
// this side reports.
func TestRoundTrip_RejectsAKeyIDThatDoesNotMatchTheKey(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x5c, "https://alice.rampmcp.org")
	_, otherPub := agentKeyFor(t, 0x6d, "https://bob.rampmcp.org")
	key.KeyID = thumbprintOf(t, otherPub)

	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second),
		staticSource(key), WithWBASigning())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	err = sendExpectingFailure(t, transport, srv.URL+wbaTarget)

	if !errors.Is(err, ErrUnusableKey) {
		t.Fatalf("err = %v, want ErrUnusableKey", err)
	}
	if len(*seen) != 0 {
		t.Errorf("server received %d requests; a mis-keyed signature must not be sent", len(*seen))
	}
}

// failingBody is a request body that errors partway through, standing in for a
// streaming source that dies mid-read.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("body source failed") }
func (failingBody) Close() error             { return nil }

// TestRoundTrip_UnreadableBodyNeverSends pins fail-closed on the buffering step.
// The signature commits to the body, so a body that cannot be read cannot be
// signed — and a request that cannot be signed must not be sent. Forwarding it
// would put an unsigned, half-read request in front of the origin.
func TestRoundTrip_UnreadableBodyNeverSends(t *testing.T) {
	srv, seen := captureServer(t)
	key, _ := agentKeyFor(t, 0x2b, "https://alice.rampmcp.org")

	req := newRequest(t, http.MethodPost, srv.URL+rampTarget, nil)
	req.Body = failingBody{}
	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), staticSource(key))
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}

	if err == nil {
		t.Fatal("a request whose body could not be read was sent anyway")
	}
	if len(*seen) != 0 {
		t.Errorf("origin saw %d requests; want none", len(*seen))
	}
}

// TestRoundTrip_RejectsNonEd25519KeyMaterial pins that a KeySource returning
// something that is not an Ed25519 private key fails the request rather than
// panicking inside the signer.
func TestRoundTrip_RejectsNonEd25519KeyMaterial(t *testing.T) {
	srv, seen := captureServer(t)
	src := WithKeySource(func(context.Context) (AgentKey, error) {
		return AgentKey{Directory: "https://alice.rampmcp.org", Private: []byte("too short")}, nil
	})

	transport, err := New(nil, "", nil, ClockWindow(clock.System{}, 30*time.Second), src, WithWBASigning())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	err = sendExpectingFailure(t, transport, srv.URL+wbaTarget)

	if !errors.Is(err, ErrUnusableKey) {
		t.Fatalf("err = %v, want ErrUnusableKey", err)
	}
	if len(*seen) != 0 {
		t.Errorf("server received %d requests; want none", len(*seen))
	}
}
