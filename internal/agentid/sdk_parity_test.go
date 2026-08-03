package agentid_test

// SDK reader parity. DirectoryFromHeader is a reimplementation of the protocol
// SDK's own Signature-Agent reader, which the SDK does not export, and the package
// doc states why the two must agree: this repo verifies signatures through BOTH
// stacks — the SDK's connectserver gate for the Connect services, internal/httpsig
// for the identity delivery path — so a header the two read differently is one that
// authorizes differently depending on which door the request came through.
//
// That is an authentication-boundary invariant across a module boundary a
// dependency bump can move, so it needs a gate rather than a comment. The tests in
// agentid_test.go pin this repo's reader against literals; nothing there would
// notice the SDK's reader changing underneath it.
//
// The SDK's reader is reached the only way it can be reached from outside its
// package: through the exported verify surface, which threads the value it read
// both into the resolver's context and onto the VerifiedRequest. Both are asserted,
// because they are the two places a caller consumes it.
//
// When this fails after an SDK bump, the fix is to make DirectoryFromHeader match
// the SDK again — the SDK owns the wire format. It is not to relax this test.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
)

// The signature window is fixed so the test does not depend on wall-clock time.
const (
	parityCreated = 1700000000
	parityExpires = 1700000300
)

var parityNow = time.Unix(1700000100, 0) // inside [created, expires]

// recordingResolver serves one key and records the Signature-Agent directory the
// SDK threaded into its context — which is the SDK's reader output, observed at
// the point a real resolver would fetch the directory from it.
type recordingResolver struct {
	pub  ed25519.PublicKey
	seen string
}

func (r *recordingResolver) Resolve(ctx context.Context, _ string) (ed25519.PublicKey, error) {
	r.seen = helpers.SignatureAgentFromContext(ctx)
	return r.pub, nil
}

// signedParityRequest signs a request carrying the given raw Signature-Agent
// header lines and returns it with a resolver bound to the signing key. The header
// is set BEFORE signing, so the signature covers exactly the bytes under test —
// helpers.SignRequest only fills the header in when it is absent, and never
// rewrites a value already present.
func signedParityRequest(t *testing.T, body []byte, headerLines []string) (*http.Request, *recordingResolver) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer("thumbprint.v1", priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/Execute", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range headerLines {
		req.Header.Add(agentid.SignatureAgentHeader, line)
	}
	if err := helpers.SignRequest(context.Background(), req, body, signer,
		helpers.SignOptions{Created: parityCreated, Expires: parityExpires}); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	return req, &recordingResolver{pub: pub}
}

// TestDirectoryFromRequest_matchesSDKReader is the gate. Every form below is read
// by both stacks and the two results must be the same string — including the forms
// neither stack supports, because "both refuse it identically" is as much a parity
// property as "both accept it identically". A form one stack unwrapped and the
// other passed through verbatim would be a request that resolves a directory
// through one door and not the other.
func TestDirectoryFromRequest_matchesSDKReader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"quoted sf-string (conformant)", `"https://agent.example"`},
		{"bare token (RAMP's own)", "https://agent.example"},
		{"quoted bare host", `"agent.example"`},
		{"bare host:port", "identity:8080"},
		{"quoted host:port", `"identity:8080"`},
		{"quoted with default port", `"https://agent.example:443"`},
		{"surrounding whitespace", `  "https://agent.example"  `},
		{"sf-dictionary (supported by neither)", `agent2="https://agent.example"`},
		{"inline data: directory (supported by neither)", `data:application/http-message-signatures-directory;utf8,{"keys":[]}`},
		{"non-ASCII host no structured-field parser types", "bücher.example"},
		{"empty value", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"resource_id":"r1"}`)
			req, resolver := signedParityRequest(t, body, []string{tc.header})

			verified, err := helpers.VerifyRequestResolved(
				context.Background(), req, body, resolver, helpers.VerifyOptions{Now: parityNow},
			)
			if err != nil {
				t.Fatalf("VerifyRequestResolved with Signature-Agent %q: %v", tc.header, err)
			}

			ours := agentid.DirectoryFromRequest(req.Header)
			if verified.SignatureAgent != ours {
				t.Errorf("readers diverge on %q: SDK -> %q, agentid -> %q\n"+
					"a header the two stacks read differently authorizes differently "+
					"depending on which door the request came through",
					tc.header, verified.SignatureAgent, ours)
			}
			if resolver.seen != ours {
				t.Errorf("resolver context on %q: SDK -> %q, agentid -> %q — "+
					"the two stacks would fetch different directories",
					tc.header, resolver.seen, ours)
			}
		})
	}
}

// TestDirectoryFromRequest_matchesSDKReaderOnRepeatedHeader is the case that
// motivated reading the REQUEST rather than one header line. A field repeated
// across two lines contributes BOTH values to the RFC 9421 signature base, joined
// by ", ", so the signature commits to both. Reading only the first line would
// derive an identity from one value while the signature covered two — and the SDK
// does not read only the first line, so this stack must not either.
//
// The assertion is parity, not a particular string: what both readers produce is a
// value no structured-field parser accepts as a single Item, which FromDirectory
// then refuses. That refusal is checked here too, since parity on a value that
// later became an identity would be parity on the wrong thing.
func TestDirectoryFromRequest_matchesSDKReaderOnRepeatedHeader(t *testing.T) {
	body := []byte(`{"resource_id":"r2"}`)
	req, resolver := signedParityRequest(t, body, []string{
		`"https://victim.example"`,
		`"https://attacker.example"`,
	})

	verified, err := helpers.VerifyRequestResolved(
		context.Background(), req, body, resolver, helpers.VerifyOptions{Now: parityNow},
	)
	if err != nil {
		t.Fatalf("VerifyRequestResolved on a repeated Signature-Agent: %v", err)
	}

	ours := agentid.DirectoryFromRequest(req.Header)
	if verified.SignatureAgent != ours {
		t.Errorf("readers diverge on a repeated header: SDK -> %q, agentid -> %q",
			verified.SignatureAgent, ours)
	}
	if resolver.seen != ours {
		t.Errorf("resolver context on a repeated header: SDK -> %q, agentid -> %q",
			resolver.seen, ours)
	}
	if id, err := agentid.FromDirectory(ours); err == nil {
		t.Errorf("a repeated Signature-Agent resolved to identity %q; want refusal — "+
			"the signature committed to both values", id)
	}
}
