package httpsig

// The Signature-Agent directory as the VERIFIER hands it on. This stack's
// consumer of that value is a key resolver: it fetches the named WBA directory
// and matches the keyid thumbprint against what it publishes. So the value that
// reaches the resolver's context is the one that decides whether the request
// authenticates at all — a directory URI the resolver cannot parse a host out of
// is a 401, not a storage-format wart.
//
// Web Bot Auth defines the header value as an RFC 8941 String, which is QUOTED;
// quoting is not optional in structured fields. Reading the header verbatim
// carried those quotes into the directory URI, so a conformant signer was
// unresolvable while RAMP's own bare emission worked. Both forms must reach the
// resolver as the same bare origin, and the wire bytes must be left alone either
// way, because the signature base covers what the signer actually sent.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// recordingResolver serves one key and records the Signature-Agent directory the
// verifier threaded into its context — observed at the point a real discovery
// resolver would turn that value into a fetch.
type recordingResolver struct {
	pub  ed25519.PublicKey
	seen string
	// calls guards against a vacuous pass: an assertion on seen means nothing if
	// Resolve was never reached.
	calls int
}

func (r *recordingResolver) Resolve(ctx context.Context, _ string) (ed25519.PublicKey, error) {
	r.calls++
	r.seen = SignatureAgentFromContext(ctx)
	return r.pub, nil
}

// TestVerifyRequest_SignatureAgentReachesResolverUnquoted pins the directory the
// resolver is given, for both wire forms. Verification passing is half the
// assertion: the signature base is built from the header's raw bytes, so the
// quoted value must be signed and verified WITH its quotes while the value handed
// to the resolver has them stripped. If those two treatments ever collapsed into
// one, one of these subtests would fail.
func TestVerifyRequest_SignatureAgentReachesResolverUnquoted(t *testing.T) {
	const wantDirectory = "https://agent.example"
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"quoted sf-string (Web Bot Auth conformant)", `"` + wantDirectory + `"`},
		{"bare token (RAMP's own emission)", wantDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("gen: %v", err)
			}
			now := signNow()
			body := []byte(`{"query":"foo"}`)
			req := newRAMPSignedRequestMutated(t, body, priv, now.Add(30*time.Second).Unix(),
				func(r *http.Request) { r.Header.Set(SignatureAgentHeader, tc.header) })

			resolver := &recordingResolver{pub: pub}
			v, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
			if err != nil {
				t.Fatalf("verify with Signature-Agent %s: %v", tc.header, err)
			}
			if resolver.calls != 1 {
				t.Fatalf("resolver called %d times; the directory assertion below is vacuous otherwise", resolver.calls)
			}
			if resolver.seen != wantDirectory {
				t.Errorf("resolver context directory = %q; want %q — a resolver cannot fetch a "+
					"directory whose URI still carries its structured-field quotes",
					resolver.seen, wantDirectory)
			}
			if v.SignatureAgent != wantDirectory {
				t.Errorf("VerifiedRequest.SignatureAgent = %q; want %q", v.SignatureAgent, wantDirectory)
			}
			// The wire bytes are untouched: a relay forwards this header verbatim, so
			// the signer's signature must still verify at the next hop.
			if got := req.Header.Get(SignatureAgentHeader); got != tc.header {
				t.Errorf("header mutated to %q; want %q left on the wire", got, tc.header)
			}
		})
	}
}

// TestVerifyRequest_RepeatedSignatureAgentReachesResolverJoined covers the reason
// the verifier reads the REQUEST rather than one header line. A field repeated
// across two lines contributes BOTH values to the RFC 9421 signature base, joined
// by ", ", so the signature commits to both. Reading only the first would hand the
// resolver one directory while the signature covered two — an attacker's value
// appended after a victim's would then be signed-for but invisible to the code
// that decides which directory to trust.
//
// What the resolver receives here is the joined pair, which no structured-field
// parser accepts as a single Item and which names no host: the ambiguity surfaces
// rather than being silently resolved in the first value's favour.
func TestVerifyRequest_RepeatedSignatureAgentReachesResolverJoined(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	now := signNow()
	body := []byte(`{"query":"foo"}`)
	req := newRAMPSignedRequestMutated(t, body, priv, now.Add(30*time.Second).Unix(),
		func(r *http.Request) {
			r.Header.Add(SignatureAgentHeader, `"https://victim.example"`)
			r.Header.Add(SignatureAgentHeader, `"https://attacker.example"`)
		})

	resolver := &recordingResolver{pub: pub}
	if _, err := VerifyRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver called %d times", resolver.calls)
	}
	const wantJoined = `"https://victim.example", "https://attacker.example"`
	if resolver.seen != wantJoined {
		t.Errorf("resolver context directory = %q; want the joined pair %q — reading only the "+
			"first field line derives a directory the signature did not solely commit to",
			resolver.seen, wantJoined)
	}
}
