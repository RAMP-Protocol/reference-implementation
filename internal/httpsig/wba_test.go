package httpsig

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yaronf/httpsign"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

const testDirectory = "https://alice.rampmcp.org"

// wbaKey returns the deterministic key the WBA suite signs with, plus its RFC
// 7638 thumbprint — the keyid the draft requires.
func wbaKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	priv := fixedKey(0x42)
	keyID, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return priv, keyID
}

// newWBARequest builds an outbound request to a WBA-aware origin. A nil body
// yields the ordinary case: a bodyless GET.
func newWBARequest(t *testing.T, method, url string, body []byte) *http.Request {
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

// signWBA signs req with the suite key and returns the public half for verifying.
func signWBA(t *testing.T, req *http.Request, body []byte, expires time.Time) ed25519.PublicKey {
	t.Helper()
	priv, keyID := wbaKey(t)
	opts := WBAOptions{Directory: testDirectory, KeyID: keyID, Expires: expires.Unix()}
	if err := SignRequestWBA(req, body, priv, opts); err != nil {
		t.Fatalf("sign WBA: %v", err)
	}
	return priv.Public().(ed25519.PublicKey)
}

// independentVerify checks the signature WITHOUT going through yaronf: it
// rebuilds the RFC 9421 signature base from the request as received — one
// `"<component>": <value>` line per covered component, then `"@signature-params"`
// carrying the Signature-Input inner list VERBATIM off the wire — and runs a raw
// ed25519.Verify. That is exactly what an origin implementing the spec from the
// text would do, so it catches a canonicalization the signing library and our
// wrapper agree on but the spec does not.
func independentVerify(t *testing.T, req *http.Request, pub ed25519.PublicKey) bool {
	t.Helper()
	allParams, sigMap, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parse signatures: %v", err)
	}
	params := allParams[0]

	var base strings.Builder
	for _, c := range params.Covered {
		base.WriteString(`"` + strings.ToLower(c.Name) + `": ` + componentValueForTest(req, c.Name) + "\n")
	}
	// The inner list as sent, so the parameter serialization under test is the
	// one the verifier sees rather than one this test re-derives.
	inner := strings.TrimPrefix(req.Header.Get("Signature-Input"), params.Label+"=")
	base.WriteString(`"@signature-params": ` + inner)

	return ed25519.Verify(pub, []byte(base.String()), sigMap[params.Label])
}

// componentValueForTest resolves one covered component against the request the
// way RFC 9421 §2 does, for the derived components these suites sign. Anything
// else is an ordinary header field.
func componentValueForTest(req *http.Request, name string) string {
	switch strings.ToLower(name) {
	case "@authority":
		return req.Host
	case "@method":
		return req.Method
	case "@path":
		return req.URL.EscapedPath()
	default:
		return req.Header.Get(name)
	}
}

// yaronfVerify checks the signature through the library's own verifier, held to
// the WBA tag — a second, independent-of-our-wrapper opinion on the same bytes.
func yaronfVerify(t *testing.T, req *http.Request, pub ed25519.PublicKey) error {
	t.Helper()
	cfg := httpsign.NewVerifyConfig().
		SetVerifyCreated(false).
		SetAllowedTags([]string{WBATag})
	verifier, err := httpsign.NewEd25519Verifier(pub, cfg, httpsign.Headers("@authority", "signature-agent"))
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	return httpsign.VerifyRequest("sig1", *verifier, req)
}

// TestSignRequestWBA_VerifiesUnderIndependentVerifier is the ticket's acceptance
// case: a request signed with the Web Bot Auth profile verifies under a verifier
// that shares no code with the signer.
func TestSignRequestWBA_VerifiesUnderIndependentVerifier(t *testing.T) {
	t.Parallel()
	req := newWBARequest(t, http.MethodGet, "https://origin.example/article", nil)
	pub := signWBA(t, req, nil, time.Now().Add(5*time.Minute))

	if !independentVerify(t, req, pub) {
		t.Fatal("hand-built RFC 9421 base did not verify")
	}
	if err := yaronfVerify(t, req, pub); err != nil {
		t.Fatalf("library verify: %v", err)
	}
}

// TestSignRequestWBA_BodiedRequestBindsTheBody covers the RAMP addition to the
// draft's minimum set: a request that carries a body also covers content-digest,
// so the body cannot be swapped under the signature.
func TestSignRequestWBA_BodiedRequestBindsTheBody(t *testing.T) {
	t.Parallel()
	body := []byte(`{"query":"foo"}`)
	req := newWBARequest(t, http.MethodPost, "https://origin.example/api", body)
	pub := signWBA(t, req, body, time.Now().Add(5*time.Minute))

	if got := req.Header.Get("Content-Digest"); got == "" {
		t.Fatal("bodied WBA request emitted no Content-Digest")
	}
	if !independentVerify(t, req, pub) {
		t.Fatal("bodied WBA signature did not verify")
	}
	params, err := ParseSignatureLabels(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !coversComponent(params[0].Covered, "content-digest") {
		t.Errorf("covered set %v omits content-digest", coveredNames(params[0].Covered))
	}
}

// TestSignRequestWBA_EmitsDraftRequiredParameters pins what the Web Bot Auth
// architecture draft mandates on the wire: the covered set is exactly
// ("@authority" "signature-agent") for a bodyless request, the keyid is the RFC
// 7638 thumbprint, and created/expires/alg/nonce/tag are all present with
// tag="web-bot-auth". An origin MAY discard a signature whose tag differs, so a
// missing tag is a silently-unauthenticated agent.
func TestSignRequestWBA_EmitsDraftRequiredParameters(t *testing.T) {
	t.Parallel()
	_, keyID := wbaKey(t)
	req := newWBARequest(t, http.MethodGet, "https://origin.example/article", nil)
	expires := time.Now().Add(5 * time.Minute)
	signWBA(t, req, nil, expires)

	params, err := ParseSignatureLabels(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := params[0]

	if got, want := coveredNames(p.Covered), []string{"@authority", "signature-agent"}; !equalStrings(got, want) {
		t.Errorf("covered = %v, want %v", got, want)
	}
	if p.KeyID != keyID {
		t.Errorf("keyid = %q, want the RFC 7638 thumbprint %q", p.KeyID, keyID)
	}
	if p.Alg != "ed25519" {
		t.Errorf("alg = %q, want ed25519", p.Alg)
	}
	if p.Tag != WBATag {
		t.Errorf("tag = %q, want %q", p.Tag, WBATag)
	}
	if p.Nonce == "" {
		t.Error("nonce absent; the draft's replay guard is not on the wire")
	}
	if p.Created == 0 {
		t.Error("created absent")
	}
	if p.Expires != expires.Unix() {
		t.Errorf("expires = %d, want %d", p.Expires, expires.Unix())
	}
	// The draft defines Signature-Agent as a structured-field String, so the
	// origin canonicalizes it WITH its quotes. Sending it bare (the RAMP profile's
	// form) would verify nowhere off-network.
	if got, want := req.Header.Get(SignatureAgentHeader), `"`+testDirectory+`"`; got != want {
		t.Errorf("Signature-Agent = %s, want %s (quoted sf-string)", got, want)
	}
}

// TestSignRequestWBA_TamperedRequestFails drives each way a relay could rewrite a
// signed request and asserts the signature stops verifying. A signature that
// survives any of these is one an attacker can reuse.
func TestSignRequestWBA_TamperedRequestFails(t *testing.T) {
	t.Parallel()
	body := []byte(`{"query":"foo"}`)
	cases := map[string]func(*http.Request){
		"authority repointed": func(r *http.Request) { r.Host = "evil.example" },
		"signature-agent repointed": func(r *http.Request) {
			r.Header.Set(SignatureAgentHeader, `"https://evil.example"`)
		},
		"body swapped":      func(r *http.Request) { r.Header.Set("Content-Digest", "sha-256=:AAAA:") },
		"signature mangled": func(r *http.Request) { r.Header.Set("Signature", mangleSignature(r.Header.Get("Signature"))) },
		"expires stretched": func(r *http.Request) {
			r.Header.Set("Signature-Input", stretchExpires(r.Header.Get("Signature-Input")))
		},
		"covered set shrunk": func(r *http.Request) {
			r.Header.Set("Signature-Input", dropSignatureAgent(r.Header.Get("Signature-Input")))
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			req := newWBARequest(t, http.MethodPost, "https://origin.example/api", body)
			pub := signWBA(t, req, body, time.Now().Add(5*time.Minute))
			if !independentVerify(t, req, pub) {
				t.Fatal("precondition: untampered signature must verify")
			}

			tamper(req)

			if independentVerify(t, req, pub) {
				t.Error("tampered request still verified")
			}
			if err := yaronfVerify(t, req, pub); err == nil {
				t.Error("tampered request accepted by the library verifier")
			}
		})
	}
}

// TestSignRequestWBA_ExpiredSignatureRejected pins that the expires cutoff is
// live: an origin holding the signature past its window rejects it.
func TestSignRequestWBA_ExpiredSignatureRejected(t *testing.T) {
	t.Parallel()
	req := newWBARequest(t, http.MethodGet, "https://origin.example/article", nil)
	pub := signWBA(t, req, nil, time.Now().Add(-1*time.Minute))

	// The bytes are intact — a raw verify still passes — but a verifier enforcing
	// the window must refuse it.
	if !independentVerify(t, req, pub) {
		t.Fatal("precondition: signature bytes must be intact")
	}
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false).SetRejectExpired(true)
	verifier, err := httpsign.NewEd25519Verifier(pub, cfg, httpsign.Headers())
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	if err := httpsign.VerifyRequest("sig1", *verifier, req); err == nil {
		t.Error("expired signature accepted")
	}
}

// TestSignRequestWBA_NonceIsFreshPerSignature pins the replay guard: two
// signatures over the same request carry different nonces, so an origin tracking
// seen nonces can tell a retry from a replay.
func TestSignRequestWBA_NonceIsFreshPerSignature(t *testing.T) {
	t.Parallel()
	nonces := make([]string, 2)
	for i := range nonces {
		req := newWBARequest(t, http.MethodGet, "https://origin.example/article", nil)
		signWBA(t, req, nil, time.Now().Add(5*time.Minute))
		params, err := ParseSignatureLabels(req.Header)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		nonces[i] = params[0].Nonce
	}
	if nonces[0] == nonces[1] {
		t.Errorf("nonce reused across signatures: %q", nonces[0])
	}
}

// TestSignRequestWBA_RequiresTheDraftsMandatoryOptions pins the refusals. Each of
// directory, keyid, and expires is required by the Web Bot Auth draft, and a
// signature missing any one is unverifiable or unexpiring at the origin — worse
// than no signature, because it presents the agent as authenticated while being
// unusable. Asserting the sentinels rather than the message text is what lets a
// caller branch on which one it tripped.
func TestSignRequestWBA_RequiresTheDraftsMandatoryOptions(t *testing.T) {
	t.Parallel()
	_, keyID := wbaKey(t)
	live := time.Now().Add(time.Minute).Unix()
	cases := map[string]struct {
		opts WBAOptions
		want error
	}{
		"no directory": {WBAOptions{KeyID: keyID, Expires: live}, ErrMissingDirectory},
		"no keyid":     {WBAOptions{Directory: testDirectory, Expires: live}, ErrMissingKeyID},
		"no expires":   {WBAOptions{Directory: testDirectory, KeyID: keyID}, ErrMissingExpires},
		"past expires": {WBAOptions{Directory: testDirectory, KeyID: keyID, Expires: -1}, ErrMissingExpires},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			priv, _ := wbaKey(t)
			req := newWBARequest(t, http.MethodGet, "https://origin.example/article", nil)

			err := SignRequestWBA(req, nil, priv, tc.opts)

			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if req.Header.Get("Signature") != "" {
				t.Error("refused signing still wrote a Signature header")
			}
		})
	}
}

// coveredNames lists the covered-component names, lowercased, in wire order.
func coveredNames(covered []CoveredComponent) []string {
	names := make([]string, 0, len(covered))
	for _, c := range covered {
		names = append(names, strings.ToLower(c.Name))
	}
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// mangleSignature flips a byte inside the base64 signature value, leaving the
// structured-field wrapper intact so the tamper is a bad signature rather than a
// parse failure.
func mangleSignature(header string) string {
	i := strings.Index(header, ":")
	if i < 0 || i+2 >= len(header) {
		return header
	}
	swap := byte('A')
	if header[i+1] == 'A' {
		swap = 'B'
	}
	return header[:i+1] + string(swap) + header[i+2:]
}

// stretchExpires pushes the expires parameter an hour out, the rewrite a relay
// would attempt to keep a captured signature usable.
func stretchExpires(input string) string {
	i := strings.Index(input, ";expires=")
	if i < 0 {
		return input
	}
	rest := input[i+len(";expires="):]
	end := strings.IndexAny(rest, ";")
	if end < 0 {
		end = len(rest)
	}
	return input[:i] + ";expires=99999999999" + rest[end:]
}

// dropSignatureAgent removes signature-agent from the covered set, the rewrite
// that would let a relay repoint key discovery.
func dropSignatureAgent(input string) string {
	return strings.Replace(input, ` "signature-agent"`, "", 1)
}
