package testutil

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

// EdgeDouble is a publisher edge that ENFORCES delivery-URL binding (ADR-013
// D1-D3), for tests of the fetching side.
//
// It runs the real check rather than looking for the headers: it rebuilds the
// RFC 9421 signature base from the request as received, verifies the Ed25519
// signature against the presented key, and enforces the three-way identity
// agent_id == keyid == thumbprint(presented key). A double that only checked the
// headers were present would pass against a signer emitting the wrong bytes,
// which is the one failure a fetcher test has to catch — at the real edge it
// surfaces as an undifferentiated 403.
//
// The verify side is written out here rather than calling the signer's own
// helpers beyond the shared signature base. Two implementations that agree only
// because they share code prove nothing about interoperability, and the party
// this must interoperate with is the SDK's TypeScript verifier.
//
// That verifier — sdk/ts/src/pop.ts in github.com/RAMP-Protocol/protocol — is the
// behaviour this double tracks, and nothing pins the two together the way the
// shared vectors pin the signer. Where they knowingly differ, the difference is
// commented at the site. Independence is the point, so the ORDER of the checks is
// deliberately not copied; only the accept/reject boundaries have to agree,
// because those are what a test asserts on.
//
// Nothing is bound at construction: like the real edge, the double reads the
// expected identity out of the URL's own agent_id parameter, so one double
// serves any number of agents.
type EdgeDouble struct {
	server *httptest.Server
	hits   atomic.Int32

	// now is fixed at construction, so verify and freshness read it without the
	// lock below.
	now int64

	mu  sync.RWMutex
	set settings
}

// settings is the double's programmable behaviour, held together so the handler
// goroutine can take it in one consistent read.
//
// The test goroutine writes these through the Set* methods and the httptest
// server's goroutine reads them, with no happens-before edge between the two.
// Guarding them matches the sibling double in the MCP suite, which reads its
// programmable responses under its own mutex for the same reason.
type settings struct {
	body          []byte
	contentType   string
	refusalStatus int
	refusalBody   string
	handler       http.HandlerFunc
}

// popParams re-parses the parameters the agent-binding profile emits. The
// covered set is fixed at exactly @method and @target-uri, so an anchored
// pattern is also the covered-component check.
var popParams = regexp.MustCompile(
	`^sig1=\("@method" "@target-uri"\);keyid="([^"]+)";alg="([^"]+)";created=(\d+);expires=(\d+)$`,
)

// NewEdgeDouble starts an enforcing edge and registers its shutdown.
func NewEdgeDouble(tb testing.TB, now int64) *EdgeDouble {
	tb.Helper()
	e := &EdgeDouble{
		now: now,
		set: settings{
			body:        []byte("<html>licensed</html>"),
			contentType: "text/html; charset=utf-8",
		},
	}
	e.server = httptest.NewServer(http.HandlerFunc(e.serve))
	tb.Cleanup(e.server.Close)
	return e
}

// Origin is the double's scheme and authority.
func (e *EdgeDouble) Origin() string { return e.server.URL }

// Now is the instant the double verifies freshness against, so a test can build a
// signing window that lands on a chosen side of the expiry boundary without
// having to thread the same value through two constructors.
func (e *EdgeDouble) Now() int64 { return e.now }

// URLFor mints a delivery URL bound to agentID, shaped like one the Exchange
// signs: the reserved parameters plus agent_id, which is what the binding check
// reads.
func (e *EdgeDouble) URLFor(agentID string) string {
	return e.server.URL + "/article?exp=4102444800&kid=exchange&agent_id=" + url.QueryEscape(agentID)
}

// Hits counts requests that reached the handler, so a test can assert a redirect
// was NOT followed.
func (e *EdgeDouble) Hits() int32 { return e.hits.Load() }

// Close stops the double while leaving its URL valid to mint from, so a test can
// drive the dial-failure path against an address that is genuinely refusing
// rather than a hostname that resolves nowhere. Safe to call again — the
// constructor's cleanup does too.
func (e *EdgeDouble) Close() { e.server.Close() }

// SetBody sets what a passing fetch receives.
func (e *EdgeDouble) SetBody(body []byte, contentType string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.set.body, e.set.contentType = body, contentType
}

// SetRefusal makes every request fail with this status and body, without running
// the binding check.
func (e *EdgeDouble) SetRefusal(status int, body string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.set.refusalStatus, e.set.refusalBody = status, body
}

// SetHandler replaces the whole behaviour, for cases the knobs do not cover.
func (e *EdgeDouble) SetHandler(fn http.HandlerFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.set.handler = fn
}

// snapshot takes the programmable behaviour in one read and RETURNS it rather
// than leaving the lock held. serve goes on to run a caller-supplied handler and
// write a response, and some tests install handlers that block until cleanup —
// holding the mutex across that would serialise or deadlock the double.
func (e *EdgeDouble) snapshot() settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.set
}

func (e *EdgeDouble) serve(w http.ResponseWriter, r *http.Request) {
	e.hits.Add(1)
	set := e.snapshot()
	if set.handler != nil {
		set.handler(w, r)
		return
	}
	if set.refusalStatus != 0 {
		w.WriteHeader(set.refusalStatus)
		_, _ = w.Write([]byte(set.refusalBody))
		return
	}
	if reason := e.verify(r); reason != "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprintf(w, `{"error":"Agent binding check failed","reason":%q}`, reason)
		return
	}
	w.Header().Set("Content-Type", set.contentType)
	_, _ = w.Write(set.body)
}

// verify returns the edge's own refusal token, or "" when the proof holds. The
// tokens match the production vocabulary so a test can assert on the exact
// string an agent would see.
func (e *EdgeDouble) verify(r *http.Request) string {
	pub, reason := presentedKey(r)
	if reason != "" {
		return reason
	}
	sigInput := r.Header.Get("Signature-Input")
	m := popParams.FindStringSubmatch(sigInput)
	if m == nil {
		return "bad_covered_components"
	}
	if m[2] != "ed25519" {
		return "unsupported_alg"
	}
	if reason = e.freshness(m[3], m[4]); reason != "" {
		return reason
	}
	if reason = identityAgrees(r, m[1], pub); reason != "" {
		return reason
	}
	sig, reason := presentedSignature(r)
	if reason != "" {
		return reason
	}
	// The base is rebuilt from the request AS RECEIVED — the raw request line,
	// never a re-parsed URL — which is what makes this a real interop check.
	base := httpsig.PoPSignatureBase(r.Method, "http://"+r.Host+r.RequestURI, strings.TrimPrefix(sigInput, "sig1="))
	if !ed25519.Verify(pub, []byte(base), sig) {
		return "pop_sig_invalid"
	}
	return ""
}

// presentedKey decodes the key the fetcher offered.
func presentedKey(r *http.Request) (ed25519.PublicKey, string) {
	raw := r.Header.Get(httpsig.AgentKeyHeader)
	if raw == "" {
		return nil, "missing_agent_key"
	}
	pub, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, "bad_agent_key"
	}
	return pub, ""
}

// presentedSignature decodes the RFC 8941 byte string, which is STANDARD base64
// even though the presented key beside it is base64url.
func presentedSignature(r *http.Request) ([]byte, string) {
	raw, ok := strings.CutPrefix(r.Header.Get("Signature"), "sig1=:")
	if !ok || !strings.HasSuffix(raw, ":") {
		return nil, "missing_sig"
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(raw, ":"))
	if err != nil {
		return nil, "missing_sig"
	}
	return sig, ""
}

// identityAgrees enforces the three-way identity: the agent_id the Exchange
// signed into the URL, the keyid on the signature, and the thumbprint of the key
// actually presented must all be one value. Verifying the signature without this
// would let any actor present their own key plus a valid self-signature.
func identityAgrees(r *http.Request, keyid string, pub ed25519.PublicKey) string {
	agentID := r.URL.Query().Get("agent_id")
	if keyid != agentID {
		return "keyid_mismatch"
	}
	thumbprint, err := helpers.Thumbprint(pub)
	if err != nil || thumbprint != agentID {
		return "thumbprint_mismatch"
	}
	return ""
}

// freshness applies the window the production edge applies: created may lead the
// verifier by at most 300s, and expires may not already have passed.
//
// The expiry comparison is INCLUSIVE — a proof whose expires lands exactly on the
// verifier's current second is stale, matching the SDK verifier's `now >= expires`
// (sdk/ts/src/pop.ts). Refusing only strictly-past proofs would make this double
// lenient where production refuses, which is the direction that lets a bad signing
// window pass every Go test and 403 at the real edge.
func (e *EdgeDouble) freshness(createdRaw, expiresRaw string) string {
	created, err := strconv.ParseInt(createdRaw, 10, 64)
	if err != nil {
		return "pop_missing_created"
	}
	expires, err := strconv.ParseInt(expiresRaw, 10, 64)
	if err != nil {
		return "pop_missing_exp"
	}
	if created > e.now+300 {
		return "pop_future_created"
	}
	if expires <= e.now {
		return "pop_expired"
	}
	return ""
}
