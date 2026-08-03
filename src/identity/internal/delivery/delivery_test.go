package delivery

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// edgeNow is the verifier clock the doubles here run on.
func edgeNow() int64 { return time.Now().Unix() }

// newEdge starts an enforcing edge double. The double is shared with the MCP
// adapter's tests (internal/testutil), so both sides of the fetch are proved
// against one implementation of the verify face rather than two that could
// drift.
func newEdge(t *testing.T) *testutil.EdgeDouble {
	t.Helper()
	return testutil.NewEdgeDouble(t, edgeNow())
}

// custody returns a KeySource over a fresh key, plus that key's thumbprint.
func custody(t *testing.T) (ramphttpsig.KeySource, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	thumbprint, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return func(context.Context) (ramphttpsig.AgentKey, error) {
		return ramphttpsig.AgentKey{Directory: "https://agent.example", KeyID: thumbprint, Private: priv}, nil
	}, thumbprint
}

func newFetcher(t *testing.T, keys ramphttpsig.KeySource, mut func(*Config)) *Fetcher {
	t.Helper()
	// http.DefaultTransport, not the guarded default: the double is on loopback,
	// which the SSRF guard exists to block. Only the transport is injected, so
	// the redirect policy under test is still production's.
	cfg := Config{Keys: keys, Transport: http.DefaultTransport}
	if mut != nil {
		mut(&cfg)
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatalf("new fetcher: %v", err)
	}
	return f
}

// deliveryError unwraps to *Error and checks the classification, returning it so
// a caller can go on to inspect the status or the edge's own reason.
func deliveryError(t *testing.T, err error, want Kind) *Error {
	t.Helper()
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("want *delivery.Error, got %T: %v", err, err)
	}
	if de.Kind != want {
		t.Fatalf("want kind %v, got %v (%v)", want, de.Kind, de)
	}
	return de
}

// assertKind is deliveryError for callers that only care about the class.
func assertKind(t *testing.T, err error, want Kind) {
	t.Helper()
	if de := deliveryError(t, err, want); de == nil {
		t.Fatal("classified error is nil")
	}
}

// TestFetchPresentsTheBoundKey is the load-bearing case: the double accepts the
// proof only if the signer produced the exact bytes the edge reconstructs, and
// only if the key presented is the one the URL names.
func TestFetchPresentsTheBoundKey(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)

	got, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(got.Body) != "<html>licensed</html>" {
		t.Errorf("body: got %q, want the served document", got.Body)
	}
	if got.MIMEType != "text/html" {
		t.Errorf("mime: got %q, want text/html (parameters stripped)", got.MIMEType)
	}
	if got.URL != edge.URLFor(thumbprint) {
		t.Errorf("url echo: got %q, want %q", got.URL, edge.URLFor(thumbprint))
	}
}

// TestFetchRefusedWhenKeyIsNotTheBoundOne proves the edge check is real: a
// perfectly-formed proof from the wrong key is refused, which is the property
// that makes a stolen URL useless to another agent.
func TestFetchRefusedWhenKeyIsNotTheBoundOne(t *testing.T) {
	t.Parallel()
	_, boundThumbprint := custody(t)
	otherKeys, _ := custody(t)
	edge := newEdge(t)

	_, err := newFetcher(t, otherKeys, nil).Fetch(context.Background(), edge.URLFor(boundThumbprint))
	de := deliveryError(t, err, KindRefused)
	if de.Status != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", de.Status)
	}
	if de.Reason != "keyid_mismatch" {
		t.Errorf("reason: got %q, want keyid_mismatch", de.Reason)
	}
}

func TestFetchRefusalCarriesTheEdgeReason(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	edge.SetRefusal(http.StatusForbidden, `{"error":"Agent binding check failed","reason":"pop_sig_invalid"}`)

	_, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
	de := deliveryError(t, err, KindRefused)
	if de.Reason != "pop_sig_invalid" {
		t.Errorf("reason: got %q, want pop_sig_invalid", de.Reason)
	}
	if de.ReasonOf() != "pop_sig_invalid" {
		t.Errorf("ReasonOf: got %q", de.ReasonOf())
	}
}

func TestFetchRefusalWithoutAParseableBody(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	edge.SetRefusal(http.StatusInternalServerError, "<html>five hundred</html>")

	_, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
	de := deliveryError(t, err, KindRefused)
	if de.Status != http.StatusInternalServerError {
		t.Errorf("status: got %d, want 500", de.Status)
	}
	if de.Reason != "" {
		t.Errorf("reason: got %q, want empty for an uninterpretable body", de.Reason)
	}
	// The class is still reportable to an agent even with no token from the edge.
	if de.ReasonOf() != "refused" {
		t.Errorf("ReasonOf: got %q, want refused", de.ReasonOf())
	}
}

func TestFetchTimesOut(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	edge.SetHandler(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})

	f := newFetcher(t, keys, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	_, err := f.Fetch(context.Background(), edge.URLFor(thumbprint))
	assertKind(t, err, KindUnreachable)
}

// TestFetchTimeoutCoversKeyResolution pins that the deadline bounds CUSTODY, not
// just the round trip. Resolving the key is a call to the custody backend, and
// while it sat outside the timeout a degraded backend held the tool call for
// whatever that backend's own client allowed — once per item in a batch.
//
// The classification stays NotSignable rather than becoming Unreachable: nothing
// left the process, which is the promise that kind makes.
func TestFetchTimeoutCoversKeyResolution(t *testing.T) {
	t.Parallel()
	edge := newEdge(t)
	hang := func(ctx context.Context) (ramphttpsig.AgentKey, error) {
		<-ctx.Done()
		return ramphttpsig.AgentKey{}, ctx.Err()
	}

	f := newFetcher(t, hang, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	_, err := f.Fetch(context.Background(), edge.URLFor("any-agent"))

	assertKind(t, err, KindNotSignable)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("want the deadline as the cause, got %v", err)
	}
	if hits := edge.Hits(); hits != 0 {
		t.Errorf("edge saw %d requests; nothing may leave when the key never resolved", hits)
	}
}

// TestFetchRefusesAnOversizedBody pins that an oversized body is DETECTED, not
// truncated. Truncated content that looks whole is worse than a refusal: the
// agent has paid for it and cannot tell it is incomplete.
func TestFetchRefusesAnOversizedBody(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	edge.SetBody([]byte(strings.Repeat("x", 1024)), "text/plain")

	f := newFetcher(t, keys, func(c *Config) { c.MaxBytes = 512 })
	_, err := f.Fetch(context.Background(), edge.URLFor(thumbprint))
	assertKind(t, err, KindTooLarge)
}

func TestFetchAcceptsABodyExactlyAtTheCap(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	edge.SetBody([]byte(strings.Repeat("x", 512)), "text/plain")

	f := newFetcher(t, keys, func(c *Config) { c.MaxBytes = 512 })
	got, err := f.Fetch(context.Background(), edge.URLFor(thumbprint))
	if err != nil {
		t.Fatalf("fetch at exactly the cap: %v", err)
	}
	if len(got.Body) != 512 {
		t.Errorf("body length: got %d, want 512", len(got.Body))
	}
}

// TestFetchRefusesRedirects also asserts the redirect target was never
// contacted: following it would hand a fresh proof of possession of the agent's
// key to whatever host the first hop named.
func TestFetchRefusesRedirects(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	target := newEdge(t)
	hop := newEdge(t)
	hop.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URLFor(thumbprint), http.StatusFound)
	})

	_, err := newFetcher(t, keys, nil).Fetch(context.Background(), hop.URLFor(thumbprint))
	assertKind(t, err, KindUnreachable)
	if got := target.Hits(); got != 0 {
		t.Errorf("redirect target was contacted %d times, want 0", got)
	}
}

// TestFetchWithoutCustodyMakesNoRequest is the important half of the custody
// failure: not merely that it errors, but that nothing leaves the process.
func TestFetchWithoutCustodyMakesNoRequest(t *testing.T) {
	t.Parallel()
	_, thumbprint := custody(t)
	edge := newEdge(t)
	sentinel := errors.New("vault is down")
	keys := func(context.Context) (ramphttpsig.AgentKey, error) {
		return ramphttpsig.AgentKey{}, sentinel
	}

	_, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
	assertKind(t, err, KindNotSignable)
	if !errors.Is(err, sentinel) {
		t.Errorf("custody cause is no longer matchable: %v", err)
	}
	if got := edge.Hits(); got != 0 {
		t.Errorf("edge was contacted %d times without a key, want 0", got)
	}
}

// TestFetchRefusesAMispairedKey covers custody handing back a keyid that is not
// the thumbprint of the key beside it. The edge would answer
// thumbprint_mismatch; refusing before the request names the real cause.
func TestFetchRefusesAMispairedKey(t *testing.T) {
	t.Parallel()
	_, thumbprint := custody(t)
	edge := newEdge(t)
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keys := func(context.Context) (ramphttpsig.AgentKey, error) {
		return ramphttpsig.AgentKey{KeyID: thumbprint, Private: priv}, nil
	}

	_, err = newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
	assertKind(t, err, KindNotSignable)
	if !errors.Is(err, httpsig.ErrKeyIDMismatch) {
		t.Errorf("want ErrKeyIDMismatch underneath, got %v", err)
	}
	if got := edge.Hits(); got != 0 {
		t.Errorf("edge was contacted %d times with a mispaired key, want 0", got)
	}
}

func TestFetchMIMEHandling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, served, want string
	}{
		{"parameters stripped", "text/html; charset=utf-8", "text/html"},
		{"bare type", "application/pdf", "application/pdf"},
		{"absent", "", defaultMIMEType},
		{"unparseable", "not/a/media/type;;;", defaultMIMEType},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keys, thumbprint := custody(t)
			edge := newEdge(t)
			edge.SetBody([]byte("body"), tc.served)

			got, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if got.MIMEType != tc.want {
				t.Errorf("mime: got %q, want %q", got.MIMEType, tc.want)
			}
		})
	}
}

// TestFetchDeliversAnEmptyBody pins that a 2xx with no bytes is content, not an
// error: the edge's no-origin-mode path answers exactly that by design.
func TestFetchDeliversAnEmptyBody(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	edge.SetBody(nil, "text/plain")

	got, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got.Body) != 0 {
		t.Errorf("body: got %d bytes, want 0", len(got.Body))
	}
}

func TestNewRequiresAKeySource(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{}); err == nil {
		t.Fatal("want an error when Keys is absent")
	}
}

// TestRedactURL pins that the credential really is gone. A redaction that
// silently passes the value through is worse than none, because every caller
// downstream then believes the value is safe to keep.
func TestRedactURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want string
	}{{
		name: "a signed delivery URL loses its whole query",
		raw:  "https://edge.example/article?exp=4102444800&kid=exchange&sig=SECRET&agent_id=AGENT",
		want: "https://edge.example/article",
	}, {
		name: "userinfo goes too, which is all url.URL.Redacted would have touched",
		raw:  "https://user:pw@edge.example/article?sig=SECRET",
		want: "https://edge.example/article",
	}, {
		name: "a fragment cannot carry one past the redaction either",
		raw:  "https://edge.example/article?sig=SECRET#sig=SECRET",
		want: "https://edge.example/article",
	}, {
		name: "nothing to redact is left alone",
		raw:  "https://edge.example/article",
		want: "https://edge.example/article",
	}, {
		name: "an unparseable value yields nothing rather than itself",
		raw:  "://not a url?sig=SECRET",
		want: "",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RedactURL(tc.raw)
			if got != tc.want {
				t.Fatalf("RedactURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
			if strings.Contains(got, "SECRET") || strings.Contains(got, "pw") {
				t.Errorf("redacted form still carries a secret: %q", got)
			}
		})
	}
}
