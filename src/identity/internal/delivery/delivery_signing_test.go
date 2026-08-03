package delivery

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// TestFetchProofFreshness drives the created/expires window the fetcher emits.
//
// Nothing else covers it: Config.Clock and Config.TTL are settable but no other
// test injects either, so a mis-plumbed window would reach the wire unnoticed and
// surface at a real edge as an undifferentiated 403 — the one failure this
// package's own guards exist to name at the source.
//
// The boundary case is why this is a table. A proof whose expires lands exactly
// on the verifier's current second is stale to the SDK verifier the production
// edge runs (`now >= expires`), so the double has to refuse it too; only a case
// that hits the boundary exactly distinguishes an inclusive comparison from an
// exclusive one. The fresh case is the control — without it, a double that
// refused everything would pass the other two.
func TestFetchProofFreshness(t *testing.T) {
	t.Parallel()
	const ttl = 30 * time.Second
	tests := []struct {
		name string
		// mintedAgo is how far behind the edge's own clock the fetcher signs.
		mintedAgo time.Duration
		// wantReason is the edge's refusal token; "" means the fetch must succeed.
		wantReason string
	}{
		{name: "inside the window", mintedAgo: 0},
		{name: "expiring on the verifier's own second", mintedAgo: ttl, wantReason: "pop_expired"},
		{name: "long stale", mintedAgo: time.Hour, wantReason: "pop_expired"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keys, thumbprint := custody(t)
			edge := newEdge(t)
			signingAt := time.Unix(edge.Now(), 0).Add(-tc.mintedAgo)
			fetcher := newFetcher(t, keys, func(c *Config) {
				c.Clock = clock.NewDeterministic(signingAt)
				c.TTL = ttl
			})

			_, err := fetcher.Fetch(context.Background(), edge.URLFor(thumbprint))

			if tc.wantReason == "" {
				if err != nil {
					t.Fatalf("fetch: %v", err)
				}
				return
			}
			refusal := deliveryError(t, err, KindRefused)
			if refusal.Status != http.StatusForbidden {
				t.Errorf("status: got %d, want %d", refusal.Status, http.StatusForbidden)
			}
			if refusal.Reason != tc.wantReason {
				t.Errorf("reason: got %q, want %q", refusal.Reason, tc.wantReason)
			}
		})
	}
}

// TestFetchRefusesAURLItCannotSignFaithfully covers the round-trip-stability
// guard.
//
// The proof covers @target-uri as the VERBATIM string, while the request line
// carries whatever url.URL re-serializes to. When those diverge the signature
// cannot verify, and the edge reports only an undifferentiated 403 — so the
// fetcher refuses at the source instead of shipping a proof guaranteed to fail.
// Asserting the message names the cause matters: a URL that url.Parse rejects
// outright would also yield KindMalformed, from a different branch, and would
// pass a test that only checked the class.
func TestFetchRefusesAURLItCannotSignFaithfully(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)
	// A literal space survives url.Parse but comes back percent-encoded from
	// EscapedPath, so the request line would not carry the bytes that were signed.
	unstable := strings.Replace(edge.URLFor(thumbprint), "/article?", "/art icle?", 1)

	_, err := newFetcher(t, keys, nil).Fetch(context.Background(), unstable)

	refusal := deliveryError(t, err, KindMalformed)
	if !strings.Contains(refusal.Error(), "round-trip stable") {
		t.Errorf("refusal does not name round-trip instability: %v", refusal)
	}
	if hits := edge.Hits(); hits != 0 {
		t.Errorf("edge saw %d requests; a URL that cannot be signed faithfully must not leave the process", hits)
	}
}

// TestFetchRefusedWhenTheProofIsTampered drives the edge double's actual
// signature check, which nothing else does.
//
// Every other refusal case here is reached before the Ed25519 verify runs — a
// missing key, a mismatched keyid, a stale window, or a SetRefusal short-circuit
// that skips verification entirely. So the double's crypto could have been a
// no-op and the whole suite would still pass, which would quietly retire the one
// property the double exists to provide: that a signer emitting the wrong bytes is
// caught here rather than as an undifferentiated 403 at a real edge.
//
// The proof is made valid and then corrupted in transit, so everything the edge
// checks BEFORE the signature still agrees: the presented key is right, its
// thumbprint matches the URL's agent_id, and the window is fresh. Only the bytes
// are wrong.
func TestFetchRefusedWhenTheProofIsTampered(t *testing.T) {
	t.Parallel()
	keys, thumbprint := custody(t)
	edge := newEdge(t)

	tamper := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		// Flip one byte inside the base64 signature, leaving its structure intact so
		// the edge parses it and reaches the verify rather than rejecting the shape.
		sig := req.Header.Get("Signature")
		body, ok := strings.CutPrefix(strings.TrimSuffix(sig, ":"), "sig1=:")
		if !ok || body == "" {
			t.Errorf("unexpected Signature shape %q", sig)
			return http.DefaultTransport.RoundTrip(req)
		}
		swapped := "A"
		if body[0] == 'A' {
			swapped = "B"
		}
		req.Header.Set("Signature", "sig1=:"+swapped+body[1:]+":")
		return http.DefaultTransport.RoundTrip(req)
	})

	fetcher := newFetcher(t, keys, func(c *Config) { c.Transport = tamper })
	_, err := fetcher.Fetch(context.Background(), edge.URLFor(thumbprint))

	refusal := deliveryError(t, err, KindRefused)
	if refusal.Reason != "pop_sig_invalid" {
		t.Errorf("reason: got %q, want pop_sig_invalid — the edge must reach its verify", refusal.Reason)
	}
}

// roundTripperFunc adapts a function to http.RoundTripper, so a test can mutate a
// request after the fetcher has signed it. Signing happens inside the fetcher, so
// this is the only seam where a proof can be corrupted the way the wire could.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestFetchRefusalReasonIsTokenShaped pins that a refusal token is only ever
// promoted when it looks like one.
//
// The body it comes from is written by the host just fetched from, and the value
// is promoted OVER this package's own classification and handed to the agent as a
// machine-readable token in our vocabulary. Unchecked, a publisher could claim a
// custody fault that is ours rather than theirs, or push arbitrary text into a
// structured log field.
func TestFetchRefusalReasonIsTokenShaped(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want string // the reason an agent ends up seeing
	}{{
		name: "a real edge token is promoted",
		body: `{"reason":"keyid_mismatch"}`,
		want: "keyid_mismatch",
	}, {
		name: "prose falls back to our own class",
		body: `{"reason":"your custody wiring is broken, contact the registry"}`,
		want: "refused",
	}, {
		// 64 is the limit, so both sides of it are pinned here — a bare "too long"
		// case would pass against an off-by-one in either direction.
		name: "a token at the length limit is promoted",
		body: `{"reason":"` + strings.Repeat("a", 64) + `"}`,
		want: strings.Repeat("a", 64),
	}, {
		name: "one character past the limit falls back",
		body: `{"reason":"` + strings.Repeat("a", 65) + `"}`,
		want: "refused",
	}, {
		name: "uppercase and punctuation fall back",
		body: `{"reason":"Keyid-Mismatch"}`,
		want: "refused",
	}, {
		name: "no reason at all falls back",
		body: `{"error":"nope"}`,
		want: "refused",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			keys, thumbprint := custody(t)
			edge := newEdge(t)
			edge.SetRefusal(http.StatusForbidden, tc.body)

			_, err := newFetcher(t, keys, nil).Fetch(context.Background(), edge.URLFor(thumbprint))

			refusal := deliveryError(t, err, KindRefused)
			if got := refusal.ReasonOf(); got != tc.want {
				t.Errorf("ReasonOf() = %q, want %q", got, tc.want)
			}
		})
	}
}
