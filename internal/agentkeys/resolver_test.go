package agentkeys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

const agentHost = "agent.fixture.test"

var clockNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// origin is a fixture well-known host with a request counter so tests can assert
// whether (and how often) the resolver fetched the WBA directory.
type origin struct {
	server *httptest.Server
	hits   atomic.Int32
}

// newOrigin serves body/status at the WBA directory path and counts hits.
func newOrigin(t *testing.T, status int, body []byte) *origin {
	t.Helper()
	o := &origin{}
	o.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		if r.URL.Path != rampwellknown.WBAPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(o.server.Close)
	return o
}

// rewriter routes requests for agentHost to the fixture origin, mirroring the
// production fetch of a signer's WBA directory from its own host (ADR-009 D3/D4)
// without DNS.
type rewriter struct{ target string }

func (rw rewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == agentHost && rw.target != "" {
		t, err := url.Parse(rw.target)
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.URL.Scheme, req.URL.Host = t.Scheme, t.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func resolverFor(t *testing.T, target string) helpers.KeyResolver {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return agentkeys.New(ctx, agentkeys.Config{
		Client: &http.Client{Transport: rewriter{target: target}},
		Clk:    clock.NewDeterministic(clockNow),
	})
}

// resolve invokes r with dir carried as the signed Signature-Agent directory and
// keyid as the RFC 9421 keyid (an RFC 7638 thumbprint).
func resolve(r helpers.KeyResolver, dir, keyid string) (ed25519.PublicKey, error) {
	return r.Resolve(helpers.WithSignatureAgent(context.Background(), dir), keyid)
}

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	return pub, priv
}

// wbaJSON renders a WBA directory carrying one key valid over [from, until), and
// returns the bytes plus the key's RFC 7638 thumbprint (the keyid to resolve).
func wbaJSON(t *testing.T, pub ed25519.PublicKey, from, until time.Time) ([]byte, string) {
	t.Helper()
	key := rampwellknown.NewKey(pub, from, until)
	tp, err := rampwellknown.Thumbprint(key)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return testutil.MarshalWBA(testutil.WBAFile(key)), tp
}

func TestResolver_PublishedKeyResolves(t *testing.T) {
	pub, _ := mustKey(t)
	body, keyid := wbaJSON(t, pub, clockNow.Add(-time.Hour), clockNow.Add(24*time.Hour))
	o := newOrigin(t, http.StatusOK, body)

	got, err := resolve(resolverFor(t, o.server.URL), agentHost, keyid)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatal("resolved key != published key")
	}
}

func TestResolver_NoSignatureAgentSkippedNoFetch(t *testing.T) {
	pub, _ := mustKey(t)
	body, keyid := wbaJSON(t, pub, clockNow, clockNow.Add(time.Hour))
	o := newOrigin(t, http.StatusOK, body)

	// No Signature-Agent directory on the context — the resolver cannot know
	// which directory to fetch, so it reports the keyid unknown WITHOUT a fetch.
	_, err := resolverFor(t, o.server.URL).Resolve(context.Background(), keyid)
	if !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey without Signature-Agent, got %v", err)
	}
	if hits := o.hits.Load(); hits != 0 {
		t.Fatalf("missing Signature-Agent must not trigger a fetch; got %d hits", hits)
	}
}

func TestResolver_DirectoryMissing(t *testing.T) {
	o := newOrigin(t, http.StatusNotFound, nil)
	assertUnknown(t, resolverFor(t, o.server.URL), "any-thumbprint")
}

func TestResolver_OriginUnreachable(t *testing.T) {
	// Point the rewriter at a closed server so the fetch fails at transport.
	o := newOrigin(t, http.StatusOK, nil)
	target := o.server.URL
	o.server.Close()
	assertUnknown(t, resolverFor(t, target), "any-thumbprint")
}

func TestResolver_MalformedDirectory(t *testing.T) {
	o := newOrigin(t, http.StatusOK, []byte("{not valid jwk set"))
	assertUnknown(t, resolverFor(t, o.server.URL), "any-thumbprint")
}

func TestResolver_UnknownThumbprint(t *testing.T) {
	pub, _ := mustKey(t)
	body, _ := wbaJSON(t, pub, clockNow.Add(-time.Hour), clockNow.Add(time.Hour))
	o := newOrigin(t, http.StatusOK, body)
	// A thumbprint the directory does not publish resolves to unknown.
	other, _ := mustKey(t)
	otherTP, err := helpers.Thumbprint(other)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	assertUnknown(t, resolverFor(t, o.server.URL), otherTP)
}

func TestResolver_AllKeysExpired(t *testing.T) {
	pub, _ := mustKey(t)
	body, keyid := wbaJSON(t, pub, clockNow.Add(-48*time.Hour), clockNow.Add(-time.Hour))
	o := newOrigin(t, http.StatusOK, body)
	assertUnknown(t, resolverFor(t, o.server.URL), keyid)
}

func TestResolver_CachesDirectory(t *testing.T) {
	pub, _ := mustKey(t)
	body, keyid := wbaJSON(t, pub, clockNow.Add(-time.Hour), clockNow.Add(24*time.Hour))
	o := newOrigin(t, http.StatusOK, body)
	r := resolverFor(t, o.server.URL)

	for range 3 {
		if _, err := resolve(r, agentHost, keyid); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if hits := o.hits.Load(); hits != 1 {
		t.Fatalf("WBA directory should be fetched once and cached; got %d hits", hits)
	}
}

// TestResolver_PollerAppliesRevocation proves New starts the loader's
// background revocation poller: a key that resolves cleanly on first contact is
// rejected once a newer revocation snapshot is published, WITHOUT the directory
// TTL expiring (TTL is set far past the test). If New did not start
// loader.Run, the revocation would never be polled and this key would keep
// resolving until the directory TTL — the SEC gap this guards against. Mirrors
// rampwellknown's TestLoaderRun_PollerAppliesRevocation, but drives the behavior
// through the agentkeys resolver surface rather than the loader directly.
func TestResolver_PollerAppliesRevocation(t *testing.T) {
	_, key := testutil.NewSigningKey("agent-k1", clockNow.Add(-time.Hour), clockNow.Add(1000*time.Hour))
	tp, err := rampwellknown.Thumbprint(key)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	o := testutil.NewOrigin(nil)
	t.Cleanup(o.Close)
	wba := testutil.WBAFile(key)
	wba.RevocationUrl = testutil.Ptr(o.RevocationURL())
	o.SetWBA(testutil.MarshalWBA(wba))
	o.SetRevocation(testutil.MarshalRevocation(clockNow.Add(-time.Hour))) // nothing revoked yet

	const pollInterval = 10 * time.Second
	clk := clock.NewDeterministic(clockNow)
	poll := testutil.NewPollSignals()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := agentkeys.New(ctx, agentkeys.Config{
		Client: testutil.Client(),
		// The fixture origin is plaintext, and the resolver canonicalizes the
		// Signature-Agent value — which drops the scheme the caller spelled, so the
		// CONFIGURED one decides the fetch. That is deliberate (a caller must not be
		// able to pull the directory fetch down to cleartext by asking), and it is
		// what RAMP_WELLKNOWN_SCHEME is for; the compose stacks set it the same way.
		Scheme:       "http",
		Clk:          clk,
		TTL:          100 * time.Hour, // never re-fetch the directory → isolate the poller
		PollInterval: pollInterval,
		OnPollArmed:  poll.Armed,
		OnPollCycle:  poll.Cycled,
	})

	// Prime the directory + empty revocation snapshot; the key resolves.
	if _, err := resolve(r, o.URL, tp); err != nil {
		t.Fatalf("prime resolve: %v", err)
	}
	// Publish a newer snapshot revoking the key, then deterministically cross one
	// poll boundary: wait until the poller has armed its tick timer, advance past
	// the (jittered ±10%) interval to fire it, and wait for the refresh to
	// complete — no sleeps, no wall-clock deadline.
	o.SetRevocation(testutil.MarshalRevocation(clockNow, tp))
	poll.CrossOne(t, clk, 2*pollInterval)

	if _, err := resolve(r, o.URL, tp); !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("running poller did not apply the revocation: got %v", err)
	}
}

// captureTransport records the host of the outbound WBA fetch so a test can
// assert the URL the resolver shaped from the env knobs, then fails the request
// — the captured host is the assertion, no live directory is needed.
type captureTransport struct{ host string }

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.host = req.URL.Host
	return nil, errors.New("captured")
}

// TestNewFromEnv_PortReadsWellknownEnv pins that the env-driven constructor takes
// the bare-host fetch port from RAMP_WELLKNOWN_PORT — the converged well-known
// knob, renamed from RAMP_MANIFEST_FETCH_PORT to sit beside RAMP_WELLKNOWN_SCHEME
// — and appends it to a bare Signature-Agent directory before fetching. A deploy
// that still sets the old name would leave the port unshaped and this test red.
func TestNewFromEnv_PortReadsWellknownEnv(t *testing.T) {
	t.Setenv("RAMP_WELLKNOWN_SCHEME", "http")
	t.Setenv("RAMP_WELLKNOWN_PORT", "8123")
	ct := &captureTransport{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := agentkeys.NewFromEnv(ctx, &http.Client{Transport: ct}, slog.Default())
	// A bare-host directory (no scheme, no port) is the only shape withConfiguredPort
	// rewrites; the resolve outcome is irrelevant — the shaped host is the proof.
	_, _ = resolve(r, "bare-agent-host", "some-thumbprint")
	if ct.host != "bare-agent-host:8123" {
		t.Fatalf("fetch host = %q, want bare-agent-host:8123 (port from RAMP_WELLKNOWN_PORT)", ct.host)
	}
}

func assertUnknown(t *testing.T, r helpers.KeyResolver, keyid string) {
	t.Helper()
	_, err := resolve(r, agentHost, keyid)
	if !errors.Is(err, helpers.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}
