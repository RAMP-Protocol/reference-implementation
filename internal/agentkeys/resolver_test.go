package agentkeys_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

const agentHost = "agent.fixture.test"

var clockNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// origin is a fixture well-known host with a request counter so tests can assert
// whether (and how often) the resolver fetched.
type origin struct {
	server *httptest.Server
	hits   atomic.Int32
}

// newOrigin serves body/status at /.well-known/ramp.json and counts hits.
func newOrigin(t *testing.T, status int, body []byte) *origin {
	t.Helper()
	o := &origin{}
	o.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		if r.URL.Path != "/.well-known/ramp.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(o.server.Close)
	return o
}

// rewriter routes requests for agentHost to the fixture origin, mirroring the
// production fetch of an agent's manifest from its own host (ADR-009 D3/D4)
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

func resolverFor(target string) httpsig.KeyResolver {
	return agentkeys.NewResolver(agentkeys.Config{
		Client: &http.Client{Transport: rewriter{target: target}},
		Clk:    clock.NewDeterministic(clockNow),
	})
}

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	return pub, priv
}

// manifestJSON renders a ROLE_AGENT manifest anchoring domain with one key valid
// over [from, until).
func manifestJSON(domain string, pub ed25519.PublicKey, from, until time.Time) []byte {
	key := rampwellknown.NewKey("k1", pub, from, until)
	return testutil.MarshalManifest(testutil.Manifest(rampwellknown.RoleAgent, domain, key))
}

func TestResolver_PublishedKeyResolves(t *testing.T) {
	pub, _ := mustKey(t)
	o := newOrigin(t, http.StatusOK,
		manifestJSON(agentHost, pub, clockNow.Add(-time.Hour), clockNow.Add(24*time.Hour)))

	got, err := resolverFor(o.server.URL).Resolve(context.Background(), agentHost)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatal("resolved key != published key")
	}
}

func TestResolver_BrokerKidSkippedNoFetch(t *testing.T) {
	o := newOrigin(t, http.StatusOK, manifestJSON(agentHost, mustPub(t), clockNow, clockNow.Add(time.Hour)))

	_, err := resolverFor(o.server.URL).Resolve(context.Background(), httpsig.BrokerKeyIDPrefix+"relay.v1")
	if !errors.Is(err, httpsig.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey for broker kid, got %v", err)
	}
	if hits := o.hits.Load(); hits != 0 {
		t.Fatalf("broker kid must not trigger a manifest fetch; got %d hits", hits)
	}
}

func TestResolver_ManifestMissing(t *testing.T) {
	o := newOrigin(t, http.StatusNotFound, nil)
	assertUnknown(t, resolverFor(o.server.URL))
}

func TestResolver_OriginUnreachable(t *testing.T) {
	// Point the rewriter at a closed server so the fetch fails at transport.
	o := newOrigin(t, http.StatusOK, nil)
	target := o.server.URL
	o.server.Close()
	assertUnknown(t, resolverFor(target))
}

func TestResolver_MalformedManifest(t *testing.T) {
	o := newOrigin(t, http.StatusOK, []byte("{not valid ramp json"))
	assertUnknown(t, resolverFor(o.server.URL))
}

func TestResolver_AllKeysExpired(t *testing.T) {
	pub, _ := mustKey(t)
	o := newOrigin(t, http.StatusOK,
		manifestJSON(agentHost, pub, clockNow.Add(-48*time.Hour), clockNow.Add(-time.Hour)))
	assertUnknown(t, resolverFor(o.server.URL))
}

func TestResolver_AnchorMismatch(t *testing.T) {
	pub, _ := mustKey(t)
	// Manifest is fetched from agentHost but self-asserts a different domain.
	o := newOrigin(t, http.StatusOK,
		manifestJSON("imposter.test", pub, clockNow.Add(-time.Hour), clockNow.Add(time.Hour)))
	assertUnknown(t, resolverFor(o.server.URL))
}

func TestResolver_CachesManifest(t *testing.T) {
	pub, _ := mustKey(t)
	o := newOrigin(t, http.StatusOK,
		manifestJSON(agentHost, pub, clockNow.Add(-time.Hour), clockNow.Add(24*time.Hour)))
	r := resolverFor(o.server.URL)

	for range 3 {
		if _, err := r.Resolve(context.Background(), agentHost); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if hits := o.hits.Load(); hits != 1 {
		t.Fatalf("manifest should be fetched once and cached; got %d hits", hits)
	}
}

func assertUnknown(t *testing.T, r httpsig.KeyResolver) {
	t.Helper()
	_, err := r.Resolve(context.Background(), agentHost)
	if !errors.Is(err, httpsig.ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func mustPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _ := mustKey(t)
	return pub
}
