//go:build integration

package agentsign_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yaronf/httpsign"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// These cases drive the whole custody-to-wire path with a REAL Vault holding the
// keys and a REAL HTTP origin receiving the request: mint a key through the
// KeyStore, sign an outbound request through the production transport, and verify
// the signature at the origin.
//
// What each leg traverses, named honestly: the write leg is
// KeyStore → Vault; the read leg is transport → agentsign → KeyStore → Vault →
// signature → origin. The public key the origin checks against is read back
// through the KeyStore (the same surface the agent's published WBA directory is
// built from), NOT through an HTTP fetch of that directory — so this is a CUSTODY
// round-trip, not a directory round-trip. The directory↔custody link is covered by
// the publisher package's own suite.

const (
	alice = "alice.rampmcp.org"
	bob   = "bob.rampmcp.org"
)

// origin is a WBA-aware receiver: it records the requests it is handed, body
// restored, so a test verifies the signature against the bytes that crossed the
// wire.
type origin struct {
	srv  *httptest.Server
	seen []*http.Request
}

func newOrigin(t *testing.T) *origin {
	t.Helper()
	o := &origin{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clone := r.Clone(context.Background())
		body, _ := io.ReadAll(r.Body)
		clone.Body = io.NopCloser(bytes.NewReader(body))
		o.seen = append(o.seen, clone)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(o.srv.Close)
	return o
}

// verify checks the recorded request under the Web Bot Auth profile against pub —
// what a WBA-aware origin does once it has fetched the signer's directory.
func (o *origin) verify(t *testing.T, i int, pub ed25519.PublicKey) error {
	t.Helper()
	cfg := httpsign.NewVerifyConfig().SetVerifyCreated(false).SetAllowedTags([]string{httpsig.WBATag})
	verifier, err := httpsign.NewEd25519Verifier(pub, cfg, httpsign.Headers("@authority", "signature-agent"))
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	return httpsign.VerifyRequest("sig1", *verifier, o.seen[i])
}

// signingClient wires the production shape: one transport, keys resolved per
// request from custody.
//
// The signature window runs on the SYSTEM clock even though custody runs on a
// deterministic one, because the two instants are judged by different parties.
// Custody's clock decides which key is active, and only this suite reads it. The
// signature's expires is read by the origin's yaronf/httpsign verifier, which
// compares it against time.Now() and offers no hook to override that. Stamping
// expires off a clock frozen at a fixed instant therefore yields a signature that
// is born expired from the moment real time passes that instant — green until the
// anchor's day and hour, then permanently red.
func signingClient(t *testing.T, custody agentsign.Custody) *http.Client {
	t.Helper()
	resolver, err := agentsign.New(agentsign.Config{Keys: custody, Scheme: "https"})
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	transport, err := ramphttpsig.New(nil, "", nil, ramphttpsig.ClockWindow(clock.System{}, 5*time.Minute),
		ramphttpsig.WithKeySource(resolver.Source()), ramphttpsig.WithWBASigning())
	if err != nil {
		t.Fatalf("build transport: %v", err)
	}
	return &http.Client{Transport: transport}
}

// fetchAs drives one request as the named agent and returns the transport error,
// if any. A nil subdomain-carrying context is the unauthenticated case.
func fetchAs(t *testing.T, client *http.Client, url, subdomain string) error {
	t.Helper()
	ctx := t.Context()
	if subdomain != "" {
		ctx = agentsign.WithSubdomain(ctx, subdomain)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, doErr := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return doErr
}

// TestSigningTransport_SignsWithTheAgentsCustodiedKey is the ticket's core
// property: a request the registry sends on an agent's behalf carries a signature
// the origin can check against that agent's own key, and names that agent's own
// directory so the origin knows where to look.
func TestSigningTransport_SignsWithTheAgentsCustodiedKey(t *testing.T) {
	custody, _ := newCustody(t)
	minted, err := custody.Create(t.Context(), alice, liveWindow())
	if err != nil {
		t.Fatalf("mint key: %v", err)
	}
	o := newOrigin(t)

	if err := fetchAs(t, signingClient(t, custody), o.srv.URL+"/article", alice); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	if len(o.seen) != 1 {
		t.Fatalf("origin saw %d requests, want 1", len(o.seen))
	}
	if err := o.verify(t, 0, minted.Public); err != nil {
		t.Fatalf("origin could not verify against the agent's custodied key: %v", err)
	}
	got := o.seen[0]
	if want := `"https://` + alice + `"`; got.Header.Get(httpsig.SignatureAgentHeader) != want {
		t.Errorf("Signature-Agent = %s, want %s", got.Header.Get(httpsig.SignatureAgentHeader), want)
	}
	params, err := httpsig.ParseSignatureLabels(got.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if params[0].KeyID != minted.Ref.Thumbprint {
		t.Errorf("keyid = %q, want the custodied key's thumbprint %q", params[0].KeyID, minted.Ref.Thumbprint)
	}
}

// TestSigningTransport_SignsEachAgentWithItsOwnKey is the impersonation guard. One
// transport carries every agent, so a key resolved once and reused would sign the
// second agent's request as the first — and the origin would believe it.
func TestSigningTransport_SignsEachAgentWithItsOwnKey(t *testing.T) {
	custody, _ := newCustody(t)
	aliceKey, err := custody.Create(t.Context(), alice, liveWindow())
	if err != nil {
		t.Fatalf("mint alice: %v", err)
	}
	bobKey, err := custody.Create(t.Context(), bob, liveWindow())
	if err != nil {
		t.Fatalf("mint bob: %v", err)
	}
	o := newOrigin(t)
	client := signingClient(t, custody)

	for _, subdomain := range []string{alice, bob} {
		if err := fetchAs(t, client, o.srv.URL+"/article", subdomain); err != nil {
			t.Fatalf("fetch as %s: %v", subdomain, err)
		}
	}

	if err := o.verify(t, 0, aliceKey.Public); err != nil {
		t.Errorf("first request did not verify as alice: %v", err)
	}
	if err := o.verify(t, 1, bobKey.Public); err != nil {
		t.Errorf("second request did not verify as bob: %v", err)
	}
	// Cross-check: bob's request must NOT verify under alice's key, or the two
	// agents are not actually distinguishable at the origin.
	if err := o.verify(t, 1, aliceKey.Public); err == nil {
		t.Error("bob's request verified under alice's key")
	}
}

// TestSigningTransport_FollowsARotation pins that the key is resolved per request
// rather than cached: once custody retires the old key and a newer one is active,
// the very next request is signed with the new one. A cached key would keep signing
// with a retired — or revoked — key for as long as the process lived.
func TestSigningTransport_FollowsARotation(t *testing.T) {
	custody, clk := newCustody(t)
	old, err := custody.Create(t.Context(), alice, liveWindow())
	if err != nil {
		t.Fatalf("mint old: %v", err)
	}
	o := newOrigin(t)
	client := signingClient(t, custody)
	if err := fetchAs(t, client, o.srv.URL+"/article", alice); err != nil {
		t.Fatalf("fetch before rotation: %v", err)
	}

	// Rotate: mint the successor, then retire the predecessor.
	fresh, err := custody.Create(t.Context(), alice, keystore.Window{
		NotBefore: anchor, NotAfter: anchor.Add(60 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("mint successor: %v", err)
	}
	if err := custody.Expire(t.Context(), old.Ref, anchor.Add(time.Hour)); err != nil {
		t.Fatalf("retire predecessor: %v", err)
	}
	clk.Advance(2 * time.Hour)

	if err := fetchAs(t, client, o.srv.URL+"/article", alice); err != nil {
		t.Fatalf("fetch after rotation: %v", err)
	}

	if err := o.verify(t, 1, fresh.Public); err != nil {
		t.Errorf("post-rotation request did not verify under the new key: %v", err)
	}
	if err := o.verify(t, 1, old.Public); err == nil {
		t.Error("post-rotation request still verified under the retired key")
	}
}

// TestSigningTransport_RefusesAnUnauthenticatedRequest pins the fail-closed rule:
// with no authenticated agent on the context there is nobody to sign as, and the
// request must not leave unsigned — an origin would read it as an anonymous bot.
func TestSigningTransport_RefusesAnUnauthenticatedRequest(t *testing.T) {
	custody, _ := newCustody(t)
	if _, err := custody.Create(t.Context(), alice, liveWindow()); err != nil {
		t.Fatalf("mint key: %v", err)
	}
	o := newOrigin(t)

	err := fetchAs(t, signingClient(t, custody), o.srv.URL+"/article", "")

	if !errors.Is(err, agentsign.ErrNoIdentity) {
		t.Fatalf("err = %v, want ErrNoIdentity", err)
	}
	if len(o.seen) != 0 {
		t.Errorf("origin saw %d requests; an unidentified request must not be sent", len(o.seen))
	}
}

// TestSigningTransport_RefusesWhenTheAgentHasNoActiveKey covers the states custody
// reports as "nothing to sign with": never provisioned, expired, or revoked. The
// error keeps the keystore sentinel so a caller can tell it from an outage.
func TestSigningTransport_RefusesWhenTheAgentHasNoActiveKey(t *testing.T) {
	custody, _ := newCustody(t)
	// A key whose window closed an hour before the clock's instant — the shape a
	// retired or revoked key leaves behind.
	if _, err := custody.Create(t.Context(), alice, keystore.Window{
		NotBefore: anchor.Add(-48 * time.Hour), NotAfter: anchor.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("mint expired key: %v", err)
	}
	o := newOrigin(t)

	err := fetchAs(t, signingClient(t, custody), o.srv.URL+"/article", alice)

	if !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("err = %v, want the keystore not-found sentinel", err)
	}
	if len(o.seen) != 0 {
		t.Errorf("origin saw %d requests; want none", len(o.seen))
	}
}
