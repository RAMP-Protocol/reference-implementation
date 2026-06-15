// Unit tests for the JWKS fetcher and resolver. JWKS parsing + kid
// resolution are pure parser logic and qualify for unit-test coverage
// under the testing doctrine.
package jwks_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/jwks"
)

type jwkBody struct {
	Kty      string `json:"kty"`
	Crv      string `json:"crv"`
	X        string `json:"x"`
	Kid      string `json:"kid"`
	Alg      string `json:"alg"`
	Use      string `json:"use"`
	IssuedAt string `json:"issued_at,omitempty"`
}

func encodeJWKS(keys ...jwkBody) []byte {
	body := struct {
		Keys []jwkBody `json:"keys"`
	}{Keys: keys}
	out, _ := json.Marshal(body)
	return out
}

func newOKPEntry(t *testing.T, kid, issuedAt string) (jwkBody, ed25519.PublicKey) {
	t.Helper()
	return newOKPEntryWithUse(t, kid, issuedAt, "sig")
}

func newOKPEntryWithUse(t *testing.T, kid, issuedAt, use string) (jwkBody, ed25519.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	return jwkBody{
		Kty:      "OKP",
		Crv:      "Ed25519",
		X:        base64.RawURLEncoding.EncodeToString(pub),
		Kid:      kid,
		Alg:      "EdDSA",
		Use:      use,
		IssuedAt: issuedAt,
	}, pub
}

// TestFetchAndResolveByKID — happy path with kid match.
func TestFetchAndResolveByKID(t *testing.T) {
	entry1, _ := newOKPEntry(t, "acme.delegate.2025q1", "2025-01-01T00:00:00Z")
	entry2, pub2 := newOKPEntry(t, "acme.delegate.2026", "2026-01-01T00:00:00Z")
	body := encodeJWKS(entry1, entry2)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	fetcher := &jwks.HTTPFetcher{Client: srv.Client()}
	set, err := fetcher.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	resolved, err := jwks.Resolve(set, "acme.delegate.2026")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if resolved.Kid != "acme.delegate.2026" {
		t.Errorf("kid = %q, want acme.delegate.2026", resolved.Kid)
	}
	if !resolved.PublicKey.Equal(pub2) {
		t.Errorf("pubkey mismatch")
	}
}

// TestResolveUnknownKID — explicit kid not in JWKS returns ErrUnknownKID.
func TestResolveUnknownKID(t *testing.T) {
	entry, _ := newOKPEntry(t, "acme.delegate.2025q1", "2025-01-01T00:00:00Z")
	set, err := jwks.Parse(encodeJWKS(entry))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = jwks.Resolve(set, "missing-kid")
	if !errors.Is(err, jwks.ErrUnknownKID) {
		t.Fatalf("err = %v, want ErrUnknownKID", err)
	}
}

// TestResolveMostRecent — empty kid picks the highest issued_at.
func TestResolveMostRecent(t *testing.T) {
	older, _ := newOKPEntry(t, "acme.delegate.2025q1", "2025-01-01T00:00:00Z")
	newer, newerPub := newOKPEntry(t, "acme.delegate.2026", "2026-04-01T00:00:00Z")
	set, err := jwks.Parse(encodeJWKS(older, newer))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := jwks.Resolve(set, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Kid != "acme.delegate.2026" {
		t.Errorf("kid = %q, want acme.delegate.2026", got.Kid)
	}
	if !got.PublicKey.Equal(newerPub) {
		t.Errorf("pubkey mismatch")
	}
}

// TestResolveMostRecentFallsBackToPosition — when no issued_at is set, the
// last entry in the JWKS body wins.
func TestResolveMostRecentFallsBackToPosition(t *testing.T) {
	first, _ := newOKPEntry(t, "k1", "")
	second, secondPub := newOKPEntry(t, "k2", "")
	set, err := jwks.Parse(encodeJWKS(first, second))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := jwks.Resolve(set, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Kid != "k2" {
		t.Errorf("kid = %q, want k2", got.Kid)
	}
	if !got.PublicKey.Equal(secondPub) {
		t.Errorf("pubkey mismatch")
	}
}

// TestParseRejectsNoEd25519 — a JWKS that contains only RSA / EC entries
// returns ErrNoKeys (mint cannot proceed).
func TestParseRejectsNoEd25519(t *testing.T) {
	body := []byte(`{"keys":[{"kty":"RSA","n":"x","e":"AQAB","kid":"r1"}]}`)
	_, err := jwks.Parse(body)
	if !errors.Is(err, jwks.ErrNoKeys) {
		t.Fatalf("err = %v, want ErrNoKeys", err)
	}
}

// TestParseRejectsMalformedX — base64 x that doesn't decode to 32 bytes.
func TestParseRejectsMalformedX(t *testing.T) {
	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"bad","x":"AA"}]}`)
	set, err := jwks.Parse(body)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := jwks.Resolve(set, "bad"); !errors.Is(err, jwks.ErrInvalidKey) {
		t.Fatalf("err = %v, want ErrInvalidKey", err)
	}
}

// TestFetchRejectsNonHTTPS — http:// URLs to non-loopback hosts are
// rejected at the URL-validation step (ADR-003 §1).
func TestFetchRejectsNonHTTPS(t *testing.T) {
	fetcher := jwks.NewHTTPFetcher()
	_, err := fetcher.Fetch(context.Background(), "http://example.com/keys")
	if !errors.Is(err, jwks.ErrInvalidURL) {
		t.Fatalf("err = %v, want ErrInvalidURL", err)
	}
}

// TestFetchAllowsLoopbackHTTP — dev/demo convenience: localhost http://
// is allowed.
func TestFetchAllowsLoopbackHTTP(t *testing.T) {
	entry, _ := newOKPEntry(t, "demo", "")
	body := encodeJWKS(entry)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	// httptest.NewServer URL is 127.0.0.1:port → loopback exception applies.
	fetcher := &jwks.HTTPFetcher{Client: srv.Client()}
	if _, err := fetcher.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
}

// TestFetchAllowsInsecureNonLoopbackWhenOptedIn — compose-internal
// callers (publisher-jwks reached via the `examplenews` network alias
// over plain HTTP) opt in to AllowInsecure on the default fetcher so
// the shared package serves both the public https-only fetch path
// and the dev/demo-stack fetch path without a second copy. Without
// the opt-in, a non-loopback http:// URL is rejected; with the
// opt-in the fetch proceeds.
func TestFetchAllowsInsecureNonLoopbackWhenOptedIn(t *testing.T) {
	entry, _ := newOKPEntry(t, "demo", "")
	body := encodeJWKS(entry)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Build a URL whose hostname is a non-loopback alias (`examplenews`)
	// while routing the actual TCP connection at the loopback test
	// server via a custom Transport. This mirrors the docker-compose
	// shape: the URL the operator hands the fetcher carries the
	// network-alias hostname; the underlying transport resolves that
	// alias inside the compose network. validateURL inspects the URL
	// string only, so the rewrite is invisible to it.
	rewritingClient := &http.Client{
		Transport: &rewriteTransport{target: srv.URL},
	}
	const aliasURL = "http://examplenews/.well-known/jwks.json"

	// (a) Default fetcher (AllowInsecure = false) refuses the URL.
	defaultFetcher := &jwks.HTTPFetcher{Client: rewritingClient}
	if _, err := defaultFetcher.Fetch(context.Background(), aliasURL); !errors.Is(err, jwks.ErrInvalidURL) {
		t.Fatalf("default fetcher: err = %v, want ErrInvalidURL", err)
	}

	// (b) Opted-in fetcher (AllowInsecure = true) accepts the URL.
	insecureFetcher := &jwks.HTTPFetcher{Client: rewritingClient, AllowInsecure: true}
	set, err := insecureFetcher.Fetch(context.Background(), aliasURL)
	if err != nil {
		t.Fatalf("insecure fetcher: %v", err)
	}
	if got := len(set.Keys); got != 1 {
		t.Fatalf("insecure fetcher: got %d keys, want 1", got)
	}
	if got := set.Keys[0].Kid; got != "demo" {
		t.Fatalf("insecure fetcher: kid = %q, want demo", got)
	}
}

// rewriteTransport routes every request to target, preserving the
// original Host header so the test stays observable. Used by the
// AllowInsecure non-loopback test to simulate a docker-compose
// network alias without standing up a privileged listener.
type rewriteTransport struct {
	target string
}

func (r *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetURL, err := requestURLForTarget(r.target, req)
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.URL = targetURL
	clone.Host = req.URL.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func requestURLForTarget(target string, req *http.Request) (*url.URL, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	out := *req.URL
	out.Scheme = base.Scheme
	out.Host = base.Host
	return &out, nil
}

// TestFetchPropagatesHTTPError — non-2xx status maps to ErrFetch.
func TestFetchPropagatesHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	fetcher := &jwks.HTTPFetcher{Client: srv.Client()}
	_, err := fetcher.Fetch(context.Background(), srv.URL)
	if !errors.Is(err, jwks.ErrFetch) || !strings.Contains(err.Error(), "404") {
		t.Fatalf("err = %v, want ErrFetch with status 404", err)
	}
}

// --- ye6f-21 / g32u — use=verify vs use=revoke filtering --------------------

// TestResolveSkipsRevokeEntries — Resolve (default = use=verify) MUST NOT
// return a revocation key, even when the kid matches. The compromise model
// in ADR-003 §5c depends on this: a revocation-only key signing a biscuit
// would re-couple the revocation path to the signing path.
func TestResolveSkipsRevokeEntries(t *testing.T) {
	revokeOnly, _ := newOKPEntryWithUse(t, "examplenews.revoke.2026", "2026-01-01T00:00:00Z", "revoke")
	set, err := jwks.Parse(encodeJWKS(revokeOnly))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := jwks.Resolve(set, "examplenews.revoke.2026"); !errors.Is(err, jwks.ErrUnknownKID) {
		t.Fatalf("Resolve(revoke kid) err = %v, want ErrUnknownKID", err)
	}
	if _, err := jwks.Resolve(set, ""); !errors.Is(err, jwks.ErrUnknownKID) {
		t.Fatalf("Resolve(empty kid, revoke-only set) err = %v, want ErrUnknownKID", err)
	}
}

// TestResolveRevokeRejectsVerifyKey — ResolveRevoke MUST refuse a key whose
// `use` is verify (or the legacy default sig/empty). A revocation-list
// verifier that called ResolveRevoke with the issuer's signing kid would
// otherwise be tricked into accepting a list signed by the verify key,
// defeating the dedicated-key separation in ADR-003 §5c.
func TestResolveRevokeRejectsVerifyKey(t *testing.T) {
	verify, _ := newOKPEntryWithUse(t, "examplenews.sub.2026q2", "2026-01-01T00:00:00Z", "verify")
	legacy, _ := newOKPEntryWithUse(t, "legacy.sig", "", "sig")
	empty, _ := newOKPEntryWithUse(t, "no.use", "", "")
	set, err := jwks.Parse(encodeJWKS(verify, legacy, empty))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, kid := range []string{"examplenews.sub.2026q2", "legacy.sig", "no.use", ""} {
		if _, err := jwks.ResolveRevoke(set, kid); !errors.Is(err, jwks.ErrUnknownKID) {
			t.Fatalf("ResolveRevoke(%q) err = %v, want ErrUnknownKID", kid, err)
		}
	}
}

// TestResolveAndResolveRevokeOnMixedSet — a JWKS that publishes both
// use=verify and use=revoke entries (the conventional issuer layout per
// ramp-protocol §1.1) routes each kid to its dedicated resolver.
func TestResolveAndResolveRevokeOnMixedSet(t *testing.T) {
	verify, verifyPub := newOKPEntryWithUse(t, "examplenews.sub.2026q2", "2026-01-01T00:00:00Z", "verify")
	revoke, revokePub := newOKPEntryWithUse(t, "examplenews.revoke.2026", "2026-01-01T00:00:00Z", "revoke")
	set, err := jwks.Parse(encodeJWKS(verify, revoke))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	gotVerify, err := jwks.Resolve(set, "examplenews.sub.2026q2")
	if err != nil {
		t.Fatalf("Resolve verify kid: %v", err)
	}
	if !gotVerify.PublicKey.Equal(verifyPub) {
		t.Errorf("Resolve returned wrong pubkey")
	}

	gotRevoke, err := jwks.ResolveRevoke(set, "examplenews.revoke.2026")
	if err != nil {
		t.Fatalf("ResolveRevoke revoke kid: %v", err)
	}
	if !gotRevoke.PublicKey.Equal(revokePub) {
		t.Errorf("ResolveRevoke returned wrong pubkey")
	}

	// Cross-resolver lookups MUST fail — verify resolver rejects the revoke
	// kid and revoke resolver rejects the verify kid.
	if _, err := jwks.Resolve(set, "examplenews.revoke.2026"); !errors.Is(err, jwks.ErrUnknownKID) {
		t.Fatalf("Resolve(revoke kid) err = %v, want ErrUnknownKID", err)
	}
	if _, err := jwks.ResolveRevoke(set, "examplenews.sub.2026q2"); !errors.Is(err, jwks.ErrUnknownKID) {
		t.Fatalf("ResolveRevoke(verify kid) err = %v, want ErrUnknownKID", err)
	}
}

// TestRevocationListSignedWithVerifyKeyIsRejected — focused unit test
// modeling the revocation-list verifier's expected gate: when a
// revocation-list response carries a signing_kid that resolves to a
// use=verify entry in the issuer's JWKS, ResolveRevoke MUST refuse it. The
// dedicated revocation-list-signer service that signs lists end-to-end
// lands with ye6f-19; this test asserts the JWKS-side invariant that
// service will rely on. TODO(ye6f-19): replace with an integration test
// that round-trips a signed list through the verifier.
func TestRevocationListSignedWithVerifyKeyIsRejected(t *testing.T) {
	verify, _ := newOKPEntryWithUse(t, "examplenews.sub.2026q2", "2026-01-01T00:00:00Z", "verify")
	set, err := jwks.Parse(encodeJWKS(verify))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// Simulate the revocation-list verifier flow: list claims signing_kid =
	// "examplenews.sub.2026q2" (i.e. the signer used the issuer's verify key).
	// ResolveRevoke MUST refuse so the verifier rejects the list before
	// ever calling ed25519.Verify.
	_, err = jwks.ResolveRevoke(set, "examplenews.sub.2026q2")
	if !errors.Is(err, jwks.ErrUnknownKID) {
		t.Fatalf("revocation-list verifier accepted verify-key signature: err = %v, want ErrUnknownKID", err)
	}
}

// TestResolveRevokePicksMostRecentRevoke — when no kid is named, the most
// recent revoke entry wins, mirroring Resolve's pick-most-recent behavior
// for verify entries. This matters during revocation-key rotation: an
// issuer that just published a new use=revoke kid expects the next list
// fetch to use it without touching every verifier's pinned config.
func TestResolveRevokePicksMostRecentRevoke(t *testing.T) {
	verify, _ := newOKPEntryWithUse(t, "examplenews.sub.2026q2", "2026-01-01T00:00:00Z", "verify")
	older, _ := newOKPEntryWithUse(t, "examplenews.revoke.2025", "2025-01-01T00:00:00Z", "revoke")
	newer, newerPub := newOKPEntryWithUse(t, "examplenews.revoke.2026", "2026-04-01T00:00:00Z", "revoke")
	set, err := jwks.Parse(encodeJWKS(verify, older, newer))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, err := jwks.ResolveRevoke(set, "")
	if err != nil {
		t.Fatalf("ResolveRevoke: %v", err)
	}
	if got.Kid != "examplenews.revoke.2026" {
		t.Errorf("kid = %q, want examplenews.revoke.2026", got.Kid)
	}
	if !got.PublicKey.Equal(newerPub) {
		t.Errorf("pubkey mismatch")
	}
}
