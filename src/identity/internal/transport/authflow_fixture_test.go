//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauthserver"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/session"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

// Shared driving harness for the sign-up flow, exercised over HTTP exactly as an
// MCP client's OAuth machinery would (DCR -> authorize -> [upstream] -> callback
// -> consent -> token), against the real wired server (real Postgres + Vault). The
// upstream leg is pluggable via the fixture's drive func: the fast integration
// tier fakes it at the oidcup.Authenticator port (deterministic, no container),
// and the `zitadel` tier drives a REAL Zitadel through a headless login. Success
// is the provisioning outcome — keys + card served on the minted subdomain, and
// the developer's own row readable behind them — observed through the service's
// own read surfaces. Per project doctrine the fake survives only for what a real Zitadel
// cannot stage on demand (an upstream-exchange failure); everything reachable
// through a genuine login runs against Zitadel in authflow_zitadel_test.go.

const (
	// The label the fixture's slug generator mints first, so f.subdomain names the
	// identity the first sign-up in a test provisions. It is countedSlug(1) spelled
	// out, and the consent-render assertions fail if the two ever drift.
	flowSlug      = "agent-flow0001"
	flowClientURI = "http://127.0.0.1:5599/callback"

	// The consent form's controls as they go over the wire: the decision field with
	// its two values, and the hidden CSRF field. These tests are a black-box package
	// driving the server over HTTP, so they spell each name the way a browser submits
	// it rather than reaching into the handler's unexported constants — and they use
	// the handler's own names for them, so one grep finds both copies.
	consentField   = "decision"
	consentApprove = "approve"
	consentDeny    = "deny"
	csrfField      = "csrf_token"

	// The refusal both /consent legs answer when the sealed pending cookie is
	// missing — handleConsentGet for the render, readPendingPOST for the
	// submission.
	noSessionRefusal = "no active sign-in session"
)

// csrfInputRe extracts the hidden CSRF token the consent screen renders, so a
// submit carries it the way a real browser would.
var csrfInputRe = regexp.MustCompile(`name="` + csrfField + `"\s+value="([^"]*)"`)

// fakeUpstream stands in for Zitadel: it records the leg parameters /authorize
// hands it and returns canned claims on exchange, checking the nonce the way the
// real verifier would.
type fakeUpstream struct {
	state, nonce, challenge string
	claims                  oidcup.Claims
}

func (f *fakeUpstream) AuthCodeURL(state, nonce, challenge string) string {
	f.state, f.nonce, f.challenge = state, nonce, challenge
	return "https://idp.example/authorize?state=" + url.QueryEscape(state)
}

func (f *fakeUpstream) Exchange(_ context.Context, _, _, nonce string) (oidcup.Claims, error) {
	if nonce != f.nonce {
		return oidcup.Claims{}, oidcup.ErrExchange
	}
	return f.claims, nil
}

// failingUpstream records the leg like the fake but always fails the exchange, so
// a test can drive handleCallback's upstream-failure branch — the one case a
// real, well-behaved Zitadel cannot produce on demand.
//
// It asserts the SAME identity the successful fake does, and returns those claims
// beside the error. That is what makes the negative able to fail. The assertion
// this branch's test makes is noDeveloperProvisioned, which looks the identity up
// by (issuer, subject) — so an upstream asserting nothing means the lookup asks
// for a row with an empty issuer and an empty subject, and no row can carry that.
// Add a leaked SignIn to the upstream-failure branch and the row would land under
// ("", "") while the query kept asking for the stub pair: the leak passes.
//
// handleCallback discards the claims on its error branch, so returning them
// changes nothing that passes today. It only closes the gap between what the
// assertion looks for and what a regression would write.
type failingUpstream struct{ state string }

func (f *failingUpstream) AuthCodeURL(state, _, _ string) string {
	f.state = state
	return "https://idp.example/authorize?state=" + url.QueryEscape(state)
}

func (f *failingUpstream) Exchange(context.Context, string, string, string) (oidcup.Claims, error) {
	return oidcup.Claims{Issuer: stubUpstreamIssuer, Subject: stubUpstreamSubject}, oidcup.ErrExchange
}

type fixedSlug struct{ v string }

func (s fixedSlug) New() (string, error) { return s.v, nil }

// countingSlug hands out a distinct label per call, starting at flowSlug. Sign-up
// asks for a slug only when it is reserving a NEW account, so which subdomain a
// flow lands on separates "resolved the account this developer already has" from
// "minted a second one". fixedSlug cannot make that distinction: every account it
// mints carries the same string, and a second developer signing up under it
// collides until reserve runs out of attempts.
type countingSlug struct{ n int }

func (s *countingSlug) New() (string, error) {
	s.n++
	return countedSlug(s.n), nil
}

func countedSlug(n int) string { return fmt.Sprintf("agent-flow%04d", n) }

type authFixture struct {
	srv       *httptest.Server
	client    *http.Client
	tokens    *token.Issuer
	devs      *repo.PgxDeveloperRepo
	up        oidcup.Authenticator
	subdomain string
	// seen carries the identity the upstream asserted, filled in by the recording
	// wrapper the server was actually built with. f.up stays the bare upstream so
	// the negatives can still reach the fake's recorded state.
	seen *upstreamIdentity
	// drive completes the upstream leg: given the /authorize 302 Location it
	// returns the code + state the client presents to /callback. The fake tiers
	// synthesize it; the real tier runs a headless Zitadel login.
	drive func(t *testing.T, authorizeLoc string) (code, state string)
}

// authServerOpts tunes the auth server the fixture wires. The zero value drives
// the everyday flow with a wall clock and the server's default code TTL; the
// expired-code negative overrides clk + codeTTL to advance time deterministically,
// and the keystore-outage negative overrides keyMount to point custody at a mount
// that does not exist so every keystore op fails with keystore.ErrUnavailable.
type authServerOpts struct {
	clk      clock.Clock
	codeTTL  time.Duration
	keyMount string
	// slugs overrides the subdomain generator, which defaults to the fixed label
	// every flow test but the returning-developer one wants.
	slugs signup.SlugGen
}

// buildAuthFixture wires the real server through the production composition root
// (app.Build) with the given upstream authenticator and drive func — so the tests
// drive the exact wiring cmd/server ships, not a hand-rolled subset. Callers pick
// fake vs real upstream; everything else is identical, so the flow assertions are
// shared across tiers.
func buildAuthFixture(
	t *testing.T, up oidcup.Authenticator,
	drive func(t *testing.T, authorizeLoc string) (string, string), opts authServerOpts,
) *authFixture {
	t.Helper()
	ctx := t.Context()
	if err := sharedVault.Reset(ctx); err != nil {
		t.Fatalf("reset vault: %v", err)
	}
	pool := acquireTestDB(t, ctx)

	mount := sharedVault.Mount
	if opts.keyMount != "" {
		mount = opts.keyMount
	}
	store, err := keystore.NewVaultStore(keystore.Config{Client: sharedVault.Client, Mount: mount, Clk: clock.System{}})
	if err != nil {
		t.Fatalf("new vault store: %v", err)
	}
	// devs is read back directly in assertions (the documented tier-2 fallback: a
	// developer's own account row is not something any public surface exposes); the
	// server builds its own repo over the same pool inside app.Build.
	devs := repo.NewDeveloperRepo(pool)
	tokens := newTokenIssuer(t)
	seen := &upstreamIdentity{}

	// A deterministic session key keeps the fixture reproducible; the httptest server
	// is plain http, so the issuer is http and cookies are not Secure (the production
	// https-issuer path that requires Secure cookies is covered by oauthserver's own
	// config validation).
	sessionKey := make([]byte, session.KeyLen)
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}
	clk := clock.Clock(clock.System{})
	if opts.clk != nil {
		clk = opts.clk
	}
	slugs := signup.SlugGen(fixedSlug{v: flowSlug})
	if opts.slugs != nil {
		slugs = opts.slugs
	}

	handler, _, err := app.Build(app.Config{
		Pool:            pool,
		Keys:            store,
		Logger:          testutil.DiscardLogger(),
		BaseDomain:      baseZone,
		DirectoryTTL:    publisher.DefaultTTL,
		WellKnownScheme: "http",
		Clock:           clk,
		Health:          func(context.Context) error { return nil },
		Auth: &app.AuthConfig{
			Issuer:        "http://auth.rampmcp.org",
			Upstream:      &recordingUpstream{Authenticator: up, seen: seen},
			SessionKey:    sessionKey,
			Tokens:        tokens,
			Slugs:         slugs,
			SecureCookies: false,
			CodeTTL:       opts.codeTTL,
		},
		// The RAMP adapter is mandatory in app.Build, so it is wired here to keep this
		// fixture faithful to the wiring cmd/server ships. These auth-flow tests never
		// call an MCP tool; the peer URLs are unused placeholders (the RAMP client does
		// not dial at construction), so no Broker/Exchange double is needed.
		MCP: &app.MCPConfig{
			BrokerURL:       "http://broker.invalid",
			WellKnownScheme: "http",
		},
	})
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &authFixture{
		srv: srv, client: newFlowClient(true), tokens: tokens, devs: devs, up: up,
		subdomain: flowSlug + "." + baseZone, drive: drive, seen: seen,
	}
}

// The OIDC identity the deterministic fake upstream asserts.
const (
	stubUpstreamIssuer  = "https://idp.example"
	stubUpstreamSubject = "user-1"

	// A second, unrelated developer, for a test that needs two accounts on one server.
	otherUpstreamSubject = "user-2"
)

// upstreamIdentity holds the (issuer, subject) pair the upstream asserted on the
// last successful exchange. The developer repo is keyed on that pair, so this is
// how a test asks whether a developer was provisioned. What went with the account
// tools' old register payload is their USE of the by-subdomain lookup, not the
// lookup: the repository read is live production code, and the publisher calls it
// as the presence gate for an agent's commercial overlay.
//
// The pair is observed rather than assumed because it is only knowable in
// advance on the fake tiers. A real Zitadel mints its own user id, and the
// bootstrap that seeds the login user does not learn it: the import call is
// treated as successful on a 409, so a re-used instance returns no id at all.
//
// The server exchanges on the httptest handler's goroutine while the test reads
// from the test goroutine, so the pair is mutex-guarded.
type upstreamIdentity struct {
	mu      sync.Mutex
	issuer  string
	subject string
}

func (u *upstreamIdentity) record(c oidcup.Claims) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.issuer, u.subject = c.Issuer, c.Subject
}

func (u *upstreamIdentity) get() (issuer, subject string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.issuer, u.subject
}

// recordingUpstream forwards every call to the authenticator under test and keeps
// the identity of the last exchange that succeeded. A flow that never got a
// successful exchange leaves the pair empty, and the read-back below then finds
// nothing — which is exactly the answer the negatives that must provision no
// developer assert, since provisioning only happens on the claims an exchange
// returned.
type recordingUpstream struct {
	oidcup.Authenticator
	seen *upstreamIdentity
}

func (r *recordingUpstream) Exchange(ctx context.Context, code, verifier, nonce string) (oidcup.Claims, error) {
	claims, err := r.Authenticator.Exchange(ctx, code, verifier, nonce)
	if err != nil {
		return claims, err
	}
	r.seen.record(claims)
	return claims, nil
}

// developer reads back the developer the flow under test would have provisioned,
// keyed on the identity the upstream actually asserted. It is the documented
// tier-2 fallback: there is no public read surface for a developer record, so
// these assertions go through the production repository rather than the database.
//
// For a flow that SUCCEEDS. A negative must not use it — see
// noDeveloperProvisioned.
func (f *authFixture) developer(t *testing.T) (account.Developer, error) {
	t.Helper()
	issuer, subject := f.seen.get()
	return f.devs.BySubject(t.Context(), issuer, subject)
}

// noDeveloperProvisioned asserts the flow under test created no developer
// account.
//
// Keyed on the identity the fake upstream asserts, which is known BEFORE the
// flow runs. Keying it on what the upstream was OBSERVED to assert cannot fail:
// f.seen is written only after a successful exchange, and a flow that must
// provision nothing is a flow that never had one — so the pair is ("", ""), the
// query asks for a row with an empty issuer and an empty subject, and no row can
// carry that. The assertion would hold with the provisioning left in.
//
// TestAuthFlow_HappyPathProvisions is the positive control for this exact key: a
// flow that completes puts a row under it, so absence here is a real answer
// rather than a lookup that could never find anything.
func (f *authFixture) noDeveloperProvisioned(t *testing.T) {
	t.Helper()
	_, err := f.devs.BySubject(t.Context(), stubUpstreamIssuer, stubUpstreamSubject)
	if !errors.Is(err, account.ErrNotFound) {
		t.Fatalf("looking up the developer a completed flow provisions gave %v, want ErrNotFound "+
			"— this flow must provision nothing", err)
	}
}

// fakeUpstreamWith builds the deterministic fake upstream carrying the standard
// developer claims, together with the synthetic drive that ignores the authorize
// Location and returns a canned code with the state the fake recorded at /authorize.
func fakeUpstreamWith() (*fakeUpstream, func(*testing.T, string) (string, string)) {
	up := &fakeUpstream{claims: oidcup.Claims{
		Issuer: stubUpstreamIssuer, Subject: stubUpstreamSubject,
		Email: "dev@acme.example", Name: "Dev One",
	}}
	return up, func(*testing.T, string) (string, string) { return "upstream-code", up.state }
}

// newAuthFixture wires the fixture with the deterministic fake upstream.
func newAuthFixture(t *testing.T) *authFixture {
	up, drive := fakeUpstreamWith()
	return buildAuthFixture(t, up, drive, authServerOpts{})
}

// newFailingUpstreamFixture wires the fixture with an upstream whose exchange
// always fails, for the callback upstream-failure negative.
func newFailingUpstreamFixture(t *testing.T) *authFixture {
	up := &failingUpstream{}
	return buildAuthFixture(t, up, func(*testing.T, string) (string, string) {
		return "upstream-code", up.state
	}, authServerOpts{})
}

// newExpiredCodeFixture wires the fake-upstream fixture with a deterministic clock
// and a short code TTL, and returns that clock so a test can advance past the TTL
// and drive the /token expiry branch. It must use the fake upstream: a real
// Zitadel needs the wall clock for its own ID-token verification, so the code-TTL
// clock can only be steered on the fake tier.
func newExpiredCodeFixture(t *testing.T, codeTTL time.Duration) (*authFixture, *clock.DeterministicClock) {
	clk := clock.NewDeterministic(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	up, drive := fakeUpstreamWith()
	f := buildAuthFixture(t, up, drive, authServerOpts{clk: clk, codeTTL: codeTTL})
	return f, clk
}

// newKeystoreOutageFixture wires the fake-upstream fixture with custody pointed at a
// mount that does not exist, so every keystore op fails with keystore.ErrUnavailable —
// simulating a Vault outage during provisioning without a real Vault fault seam.
func newKeystoreOutageFixture(t *testing.T) *authFixture {
	up, drive := fakeUpstreamWith()
	return buildAuthFixture(t, up, drive, authServerOpts{keyMount: "nonexistent-outage-mount"})
}

func newTokenIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen token key: %v", err)
	}
	iss, err := token.NewIssuer(priv, "https://auth.rampmcp.org", "https://mcp.rampmcp.org", clock.System{})
	if err != nil {
		t.Fatalf("token.NewIssuer: %v", err)
	}
	return iss
}

// --- flow driving helpers ---

func pkcePair(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("pkce entropy: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// flowResp is the extracted result of one request. The helpers return this rather
// than *http.Response so the body is read and closed in exactly one place (do),
// which also keeps the bodyclose linter satisfied.
type flowResp struct {
	status   int
	location string
	body     []byte
}

// newFlowClient builds a client for the browser side of the flow: redirects are
// surfaced rather than followed, so a test asserts on the 302 itself. withJar
// decides whether the client carries session cookies between requests — the
// fixture's own client does, and the one a stranger test uses does not.
func newFlowClient(withJar bool) *http.Client {
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	if withJar {
		c.Jar, _ = cookiejar.New(nil)
	}
	return c
}

// do issues req as the developer whose session the fixture holds.
func (f *authFixture) do(t *testing.T, req *http.Request) flowResp {
	t.Helper()
	return f.doWith(t, f.client, req)
}

// doAsStranger issues req from a client that holds no cookies, so none of the
// sealed session state the fixture's own client was handed travels with it. It
// is how a test asks what an unrelated caller sees while a real session exists
// on the server.
func (f *authFixture) doAsStranger(t *testing.T, req *http.Request) flowResp {
	t.Helper()
	return f.doWith(t, newFlowClient(false), req)
}

func (f *authFixture) doWith(t *testing.T, client *http.Client, req *http.Request) flowResp {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return flowResp{status: resp.StatusCode, location: resp.Header.Get("Location"), body: body}
}

func (f *authFixture) register(t *testing.T, redirectURI string) string {
	t.Helper()
	body := `{"redirect_uris":["` + redirectURI + `"],"client_name":"Claude Code"}`
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+oauthserver.RegisterPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r := f.do(t, req)
	if r.status != http.StatusCreated {
		t.Fatalf("register status = %d, body %s", r.status, r.body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil {
		t.Fatalf("register decode: %v", err)
	}
	return out.ClientID
}

// authorizeThenCallback runs authorize (which stashes the flow cookie and hands
// the leg to the upstream) then completes the upstream leg via f.drive and issues
// the upstream callback, returning the callback result (a 302 to /consent, or an
// error status on upstream failure).
func (f *authFixture) authorizeThenCallback(t *testing.T, clientID, redirectURI, challenge string) flowResp {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"state": {"cli-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"scope": {"openid"},
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+oauthserver.AuthorizePath+"?"+q.Encode(), nil)
	r := f.do(t, req)
	if r.status != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", r.status)
	}
	code, state := f.drive(t, r.location)
	cb := url.Values{"code": {code}, "state": {state}}
	creq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+oauthserver.CallbackPath+"?"+cb.Encode(), nil)
	return f.do(t, creq)
}

// driveToConsent runs a fresh flow up to the consent screen and returns the
// registered client_id and the downstream PKCE verifier, so a test can pick up
// from a known-good mid-flow state.
func (f *authFixture) driveToConsent(t *testing.T) (clientID, verifier string) {
	t.Helper()
	var challenge string
	verifier, challenge = pkcePair(t)
	clientID = f.register(t, flowClientURI)
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusFound || cb.location != oauthserver.ConsentPath {
		t.Fatalf("callback = %d -> %q, want 302 -> /consent", cb.status, cb.location)
	}
	return clientID, verifier
}

// getConsent GETs the consent screen (exercising the GET /consent render) and returns
// the response together with the CSRF token scraped from the hidden field.
func (f *authFixture) getConsent(t *testing.T) (flowResp, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+oauthserver.ConsentPath, nil)
	r := f.do(t, req)
	var csrf string
	if m := csrfInputRe.FindSubmatch(r.body); m != nil {
		csrf = string(m[1])
	}
	return r, csrf
}

// decideConsent posts the given decision ("approve"/"deny") to the consent screen,
// carrying the CSRF token scraped from the rendered form.
func (f *authFixture) decideConsent(t *testing.T, decision string) flowResp {
	t.Helper()
	vals := url.Values{consentField: {decision}}
	if _, csrf := f.getConsent(t); csrf != "" {
		vals.Set(csrfField, csrf)
	}
	return f.do(t, f.newConsentPOST(t, vals.Encode()))
}

// newConsentPOST builds the POST the consent form submits, with an arbitrary body so
// the negatives can drive a malformed or unauthorized submission. It is the one
// place the request line is spelled; a header the submission later needs is added
// here and every caller sends it. The caller chooses who issues it — f.do for the
// developer holding the session, f.doAsStranger for anyone else.
func (f *authFixture) newConsentPOST(t *testing.T, body string) *http.Request {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost,
		f.srv.URL+oauthserver.ConsentPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// postConsent submits body to /consent as the developer whose session the fixture
// holds.
func (f *authFixture) postConsent(t *testing.T, body string) flowResp {
	t.Helper()
	return f.do(t, f.newConsentPOST(t, body))
}

// grantCode takes an authenticated, provisioned flow the rest of the way to the
// authorization code the client receives: approve the requesting client, then read
// the code out of the redirect. It is the one place a test spells what an approved
// consent does, so a change to that path is one edit and not one per call site.
func (f *authFixture) grantCode(t *testing.T) string {
	t.Helper()
	return codeFromRedirect(t, f.decideConsent(t, consentApprove))
}

func (f *authFixture) exchangeToken(t *testing.T, code, verifier, clientID string) flowResp {
	t.Helper()
	return f.postToken(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {flowClientURI},
		"client_id": {clientID}, "code_verifier": {verifier},
	})
}

// postToken POSTs an arbitrary url-encoded body to /token, so negative tests can drive
// the parse-level and binding-mismatch rejections exchangeToken's fixed body cannot.
func (f *authFixture) postToken(t *testing.T, vals url.Values) flowResp {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+oauthserver.TokenPath, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(t, req)
}

// getAuthorize GETs /authorize with the given query, so a test does not re-spell the
// request line; authorizeThenCallback drives the happy leg, this drives the rejections.
func (f *authFixture) getAuthorize(t *testing.T, params url.Values) flowResp {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+oauthserver.AuthorizePath+"?"+params.Encode(), nil)
	return f.do(t, req)
}

// codeFromRedirect extracts the authorization code from a 302 Location back to the
// client.
func codeFromRedirect(t *testing.T, r flowResp) string {
	t.Helper()
	if r.status != http.StatusFound {
		t.Fatalf("expected 302 to client, got %d", r.status)
	}
	loc, err := url.Parse(r.location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc)
	}
	return code
}

// assertConsentNames requires the consent screen to render, and to name the given
// subdomain — the identity this sign-in resolved to, and the one a code would be
// issued for. The e2e harness scrapes that subdomain by matching the
// id="agent-subdomain" span, so the whole fragment is asserted rather than the
// subdomain appearing somewhere: a template edit that would break the harness fails
// here first, in the always-run tier and in the language the template is written in.
func (f *authFixture) assertConsentNames(t *testing.T, want string) {
	t.Helper()
	r, _ := f.getConsent(t)
	if r.status != http.StatusOK {
		t.Fatalf("GET /consent = %d, want 200", r.status)
	}
	span := fmt.Sprintf(`<span class="sub" id="agent-subdomain">%s</span>`, want)
	if !strings.Contains(string(r.body), span) {
		t.Fatalf("consent body %s missing subdomain span %q", r.body, span)
	}
}

// assertProvisioned checks the sign-in produced a real agent identity, observed
// through the service's own read surfaces: the WBA directory, the card and the
// RAMP commercial overlay are served on the minted subdomain, and the developer
// account behind them exists.
//
// The account row is read through the developer repository — the documented
// tier-2 fallback, because a developer's own account is not something any public
// surface exposes. It is a SEPARATE effect from the three documents rather than a
// strengthening of them, and the load-bearing part is that the lookup finds a row
// at all: it is keyed on the (issuer, subject) the upstream asserted, so a row
// under that key is what shows sign-in bound THAT identity to the subdomain the
// documents are served on. The documents cannot show it — the keystore and the
// card store are both keyed by subdomain and know nothing about the upstream
// identity behind it.
func (f *authFixture) assertProvisioned(t *testing.T) {
	t.Helper()
	if status, _ := f.getForHostVia(t, f.subdomain, rampwellknown.WBAPath); status != http.StatusOK {
		t.Errorf("WBA directory status = %d, want 200 (key not published)", status)
	}
	status, cardBody := f.getForHostVia(t, f.subdomain, directory.CardPath)
	if status != http.StatusOK {
		t.Fatalf("card status = %d, want 200", status)
	}
	if !strings.Contains(string(cardBody), "https://"+f.subdomain) {
		t.Errorf("card body %s missing client_uri for %q", cardBody, f.subdomain)
	}
	f.assertManifestServed(t)
	dev, err := f.developer(t)
	if err != nil {
		t.Fatalf("developer read-back: %v", err)
	}
	if dev.Subdomain != f.subdomain {
		t.Errorf("developer = %+v, want the row behind the served card to carry subdomain %q",
			dev, f.subdomain)
	}
}

// assertManifestServed reads the RAMP commercial overlay off the minted subdomain and
// holds it to the protocol contract. The bytes go through ParseManifest rather than a
// string match, so the protocol's own schema and its role expectation gate what the
// registry publishes: a document that drifts out of shape fails here rather than
// reaching a consumer. domain is checked against the requested host because the
// overlay is derived per request — every registered agent's differs only in that
// field, so serving one agent's domain under another's host is the failure this
// document can have and the card cannot.
func (f *authFixture) assertManifestServed(t *testing.T) {
	t.Helper()
	status, body := f.getForHostVia(t, f.subdomain, rampwellknown.Path)
	if status != http.StatusOK {
		t.Fatalf("manifest status = %d, want 200", status)
	}
	m, err := rampwellknown.ParseManifest(body, rampwellknown.RoleAgent)
	if err != nil {
		t.Fatalf("served manifest invalid: %v (body %s)", err, body)
	}
	if m.GetVer() != rampwellknown.Version {
		t.Errorf("manifest ver = %q, want %q", m.GetVer(), rampwellknown.Version)
	}
	if m.GetDomain() != f.subdomain {
		t.Errorf("manifest domain = %q, want the requested host %q", m.GetDomain(), f.subdomain)
	}
}

// getForHostVia issues GET path with the given Host header, which drives well-known
// dispatch to the agent's subdomain.
func (f *authFixture) getForHostVia(t *testing.T, host, path string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+path, nil)
	req.Host = host
	r := f.do(t, req)
	return r.status, r.body
}
