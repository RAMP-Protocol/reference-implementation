//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
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
// -> form -> token), against the real wired server (real Postgres + Vault). The
// upstream leg is pluggable via the fixture's drive func: the fast integration
// tier fakes it at the oidcup.Authenticator port (deterministic, no container),
// and the `zitadel` tier drives a REAL Zitadel through a headless login. Success
// is the provisioning outcome — keys + card served on the minted subdomain and
// the three licensing fields stored — observed through the service's own read
// surfaces. Per project doctrine the fake survives only for what a real Zitadel
// cannot stage on demand (an upstream-exchange failure); everything reachable
// through a genuine login runs against Zitadel in authflow_zitadel_test.go.

const (
	flowSlug      = "agent-flow0001"
	flowClientURI = "http://127.0.0.1:5599/callback"
)

// csrfInputRe extracts the hidden CSRF token the form renders, so a submit carries
// it the way a real browser would.
var csrfInputRe = regexp.MustCompile(`name="csrf_token"\s+value="([^"]*)"`)

// validLicensingForm is the fully-valid licensing submission the happy-path and
// single-use flows post; its values match assertProvisioned's expectations.
func validLicensingForm() url.Values {
	return url.Values{
		signup.FieldLegalEntity:  {"Acme GmbH"},
		signup.FieldAddress:      {"1 Main St"},
		signup.FieldJurisdiction: {"DE"},
	}
}

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
type failingUpstream struct{ state string }

func (f *failingUpstream) AuthCodeURL(state, _, _ string) string {
	f.state = state
	return "https://idp.example/authorize?state=" + url.QueryEscape(state)
}

func (f *failingUpstream) Exchange(context.Context, string, string, string) (oidcup.Claims, error) {
	return oidcup.Claims{}, oidcup.ErrExchange
}

type fixedSlug struct{ v string }

func (s fixedSlug) New() (string, error) { return s.v, nil }

type authFixture struct {
	srv       *httptest.Server
	client    *http.Client
	tokens    *token.Issuer
	devs      *repo.PgxDeveloperRepo
	up        oidcup.Authenticator
	subdomain string
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
	// devs is read back directly in assertions (the documented tier-2 fallback for the
	// private licensing fields the public card does not carry); the server builds its
	// own repo over the same pool inside app.Build.
	devs := repo.NewDeveloperRepo(pool)
	tokens := newTokenIssuer(t)

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
			Upstream:      up,
			SessionKey:    sessionKey,
			Tokens:        tokens,
			Slugs:         fixedSlug{v: flowSlug},
			SecureCookies: false,
			CodeTTL:       opts.codeTTL,
		},
		// The RAMP adapter is mandatory in app.Build, so it is wired here to keep this
		// fixture faithful to the wiring cmd/server ships. These auth-flow tests never
		// call an MCP tool; the peer URLs are unused placeholders (the RAMP client does
		// not dial at construction), so no Broker/Exchange double is needed.
		MCP: &app.MCPConfig{
			BrokerURL:       "http://broker.invalid",
			ExchangeURL:     "http://exchange.invalid",
			WellKnownScheme: "http",
		},
	})
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &authFixture{
		srv: srv, client: client, tokens: tokens, devs: devs, up: up,
		subdomain: flowSlug + "." + baseZone, drive: drive,
	}
}

// fakeUpstreamWith builds the deterministic fake upstream carrying the standard
// developer claims, together with the synthetic drive that ignores the authorize
// Location and returns a canned code with the state the fake recorded at /authorize.
func fakeUpstreamWith() (*fakeUpstream, func(*testing.T, string) (string, string)) {
	up := &fakeUpstream{claims: oidcup.Claims{
		Issuer: "https://idp.example", Subject: "user-1", Email: "dev@acme.example", Name: "Dev One",
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

func (f *authFixture) do(t *testing.T, req *http.Request) flowResp {
	t.Helper()
	resp, err := f.client.Do(req)
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
// the upstream callback, returning the callback result (a 302 to /form or to the
// client redirect with a code, or an error status on upstream failure).
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

// driveToForm runs a fresh flow up to the mandatory form and returns the
// registered client_id and the downstream PKCE verifier, so a test can pick up
// from a known-good mid-flow state.
func (f *authFixture) driveToForm(t *testing.T) (clientID, verifier string) {
	t.Helper()
	var challenge string
	verifier, challenge = pkcePair(t)
	clientID = f.register(t, flowClientURI)
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusFound || cb.location != oauthserver.FormPath {
		t.Fatalf("callback = %d -> %q, want 302 -> /form", cb.status, cb.location)
	}
	return clientID, verifier
}

// getForm GETs the mandatory registration form (exercising the GET /form render)
// and returns the response together with the CSRF token scraped from the hidden
// field.
func (f *authFixture) getForm(t *testing.T) (flowResp, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+oauthserver.FormPath, nil)
	r := f.do(t, req)
	var csrf string
	if m := csrfInputRe.FindSubmatch(r.body); m != nil {
		csrf = string(m[1])
	}
	return r, csrf
}

// submitForm posts the licensing form. A real browser first GETs the form (which
// carries the sealed pending cookie) and submits the CSRF token embedded in it, so
// this mirrors that: it fetches the form for the token before POSTing, which also
// exercises the GET /form render on every flow.
func (f *authFixture) submitForm(t *testing.T, vals url.Values) flowResp {
	t.Helper()
	if _, csrf := f.getForm(t); csrf != "" {
		vals.Set("csrf_token", csrf)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+oauthserver.FormPath, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(t, req)
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
	vals := url.Values{"decision": {decision}}
	if _, csrf := f.getConsent(t); csrf != "" {
		vals.Set("csrf_token", csrf)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, f.srv.URL+oauthserver.ConsentPath, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return f.do(t, req)
}

// grantCode drives the full post-authentication path to an authorization code: submit
// a valid licensing form (which now hands off to the consent screen), then approve the
// requesting client. It fails if the form does not redirect to the consent screen.
func (f *authFixture) grantCode(t *testing.T, vals url.Values) flowResp {
	t.Helper()
	if r := f.submitForm(t, vals); r.status != http.StatusFound || r.location != oauthserver.ConsentPath {
		t.Fatalf("form submit = %d -> %q, want 302 -> /consent", r.status, r.location)
	}
	return f.decideConsent(t, "approve")
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

// assertProvisioned checks the sign-in produced a real agent identity, observed
// through the service's own read surfaces: the WBA directory and card are served
// on the minted subdomain, and the three licensing fields are stored. The fields
// are not on the public card by design, so they are read back through the
// developer repository — the documented tier-2 fallback until a public read
// surface exists.
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
	dev, err := f.devs.BySubdomain(t.Context(), f.subdomain)
	if err != nil {
		t.Fatalf("developer read-back: %v", err)
	}
	if !dev.RegistrationComplete || dev.JurisdictionCountry != "DE" || dev.LegalEntity != "Acme GmbH" {
		t.Errorf("developer = %+v, want complete with normalized fields", dev)
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

// TestAuthFlow_HappyPathProvisions drives the full fast-tier flow (real Postgres +
// Vault, fake upstream) and asserts the ticket's central acceptance outcome — keys +
// card + well-known served on the minted subdomain and the three licensing fields
// captured — through the service's own read surfaces. This puts the primary
// acceptance assertion on the always-run integration gate, not only the Zitadel tier.
func TestAuthFlow_HappyPathProvisions(t *testing.T) {
	f := newAuthFixture(t)
	clientID, verifier := f.driveToForm(t)

	// GET /form renders the mandatory form with the minted subdomain shown.
	get, _ := f.getForm(t)
	if get.status != http.StatusOK {
		t.Fatalf("GET /form = %d, want 200", get.status)
	}
	if !strings.Contains(string(get.body), f.subdomain) {
		t.Errorf("form body %s missing minted subdomain %q", get.body, f.subdomain)
	}

	code := codeFromRedirect(t, f.grantCode(t, validLicensingForm()))
	if tok := f.exchangeToken(t, code, verifier, clientID); tok.status != http.StatusOK {
		t.Fatalf("token exchange = %d, want 200", tok.status)
	}
	f.assertProvisioned(t)
}

// TestAuthFlow_ReturningRegisteredDeveloperSkipsForm verifies the ticket's
// idempotency: once a developer has completed the mandatory form, a later sign-in
// for the same identity bypasses the form and issues a code directly, driving the
// callback's already-registered exit that every fresh-developer flow leaves untaken.
func TestAuthFlow_ReturningRegisteredDeveloperSkipsForm(t *testing.T) {
	f := newAuthFixture(t)
	clientID, verifier := f.driveToForm(t)
	code := codeFromRedirect(t, f.grantCode(t, validLicensingForm()))
	if tok := f.exchangeToken(t, code, verifier, clientID); tok.status != http.StatusOK {
		t.Fatalf("first exchange = %d, want 200", tok.status)
	}

	// Second sign-in for the same developer (the fake upstream returns the same
	// subject): the callback must skip the licensing /form (already registered) and
	// go straight to the consent screen, not issue a code without approval.
	_, challenge := pkcePair(t)
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusFound || cb.location != oauthserver.ConsentPath {
		t.Fatalf("returning developer callback = %d -> %q, want 302 -> /consent (form skipped)", cb.status, cb.location)
	}
	// Approving consent yields the code back to the client.
	codeFromRedirect(t, f.decideConsent(t, "approve"))
}
