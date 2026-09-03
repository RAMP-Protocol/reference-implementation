//go:build integration

package transport_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauthserver"
)

// Fast-tier negatives that do NOT require a genuine upstream login: they reject
// before the upstream is ever called, drive the one failure mode a real Zitadel
// cannot stage on demand, or need a steerable clock the real tier cannot use.
// Negatives reachable only THROUGH a successful login live in
// authflow_zitadel_test.go against a real Zitadel.

func TestAuthFlow_AuthorizeRejectsUnregisteredRedirect(t *testing.T) {
	f := newAuthFixture(t)
	_, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// A loopback URL that is well-formed but was never registered for this client
	// must be refused outright — no redirect, no leaked code, upstream never called.
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID},
		"redirect_uri": {"http://127.0.0.1:9999/evil"}, "state": {"s"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	r := f.getAuthorize(t, q)
	if r.status != http.StatusBadRequest {
		t.Fatalf("authorize with unregistered redirect = %d, want 400", r.status)
	}
	if r.location != "" {
		t.Fatalf("a rejected authorize must not redirect; got Location %q", r.location)
	}
	// The reject happens before the upstream leg is built, so AuthCodeURL — which
	// records the state on the fake — was never called.
	if up, ok := f.up.(*fakeUpstream); ok && up.state != "" {
		t.Fatalf("upstream was contacted despite the unregistered redirect (state %q)", up.state)
	}
}

func TestAuthFlow_CallbackRejectsUpstreamFailure(t *testing.T) {
	f := newFailingUpstreamFixture(t)
	_, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// The upstream (Zitadel) exchange fails; the callback must surface an error,
	// not redirect, and provision no developer identity. This is the case a real,
	// well-behaved Zitadel cannot reproduce, so it keeps the fake.
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusBadGateway {
		t.Fatalf("callback on upstream failure = %d, want 502", cb.status)
	}
	if cb.location != "" {
		t.Fatalf("a failed callback must not redirect; got Location %q", cb.location)
	}
	f.noDeveloperProvisioned(t)
}

func TestAuthFlow_CallbackRejectsStateMismatch(t *testing.T) {
	f := newAuthFixture(t)
	_, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// Authorize to seal the flow cookie (the client jar keeps it), then return to
	// /callback with a state that does not match the sealed upstream state — the
	// CSRF / session-binding control the ticket names as "bad state". The sealed
	// state is server-minted randomness, so any fixed value here mismatches.
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {flowClientURI},
		"state": {"cli-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if ar := f.getAuthorize(t, q); ar.status != http.StatusFound {
		t.Fatalf("authorize = %d, want 302", ar.status)
	}

	cb := url.Values{"code": {"upstream-code"}, "state": {"not-the-sealed-state"}}
	creq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		f.srv.URL+oauthserver.CallbackPath+"?"+cb.Encode(), nil)
	r := f.do(t, creq)
	if r.status != http.StatusBadRequest {
		t.Fatalf("callback with mismatched state = %d, want 400", r.status)
	}
	if r.location != "" {
		t.Fatalf("a state-mismatch callback must not redirect; got Location %q", r.location)
	}
	f.noDeveloperProvisioned(t)
}

func TestAuthFlow_TokenCodeIsSingleUse(t *testing.T) {
	f := newAuthFixture(t)
	clientID, verifier := f.driveToConsent(t)

	code := f.grantCode(t)

	// First redemption succeeds (peek -> validate -> consume -> mint); the replay
	// must be rejected because the code is now spent. Exercises the grant service's
	// validate-before-consume order end-to-end on the always-run fast tier.
	if first := f.exchangeToken(t, code, verifier, clientID); first.status != http.StatusOK {
		t.Fatalf("first token exchange = %d, want 200", first.status)
	}
	second := f.exchangeToken(t, code, verifier, clientID)
	if second.status != http.StatusBadRequest || !strings.Contains(string(second.body), "invalid_grant") {
		t.Fatalf("code replay = %d body %s, want 400 invalid_grant", second.status, second.body)
	}
}

func TestAuthFlow_TokenRejectsWrongPKCEVerifier(t *testing.T) {
	f := newAuthFixture(t)
	clientID, verifier := f.driveToConsent(t)
	code := f.grantCode(t)

	// Redeem with a verifier that does not match the challenge sent at /authorize:
	// PKCE — the OAuth server's code-interception defense — must reject with
	// invalid_grant. This branch is otherwise exercised only by the nightly zitadel
	// tier, so a PKCE regression would pass make test-integration undetected.
	wrongVerifier, _ := pkcePair(t)
	if bad := f.exchangeToken(t, code, wrongVerifier, clientID); bad.status != http.StatusBadRequest ||
		!strings.Contains(string(bad.body), "invalid_grant") {
		t.Fatalf("wrong-verifier redeem = %d body %s, want 400 invalid_grant", bad.status, bad.body)
	}
	// The grant validates PKCE BEFORE it burns the code, so the failed attempt must
	// not have consumed it — the legitimate client still redeems it with the correct
	// verifier. (A stolen code presented with a wrong verifier cannot burn the real
	// client's code.)
	if ok := f.exchangeToken(t, code, verifier, clientID); ok.status != http.StatusOK {
		t.Fatalf("correct-verifier redeem after a failed PKCE attempt = %d, want 200 (code not burned)", ok.status)
	}
}

func TestAuthFlow_TokenRejectsExpiredCode(t *testing.T) {
	const codeTTL = 2 * time.Minute
	f, clk := newExpiredCodeFixture(t, codeTTL)
	clientID, verifier := f.driveToConsent(t)

	code := f.grantCode(t)

	// Advance the auth server's clock past the code's TTL, then redeem it: the
	// expiry branch (distinct from replay) must reject with 400 invalid_grant and
	// mint no token.
	clk.Advance(codeTTL + time.Second)

	tok := f.exchangeToken(t, code, verifier, clientID)
	if tok.status != http.StatusBadRequest {
		t.Fatalf("expired-code exchange = %d, want 400", tok.status)
	}
	if !strings.Contains(string(tok.body), "invalid_grant") {
		t.Errorf("token error = %s, want invalid_grant (expired)", tok.body)
	}
}

func TestAuthFlow_CallbackRejectsUpstreamDenial(t *testing.T) {
	f := newAuthFixture(t)
	_, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// Authorize to seal the flow cookie; the fake records the server-minted upstream
	// state so the callback's state check passes and we reach the denial branch.
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {flowClientURI},
		"state": {"cli-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	if ar := f.getAuthorize(t, q); ar.status != http.StatusFound {
		t.Fatalf("authorize = %d, want 302", ar.status)
	}
	up, ok := f.up.(*fakeUpstream)
	if !ok {
		t.Fatal("expected the fake upstream fixture")
	}

	// The user denies consent at Zitadel: the upstream redirects to /callback with
	// error=access_denied. The handler must send a fixed access_denied back to the
	// client — not reflect the raw upstream string — and provision no developer.
	cb := url.Values{"error": {"access_denied"}, "state": {up.state}}
	creq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet,
		f.srv.URL+oauthserver.CallbackPath+"?"+cb.Encode(), nil)
	r := f.do(t, creq)
	if r.status != http.StatusFound {
		t.Fatalf("consent-denial callback = %d, want 302", r.status)
	}
	loc, err := url.Parse(r.location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if !strings.HasPrefix(r.location, flowClientURI) {
		t.Fatalf("denial redirect = %q, want back to the client %q", r.location, flowClientURI)
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Fatalf("denial error param = %q, want access_denied", got)
	}
	f.noDeveloperProvisioned(t)
}

func TestAuthFlow_ConsentDenialYieldsAccessDenied(t *testing.T) {
	f := newAuthFixture(t)
	f.driveToConsent(t)

	// DENY: the developer refuses the requesting client, so the server must return
	// access_denied to the client and issue no authorization code.
	r := f.decideConsent(t, consentDeny)
	if r.status != http.StatusFound {
		t.Fatalf("consent deny = %d, want 302", r.status)
	}
	loc, err := url.Parse(r.location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if !strings.HasPrefix(r.location, flowClientURI) {
		t.Fatalf("deny redirect = %q, want back to the client %q", r.location, flowClientURI)
	}
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Fatalf("deny error param = %q, want access_denied", got)
	}
	if code := loc.Query().Get("code"); code != "" {
		t.Fatalf("a denied consent must not issue a code; got %q", code)
	}
}

func TestAuthFlow_ConsentRejectsMissingCSRF(t *testing.T) {
	f := newAuthFixture(t)
	f.driveToConsent(t)

	// POST an approval WITHOUT the CSRF token — the cross-site approval a phisher
	// could auto-submit. It must be rejected outright, with no code issued.
	r := f.postConsent(t, url.Values{consentField: {consentApprove}}.Encode())
	if r.status != http.StatusBadRequest {
		t.Fatalf("consent approve without CSRF = %d, want 400", r.status)
	}
	if r.location != "" {
		t.Fatalf("a rejected consent must not redirect; got Location %q", r.location)
	}
	// Rejecting the forged POST must not also destroy the developer's in-flight
	// sign-in. handleConsentPost spends the pending session only after
	// readPendingPOST returns, so a clearCookie added to the CSRF branch would be
	// invisible to the status and Location checks above: the developer would be
	// sent back to the start by a request they never made. Their own approval
	// still has to work.
	f.grantCode(t)
}

// TestAuthFlow_ConsentWithoutSessionRejected drives the branch where the sealed
// pending cookie is absent altogether, which readPendingPOST's CSRF check never
// reaches: it fails at readSealed, one step earlier. The GET render runs no CSRF
// check at all, so this is the only assertion covering it.
//
// A real developer is driven to the consent screen first, and the two refusal
// probes then come from a client with no cookies. That ordering is what makes the
// leak assertions worth making: the server holds a pending sign-up for a known
// subdomain, so a response that named it would be naming a real one. Against an
// empty server there is no subdomain in play at all and the same assertions pass
// whatever the handler does.
//
// The final check is deliberately the other way round. It comes back from the
// developer's own cookie-carrying client, because only the client holding the
// session can show the session survived the stranger's rejected approval.
//
// Both legs assert the refusal message, not only the status. /consent answers a
// missing session from two places — handleConsentGet for the render and
// readPendingPOST for the submission — and one route must not answer the same
// failure two different ways.
func TestAuthFlow_ConsentWithoutSessionRejected(t *testing.T) {
	f := newAuthFixture(t)
	f.driveToConsent(t)

	greq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, f.srv.URL+oauthserver.ConsentPath, nil)
	g := f.doAsStranger(t, greq)
	if g.status != http.StatusBadRequest {
		t.Fatalf("GET /consent with no session = %d, want 400", g.status)
	}
	if !strings.Contains(string(g.body), noSessionRefusal) {
		t.Errorf("GET /consent with no session answered %q, want %q", g.body, noSessionRefusal)
	}
	if strings.Contains(string(g.body), f.subdomain) {
		t.Errorf("the no-session render named subdomain %q; a caller with no session "+
			"must learn nothing about who signed up", f.subdomain)
	}

	pr := f.doAsStranger(t, f.newConsentPOST(t, url.Values{consentField: {consentApprove}}.Encode()))
	if pr.status != http.StatusBadRequest {
		t.Fatalf("POST /consent with no session = %d, want 400", pr.status)
	}
	if !strings.Contains(string(pr.body), noSessionRefusal) {
		t.Errorf("POST /consent with no session answered %q, want %q — the render and the "+
			"submission must refuse a missing session in the same words", pr.body, noSessionRefusal)
	}
	if strings.Contains(string(pr.body), f.subdomain) {
		t.Errorf("the no-session refusal named subdomain %q; a caller with no session "+
			"must learn nothing about who signed up", f.subdomain)
	}
	if pr.location != "" {
		t.Fatalf("a sessionless approval must not redirect; got Location %q — a redirect "+
			"here is an authorization code leaving with no session behind it", pr.location)
	}
	// The stranger's rejected approval must not have spent the developer's own
	// session. grantCode drives both halves of that claim: it re-renders the
	// consent screen to scrape the CSRF token, then approves and requires the code
	// in the redirect. Re-rendering alone is a weaker check — it passes with code
	// issuance broken, and the session this asserts survives exists to issue one.
	f.grantCode(t)
}

// TestAuthFlow_ConsentRejectsMalformedBody drives the parse failure, which sits
// BEFORE the CSRF check in readPendingPOST and so is unreachable from the
// missing-token test. The body is malformed rather than merely wrong on purpose:
// a wrong-but-parseable body would be refused one step later, by the CSRF check.
//
// The message is asserted, not just the status, and that is the whole difficulty
// here. Both branches answer 400 with no Location, because a body that will not
// parse also yields an empty CSRF field — so a status-only assertion passes with
// the parse check deleted, and proves nothing about the branch it names. Deleting
// the check makes this test fail; a status-only version stayed green.
func TestAuthFlow_ConsentRejectsMalformedBody(t *testing.T) {
	f := newAuthFixture(t)
	f.driveToConsent(t)

	r := f.postConsent(t, "%zz")
	if r.status != http.StatusBadRequest {
		t.Fatalf("malformed consent body = %d, want 400", r.status)
	}
	if !strings.Contains(string(r.body), "malformed submission") {
		t.Fatalf("malformed consent body answered %q, want the parse refusal — a body that "+
			"cannot be parsed must be refused at parse time, not fall through to the CSRF "+
			"check and be refused for the wrong reason", r.body)
	}
	if r.location != "" {
		t.Fatalf("a rejected consent must not redirect; got Location %q", r.location)
	}

	// The rejection must not have spent the session: a well-formed approval still
	// works. Without this the test would also pass if readPendingPOST cleared the
	// pending cookie before validating the body, which would turn a typo into a
	// sign-in the developer has to start over.
	f.grantCode(t)
}

func TestAuthFlow_RegisterRejectsBadRedirectURIs(t *testing.T) {
	f := newAuthFixture(t)
	// The open-redirect guard: DCR must reject any redirect_uri that is not https or a
	// loopback http URL, and must reject a fragment — the exact predicate the gosec
	// G710 exclusion trusts.
	for _, bad := range []string{
		"myapp://cb",             // custom (non-http/https) scheme
		"http://evil.com/cb",     // non-loopback http host
		"https://x.example/cb#f", // carries a fragment
	} {
		body := `{"redirect_uris":["` + bad + `"],"client_name":"x"}`
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost,
			f.srv.URL+oauthserver.RegisterPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r := f.do(t, req)
		if r.status != http.StatusBadRequest {
			t.Errorf("register %q = %d, want 400", bad, r.status)
		}
		if !strings.Contains(string(r.body), "invalid_redirect_uri") {
			t.Errorf("register %q body = %s, want invalid_redirect_uri", bad, r.body)
		}
	}
}

func TestAuthFlow_AuthorizeRejectsBadParams(t *testing.T) {
	f := newAuthFixture(t)
	_, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// Once the client and redirect_uri are trusted, a malformed request is reported by
	// redirecting to the client with an OAuth error (RFC 6749 §4.1.2.1), not a 400 —
	// and the upstream is never contacted for a request that cannot proceed.
	cases := []struct {
		name    string
		params  url.Values
		wantErr string
	}{
		{
			"unsupported response_type",
			url.Values{
				"response_type": {"token"}, "client_id": {clientID}, "redirect_uri": {flowClientURI},
				"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
			},
			"unsupported_response_type",
		},
		{
			"missing code_challenge",
			url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {flowClientURI}, "state": {"s"}},
			"invalid_request",
		},
		{
			"non-S256 challenge method",
			url.Values{
				"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {flowClientURI},
				"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"plain"},
			},
			"invalid_request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := f.getAuthorize(t, tc.params)
			if r.status != http.StatusFound {
				t.Fatalf("authorize (%s) = %d, want 302 error redirect", tc.name, r.status)
			}
			loc, err := url.Parse(r.location)
			if err != nil {
				t.Fatalf("parse location: %v", err)
			}
			if !strings.HasPrefix(r.location, flowClientURI) {
				t.Fatalf("%s redirect = %q, want back to the client", tc.name, r.location)
			}
			if got := loc.Query().Get("error"); got != tc.wantErr {
				t.Errorf("%s error = %q, want %q", tc.name, got, tc.wantErr)
			}
			if up, ok := f.up.(*fakeUpstream); ok && up.state != "" {
				t.Errorf("%s: upstream was contacted for a malformed request (state %q)", tc.name, up.state)
			}
		})
	}
}

func TestAuthFlow_AuthorizeRejectsUnknownClient(t *testing.T) {
	f := newAuthFixture(t)
	_, challenge := pkcePair(t)

	// No /register: this client_id was never registered. Until the client is trusted
	// no error may be redirected, so it is a plain 400, not a redirect.
	r := f.getAuthorize(t, url.Values{
		"response_type": {"code"}, "client_id": {"mcp-never-registered"}, "redirect_uri": {flowClientURI},
		"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
	})
	if r.status != http.StatusBadRequest {
		t.Fatalf("authorize with unknown client = %d, want 400", r.status)
	}
	if r.location != "" {
		t.Fatalf("an unknown client must not redirect; got %q", r.location)
	}
}

func TestAuthFlow_TokenRejectsBindingMismatch(t *testing.T) {
	f := newAuthFixture(t)
	clientID, verifier := f.driveToConsent(t)
	code := f.grantCode(t)

	base := func() url.Values {
		return url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {flowClientURI},
			"client_id": {clientID}, "code_verifier": {verifier},
		}
	}
	// A code is bound to the client and the exact redirect_uri it was issued for.
	// Redeeming under a different client_id is the binding that stops a code stolen
	// from client A being redeemed by client B; a different redirect_uri is refused too.
	wrongClient := base()
	wrongClient.Set("client_id", "mcp-someone-else")
	if r := f.postToken(t, wrongClient); r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "invalid_grant") {
		t.Fatalf("wrong client_id redeem = %d body %s, want 400 invalid_grant", r.status, r.body)
	}
	wrongRedirect := base()
	wrongRedirect.Set("redirect_uri", "http://127.0.0.1:5599/other")
	if r := f.postToken(t, wrongRedirect); r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "invalid_grant") {
		t.Fatalf("wrong redirect_uri redeem = %d body %s, want 400 invalid_grant", r.status, r.body)
	}
	// Both mismatches are checked before the burn, so the code survives for the real
	// client — a stolen-then-fumbled code cannot deny the legitimate holder.
	if r := f.postToken(t, base()); r.status != http.StatusOK {
		t.Fatalf("legitimate redeem after mismatch attempts = %d, want 200 (code not burned)", r.status)
	}
}

func TestAuthFlow_TokenRejectsMalformedRequests(t *testing.T) {
	f := newAuthFixture(t)
	cases := []struct {
		name    string
		vals    url.Values
		wantErr string
	}{
		{"unsupported grant_type", url.Values{"grant_type": {"password"}, "code": {"x"}, "code_verifier": {"y"}}, "unsupported_grant_type"},
		{"missing code", url.Values{"grant_type": {"authorization_code"}, "code_verifier": {"y"}}, "invalid_request"},
		{"missing code_verifier", url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := f.postToken(t, tc.vals)
			if r.status != http.StatusBadRequest {
				t.Fatalf("%s = %d, want 400", tc.name, r.status)
			}
			if !strings.Contains(string(r.body), tc.wantErr) {
				t.Errorf("%s body = %s, want %s", tc.name, r.body, tc.wantErr)
			}
		})
	}

	// A body that will not URL-decode must be rejected at parse time.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost,
		f.srv.URL+oauthserver.TokenPath, strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r := f.do(t, req); r.status != http.StatusBadRequest || !strings.Contains(string(r.body), "invalid_request") {
		t.Fatalf("malformed token body = %d body %s, want 400 invalid_request", r.status, r.body)
	}
}

func TestAuthFlow_CallbackServesUnavailableOnKeystoreOutage(t *testing.T) {
	f := newKeystoreOutageFixture(t)
	_, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// Provisioning mints the agent's first key via the Vault keystore. With custody
	// unavailable, SignIn returns a wrapped keystore.ErrUnavailable and /callback must
	// answer a retryable 503 (the cross-backend outage mapping), not a bare 500.
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusServiceUnavailable {
		t.Fatalf("callback with keystore unavailable = %d, want 503", cb.status)
	}
	if cb.location != "" {
		t.Fatalf("a failed callback must not redirect; got %q", cb.location)
	}
}
