//go:build integration && zitadel

package transport_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// The sign-up flow driven through the REAL oidcup.Zitadel against a real Zitadel
// v3.4.9: real OIDC discovery, a real headless login, real code exchange, and
// real JWKS ID-token + nonce verification. These are the tests that "run a real
// Zitadel instead of the mock" — everything reachable through a successful login
// lives here; only the upstream-exchange failure a real Zitadel cannot stage
// stays on the fake (authflow_negative_e2e_test.go).
//
// The flow these drive is callback -> consent -> token, with no gap: the happy
// path below covers the whole of it against a real upstream.

func TestAuthFlow_RealZitadel_HappyPath(t *testing.T) {
	f := newZitadelFixture(t)

	// Authenticate through Zitadel; the developer lands on the consent screen.
	clientID, verifier := f.driveToConsent(t)

	// Approve the requesting client; the code is released back to it.
	code := f.grantCode(t)

	// Exchange the code for a token bound to the minted subdomain.
	tok := f.exchangeToken(t, code, verifier, clientID)
	if tok.status != http.StatusOK {
		t.Fatalf("token status = %d, body %s", tok.status, tok.body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(tok.body, &out); err != nil || out.TokenType != "Bearer" {
		t.Fatalf("token body = %s (err %v)", tok.body, err)
	}
	claims, err := f.tokens.Verify(out.AccessToken)
	if err != nil || claims.Subject != f.subdomain {
		t.Fatalf("token subject = %q (err %v), want %q", claims.Subject, err, f.subdomain)
	}

	f.assertProvisioned(t)
}

func TestAuthFlow_RealZitadel_TokenRejectsWrongPKCEVerifier(t *testing.T) {
	f := newZitadelFixture(t)
	clientID, _ := f.driveToConsent(t)

	code := f.grantCode(t)

	// A verifier that does not match the challenge sent at /authorize must fail.
	wrongVerifier, _ := pkcePair(t)
	tok := f.exchangeToken(t, code, wrongVerifier, clientID)
	if tok.status != http.StatusBadRequest {
		t.Fatalf("token with wrong verifier = %d, want 400", tok.status)
	}
	if !strings.Contains(string(tok.body), "invalid_grant") {
		t.Errorf("token error = %s, want invalid_grant", tok.body)
	}
}

func TestAuthFlow_RealZitadel_CodeIsSingleUse(t *testing.T) {
	f := newZitadelFixture(t)
	clientID, verifier := f.driveToConsent(t)

	code := f.grantCode(t)

	if first := f.exchangeToken(t, code, verifier, clientID); first.status != http.StatusOK {
		t.Fatalf("first token exchange = %d, want 200", first.status)
	}
	second := f.exchangeToken(t, code, verifier, clientID)
	if second.status != http.StatusBadRequest || !strings.Contains(string(second.body), "invalid_grant") {
		t.Fatalf("code replay = %d body %s, want 400 invalid_grant", second.status, second.body)
	}
}
