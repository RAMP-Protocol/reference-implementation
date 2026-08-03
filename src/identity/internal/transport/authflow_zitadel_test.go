//go:build integration && zitadel

package transport_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauthserver"
)

// The sign-up flow driven through the REAL oidcup.Zitadel against a real Zitadel
// v3.4.9: real OIDC discovery, a real headless login, real code exchange, and
// real JWKS ID-token + nonce verification. These are the tests that "run a real
// Zitadel instead of the mock" — everything reachable through a successful login
// lives here; only the upstream-exchange failure a real Zitadel cannot stage
// stays on the fake (authflow_negative_e2e_test.go).

func TestAuthFlow_RealZitadel_HappyPath(t *testing.T) {
	f := newZitadelFixture(t)
	verifier, challenge := pkcePair(t)
	clientID := f.register(t, flowClientURI)

	// Authenticate through Zitadel; a brand-new developer is sent to the form.
	cb := f.authorizeThenCallback(t, clientID, flowClientURI, challenge)
	if cb.status != http.StatusFound || cb.location != oauthserver.FormPath {
		t.Fatalf("callback = %d -> %q, want 302 -> /form", cb.status, cb.location)
	}

	// Submit valid licensing fields; the code is released back to the client.
	code := codeFromRedirect(t, f.grantCode(t, url.Values{
		"legal_entity":         {"Acme GmbH"},
		"address":              {"1 Main St, Berlin"},
		"jurisdiction_country": {"de"},
	}))

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

func TestAuthFlow_RealZitadel_FormBlocksOnMissingField(t *testing.T) {
	// The ticket requires the form reject a submission "with any of the three
	// missing", so each field is driven through the public /form surface — not just
	// legal_entity — with the other two valid.
	cases := []struct {
		name    string
		values  url.Values
		wantErr string
	}{
		{
			"legal entity",
			url.Values{"legal_entity": {""}, "address": {"1 Main St"}, "jurisdiction_country": {"DE"}},
			"Legal entity is required",
		},
		{
			"address",
			url.Values{"legal_entity": {"Acme GmbH"}, "address": {""}, "jurisdiction_country": {"DE"}},
			"Address is required",
		},
		{
			"jurisdiction",
			url.Values{"legal_entity": {"Acme GmbH"}, "address": {"1 Main St"}, "jurisdiction_country": {""}},
			"Jurisdiction is required",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newZitadelFixture(t)
			f.driveToForm(t)

			r := f.submitForm(t, tc.values)
			if r.status != http.StatusOK {
				t.Fatalf("submit with blank %s = %d, want 200 re-render", tc.name, r.status)
			}
			if r.location != "" {
				t.Fatalf("a rejected form must not redirect; got Location %q", r.location)
			}
			if !strings.Contains(string(r.body), tc.wantErr) {
				t.Errorf("re-rendered form missing %q; body:\n%s", tc.wantErr, r.body)
			}
			if dev, err := f.devs.BySubdomain(t.Context(), f.subdomain); err != nil || dev.RegistrationComplete {
				t.Errorf("developer complete=%v (err %v) after a rejected form, want incomplete",
					dev.RegistrationComplete, err)
			}
		})
	}
}

func TestAuthFlow_RealZitadel_FormRejectsInvalidCountry(t *testing.T) {
	f := newZitadelFixture(t)
	f.driveToForm(t)

	r := f.submitForm(t, url.Values{
		"legal_entity":         {"Acme GmbH"},
		"address":              {"1 Main St"},
		"jurisdiction_country": {"ZZ"},
	})
	if r.status != http.StatusOK || r.location != "" {
		t.Fatalf("invalid-country submit = %d loc=%q, want 200 re-render", r.status, r.location)
	}
	if !strings.Contains(string(r.body), "ISO 3166-1") {
		t.Errorf("re-rendered form missing the country error; body:\n%s", r.body)
	}
	if dev, _ := f.devs.BySubdomain(t.Context(), f.subdomain); dev.RegistrationComplete {
		t.Error("registration completed despite an invalid country code")
	}
}

func TestAuthFlow_RealZitadel_TokenRejectsWrongPKCEVerifier(t *testing.T) {
	f := newZitadelFixture(t)
	clientID, _ := f.driveToForm(t)

	code := codeFromRedirect(t, f.grantCode(t, url.Values{
		"legal_entity": {"Acme GmbH"}, "address": {"1 Main St"}, "jurisdiction_country": {"DE"},
	}))

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
	clientID, verifier := f.driveToForm(t)

	code := codeFromRedirect(t, f.grantCode(t, url.Values{
		"legal_entity": {"Acme GmbH"}, "address": {"1 Main St"}, "jurisdiction_country": {"DE"},
	}))

	if first := f.exchangeToken(t, code, verifier, clientID); first.status != http.StatusOK {
		t.Fatalf("first token exchange = %d, want 200", first.status)
	}
	second := f.exchangeToken(t, code, verifier, clientID)
	if second.status != http.StatusBadRequest || !strings.Contains(string(second.body), "invalid_grant") {
		t.Fatalf("code replay = %d body %s, want 400 invalid_grant", second.status, second.body)
	}
}
