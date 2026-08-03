//go:build integration && zitadel

package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// aliceUser and alicePassword are the seeded local login the headless-login
// helper drives. They are exported through HeadlessLogin's caller, not here.
const (
	aliceUser     = "alice@acme.local"
	alicePassword = "Alice12345!"
)

type zitadelCreds struct {
	clientID     string
	clientSecret string
}

// bootstrapZitadel provisions the instance over the Management API: create the
// `ramp` project, force MFA off at the org (so a scripted password login is
// possible), register the confidential `ramp-mcp` OIDC client, and import the
// `alice` login user. Every call carries the admin PAT and the Host header
// (base/host = the resolved daemon host, matching ExternalDomain) Zitadel routes
// instances by.
//
// scripts/zitadel-bootstrap.sh is a SECOND implementation of this, for the local
// dev stack. A change here does not reach it, and vice versa. Three deliberate
// divergences, each for its own reason:
//   - app name: cosmetic drift rather than a decision. Nothing reads the name;
//     the test-tier value predates a change the dev stack followed and this
//     did not.
//   - redirect URI: the dev stack registers the Identity service's real callback;
//     tests register a loopback placeholder the headless login helper intercepts
//     before anything dials it.
//   - Google federation: configured by the dev stack when credentials are
//     present, never here — the headless helper scrapes Zitadel's login HTML,
//     which a Google redirect would take it away from.
func bootstrapZitadel(ctx context.Context, base, host, pat string) (zitadelCreds, error) {
	a := &zitadelAdmin{base: base, host: host, pat: pat, http: &http.Client{Timeout: 15 * time.Second}}
	if err := a.waitReady(ctx); err != nil {
		return zitadelCreds{}, err
	}
	projectID, err := a.createProject(ctx)
	if err != nil {
		return zitadelCreds{}, err
	}
	if err := a.setLoginPolicy(ctx); err != nil {
		return zitadelCreds{}, err
	}
	creds, err := a.createApp(ctx, projectID)
	if err != nil {
		return zitadelCreds{}, err
	}
	if err := a.importAlice(ctx); err != nil {
		return zitadelCreds{}, err
	}
	return creds, nil
}

type zitadelAdmin struct {
	base, host, pat string
	http            *http.Client
}

// do issues one Management-API call. It returns the status and raw body rather
// than erroring on non-2xx, because several calls tolerate AlreadyExists.
func (a *zitadelAdmin) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal %s body: %w", path, err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("build %s request: %w", path, err)
	}
	req.Host = a.host
	req.Header.Set("Authorization", "Bearer "+a.pat)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("read %s body: %w", path, err)
	}
	return resp.StatusCode, rb, nil
}

// waitReady polls the management API until it answers, tolerating the window
// after the port listens but before the instance is fully queryable.
func (a *zitadelAdmin) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		status, _, err := a.do(ctx, http.MethodGet, "/management/v1/orgs/me", nil)
		if err == nil && status == http.StatusOK {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("zitadel management API never became reachable (last status %d, err %v)", status, err)
		}
		time.Sleep(time.Second)
	}
}

func (a *zitadelAdmin) createProject(ctx context.Context) (string, error) {
	status, body, err := a.do(ctx, http.MethodPost, "/management/v1/projects", map[string]any{
		"name": "ramp", "projectRoleAssertion": true, "projectRoleCheck": false,
	})
	if err != nil {
		return "", err
	}
	if id := jsonField(body, "id"); id != "" {
		return id, nil
	}
	// AlreadyExists path: look the project up by name.
	_, sb, serr := a.do(ctx, http.MethodPost, "/management/v1/projects/_search", map[string]any{
		"queries": []any{map[string]any{"nameQuery": map[string]any{
			"name": "ramp", "method": "TEXT_QUERY_METHOD_EQUALS",
		}}},
	})
	if serr != nil {
		return "", serr
	}
	if id := jsonField(sb, "id"); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("zitadel: could not resolve project id (create status %d: %s)", status, head(body))
}

// setLoginPolicy forces MFA off and disables passwordless so a scripted password
// login for alice succeeds. A fresh org may already carry a custom policy, so a
// conflict falls back to an update.
func (a *zitadelAdmin) setLoginPolicy(ctx context.Context) error {
	policy := map[string]any{
		"allowUsernamePassword":      true,
		"allowRegister":              false,
		"allowExternalIdp":           true,
		"forceMfa":                   false,
		"forceMfaLocalOnly":          false,
		"passwordlessType":           "PASSWORDLESS_TYPE_NOT_ALLOWED",
		"hidePasswordReset":          true,
		"passwordCheckLifetime":      "864000s",
		"externalLoginCheckLifetime": "864000s",
		"mfaInitSkipLifetime":        "0s",
		"secondFactorCheckLifetime":  "64800s",
		"multiFactorCheckLifetime":   "43200s",
		"allowDomainDiscovery":       true,
		"disableLoginWithPhone":      true,
	}
	status, body, err := a.do(ctx, http.MethodPost, "/management/v1/policies/login", policy)
	if err != nil {
		return err
	}
	if status == http.StatusOK || status == http.StatusCreated {
		return nil
	}
	// Already a custom policy → update it to the same settings.
	ustatus, ubody, uerr := a.do(ctx, http.MethodPut, "/management/v1/policies/login", policy)
	if uerr != nil {
		return uerr
	}
	if ustatus == http.StatusOK || ustatus == http.StatusCreated {
		return nil
	}
	if strings.Contains(string(body), "AlreadyExists") {
		return nil
	}
	return fmt.Errorf("zitadel: login policy not applied (create %d: %s; update %d: %s)",
		status, head(body), ustatus, head(ubody))
}

// createApp registers the confidential `ramp-mcp` OIDC client. Zitadel returns
// the generated secret only on the create response, which is exactly what a
// fresh container yields.
func (a *zitadelAdmin) createApp(ctx context.Context, projectID string) (zitadelCreds, error) {
	app := map[string]any{
		"name":                     "ramp-mcp",
		"redirectUris":             []string{"http://127.0.0.1:53217/callback", "http://localhost:53217/callback"},
		"responseTypes":            []string{"OIDC_RESPONSE_TYPE_CODE"},
		"grantTypes":               []string{"OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"},
		"appType":                  "OIDC_APP_TYPE_WEB",
		"authMethodType":           "OIDC_AUTH_METHOD_TYPE_BASIC",
		"version":                  "OIDC_VERSION_1_0",
		"devMode":                  true,
		"accessTokenType":          "OIDC_TOKEN_TYPE_JWT",
		"accessTokenRoleAssertion": true,
		"idTokenRoleAssertion":     true,
		"idTokenUserinfoAssertion": true,
		"clockSkew":                "0s",
	}
	status, body, err := a.do(ctx, http.MethodPost, "/management/v1/projects/"+projectID+"/apps/oidc", app)
	if err != nil {
		return zitadelCreds{}, err
	}
	id := jsonField(body, "clientId")
	secret := jsonField(body, "clientSecret")
	if id == "" || secret == "" {
		return zitadelCreds{}, fmt.Errorf("zitadel: app create returned no client credentials (status %d: %s)", status, head(body))
	}
	return zitadelCreds{clientID: id, clientSecret: secret}, nil
}

func (a *zitadelAdmin) importAlice(ctx context.Context) error {
	user := map[string]any{
		"userName": aliceUser,
		"profile": map[string]any{
			"firstName": "Alice", "lastName": "Subscriber",
			"displayName": "Alice Subscriber", "preferredLanguage": "en",
		},
		"email":                  map[string]any{"email": aliceUser, "isEmailVerified": true},
		"password":               alicePassword,
		"passwordChangeRequired": false,
	}
	status, body, err := a.do(ctx, http.MethodPost, "/management/v1/users/human/_import", user)
	if err != nil {
		return err
	}
	switch {
	case status == http.StatusOK, status == http.StatusCreated, status == http.StatusConflict:
		return nil
	case strings.Contains(string(body), "AlreadyExists"), strings.Contains(string(body), "already exists"):
		return nil
	default:
		return fmt.Errorf("zitadel: import alice failed (status %d: %s)", status, head(body))
	}
}

// jsonField pulls a top-level string field out of a Management-API response,
// returning "" when the body is not an object or the field is absent. The
// responses this bootstrap cares about (id, clientId, clientSecret) are all
// top-level strings.
func jsonField(body []byte, field string) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}

func head(b []byte) string {
	const n = 300
	s := strings.TrimSpace(string(b))
	if len(s) > n {
		return s[:n]
	}
	return s
}
