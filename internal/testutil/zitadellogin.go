//go:build integration && zitadel

package testutil

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// AliceLogin returns the seeded local login credentials the real-Zitadel tests
// drive, so the test package need not restate them.
func AliceLogin() (user, password string) { return aliceUser, alicePassword }

var (
	reInputTag   = regexp.MustCompile(`(?s)<input\b[^>]*>`)
	reValueAttr  = regexp.MustCompile(`value="([^"]*)"`)
	reFormAction = regexp.MustCompile(`(?s)<form\b[^>]*\baction="([^"]+)"`)
)

// HeadlessLogin drives Zitadel v3.4.9's server-rendered Login V1 UI to completion
// without a browser: it scrapes the login-name and password forms (their
// gorilla.csrf.Token + authRequestID hidden fields and form action), submits
// credentials, then chases the redirect chain until it reaches redirectPrefix,
// returning the ?code and ?state that carry back to the identity service's
// /callback. It is deliberately the only thing coupled to Zitadel's login HTML;
// a Login-V1→V2 shift or a field rename surfaces here as a fail-fast parse error
// with the body head, not a hang. Federated (Google) login is out of scope — it
// cannot complete headlessly.
func HeadlessLogin(
	ctx context.Context, zitadelBase, authorizeURL, redirectPrefix, loginName, password string,
) (code, state string, err error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", "", fmt.Errorf("zitadel login cookie jar: %w", err)
	}
	follow := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	manual := &http.Client{Jar: jar, Timeout: 15 * time.Second, CheckRedirect: noFollow}

	loginHTML, err := getBody(ctx, follow, authorizeURL)
	if err != nil {
		return "", "", fmt.Errorf("zitadel authorize GET: %w", err)
	}
	csrf := extractHidden(loginHTML, "gorilla.csrf.Token")
	reqID := extractHidden(loginHTML, "authRequestID")
	action := extractAction(loginHTML)
	if csrf == "" || reqID == "" || action == "" {
		return "", "", fmt.Errorf("zitadel login-name form parse (csrf=%q reqID=%q action=%q); body: %s",
			csrf, reqID, action, head([]byte(loginHTML)))
	}

	pwHTML, err := postFormBody(ctx, follow, zitadelBase+action, url.Values{
		"gorilla.csrf.Token": {csrf}, "authRequestID": {reqID}, "loginName": {loginName},
	})
	if err != nil {
		return "", "", fmt.Errorf("zitadel loginname POST: %w", err)
	}
	csrf2 := extractHidden(pwHTML, "gorilla.csrf.Token")
	action2 := extractAction(pwHTML)
	if csrf2 == "" || action2 == "" {
		return "", "", fmt.Errorf("zitadel password form parse (csrf=%q action=%q); body: %s",
			csrf2, action2, head([]byte(pwHTML)))
	}

	loc, err := postFormLocation(ctx, manual, zitadelBase+action2, url.Values{
		"gorilla.csrf.Token": {csrf2}, "authRequestID": {reqID}, "password": {password},
	})
	if err != nil {
		return "", "", fmt.Errorf("zitadel password POST: %w", err)
	}
	return chaseToRedirect(ctx, manual, zitadelBase, redirectPrefix, loc)
}

// chaseToRedirect follows the post-login redirect chain one hop at a time until a
// Location starts with redirectPrefix, then extracts the code + state. Relative
// Locations are resolved against zitadelBase.
func chaseToRedirect(ctx context.Context, client *http.Client, zitadelBase, redirectPrefix, loc string) (string, string, error) {
	for hop := 0; hop < 20; hop++ {
		if loc == "" {
			return "", "", fmt.Errorf("zitadel: redirect chain ended before reaching %s", redirectPrefix)
		}
		abs := loc
		if strings.HasPrefix(abs, "/") {
			abs = zitadelBase + abs
		}
		if strings.HasPrefix(abs, redirectPrefix) {
			u, perr := url.Parse(abs)
			if perr != nil {
				return "", "", fmt.Errorf("zitadel: parse redirect %q: %w", abs, perr)
			}
			q := u.Query()
			if e := q.Get("error"); e != "" {
				return "", "", fmt.Errorf("zitadel login error: %s (%s)", e, q.Get("error_description"))
			}
			if code := q.Get("code"); code != "" {
				return code, q.Get("state"), nil
			}
			return "", "", fmt.Errorf("zitadel: reached redirect URI without code: %s", abs)
		}
		next, err := getLocation(ctx, client, abs)
		if err != nil {
			return "", "", err
		}
		loc = next
	}
	return "", "", fmt.Errorf("zitadel: exceeded redirect hop limit before reaching %s", redirectPrefix)
}

func noFollow(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func getBody(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func postFormBody(ctx context.Context, client *http.Client, rawURL string, vals url.Values) (string, error) {
	resp, err := postForm(ctx, client, rawURL, vals)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func postFormLocation(ctx context.Context, client *http.Client, rawURL string, vals url.Values) (string, error) {
	resp, err := postForm(ctx, client, rawURL, vals)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("Location"), nil
}

func postForm(ctx context.Context, client *http.Client, rawURL string, vals url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return client.Do(req)
}

func getLocation(ctx context.Context, client *http.Client, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Get("Location"), nil
}

// extractHidden returns the value of the hidden input whose name matches, scanning
// input tags so attribute order (name before or after value) does not matter.
func extractHidden(html, name string) string {
	needle := `name="` + name + `"`
	for _, tag := range reInputTag.FindAllString(html, -1) {
		if strings.Contains(tag, needle) {
			if m := reValueAttr.FindStringSubmatch(tag); m != nil {
				return m[1]
			}
		}
	}
	return ""
}

func extractAction(html string) string {
	if m := reFormAction.FindStringSubmatch(html); m != nil {
		return m[1]
	}
	return ""
}
