package oauthserver

import (
	"errors"
	"net/http"
)

// handleToken implements the authorization-code grant. It parses the request and
// hands it to the grant service, which re-checks every binding — expiry, client_id,
// redirect_uri, and the PKCE verifier against the stored challenge — before minting
// the access token, consuming the one-time code only once all checks pass. Any
// mismatch is invalid_grant; a transient store outage is 503; nothing about the
// token depends on caller-supplied identity.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed token request")
		return
	}
	if r.PostFormValue("grant_type") != "authorization_code" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	code := r.PostFormValue("code")
	verifier := r.PostFormValue("code_verifier")
	if code == "" || verifier == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
		return
	}

	access, ttl, err := s.grant.redeem(r.Context(), tokenRequest{
		code:        code,
		verifier:    verifier,
		clientID:    r.PostFormValue("client_id"),
		redirectURI: r.PostFormValue("redirect_uri"),
	})
	if err != nil {
		s.writeTokenError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(ttl.Seconds()),
	})
}

// writeTokenError maps a grant redemption failure to its RFC 6749 response: a
// caller-facing invalid_grant (400), a transient store outage (503, retryable), or
// an unexpected server fault (500, detail logged not leaked).
func (s *Server) writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	var ge *grantError
	if errors.As(err, &ge) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", ge.desc)
		return
	}
	s.unavailableOrJSONError(w, r, "oauthserver.token.redeem", err)
}
