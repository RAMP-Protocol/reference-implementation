package oauthserver

import (
	"fmt"
	"net/http"
)

// handleAuthorize begins a sign-in. It first pins the client and redirect_uri (until
// those are trusted no error may be redirected, so a bad one gets a plain 400), then
// requires a code + S256 challenge, stashes the authorization-request context plus a
// fresh upstream leg in a sealed cookie, and 302s the browser to Zitadel.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.cfg.Clients.ClientByID(r.Context(), q.Get("client_id"))
	if err != nil {
		if storeUnavailable(err) {
			s.serviceUnavailable(w, r, "oauthserver.authorize.store", err)
			return
		}
		userError(w, http.StatusBadRequest, "unknown or unregistered client_id")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !allowedRedirect(client, redirectURI) {
		userError(w, http.StatusBadRequest, "redirect_uri is not registered for this client")
		return
	}

	state := q.Get("state")
	if q.Get("response_type") != "code" {
		redirectError(w, r, redirectURI, state,
			oauthErr{code: "unsupported_response_type", desc: "only response_type=code is supported"})
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		redirectError(w, r, redirectURI, state,
			oauthErr{code: "invalid_request", desc: "a S256 code_challenge is required"})
		return
	}

	leg, err := newUpstreamLeg()
	if err != nil {
		s.serverError(w, r, "oauthserver.authorize.entropy", err)
		return
	}
	flow := authFlow{
		ClientID:         client.ID,
		ClientName:       client.Name,
		RedirectURI:      redirectURI,
		ClientState:      state,
		ClientChallenge:  challenge,
		UpstreamState:    leg.state,
		UpstreamNonce:    leg.nonce,
		UpstreamVerifier: leg.verifier,
	}
	if err := s.setSealed(w, authFlowCookie, flow, authFlowTTL); err != nil {
		s.serverError(w, r, "oauthserver.authorize.seal", err)
		return
	}
	http.Redirect(w, r, s.cfg.Upstream.AuthCodeURL(leg.state, leg.nonce, s256Challenge(leg.verifier)), http.StatusFound)
}

// upstreamLeg is the per-sign-in secret set for the service's own leg to Zitadel.
type upstreamLeg struct {
	state    string
	nonce    string
	verifier string
}

// newUpstreamLeg mints a fresh state, nonce, and PKCE verifier for the upstream leg.
func newUpstreamLeg() (upstreamLeg, error) {
	state, err := randomToken(16)
	if err != nil {
		return upstreamLeg{}, fmt.Errorf("state: %w", err)
	}
	nonce, err := randomToken(16)
	if err != nil {
		return upstreamLeg{}, fmt.Errorf("nonce: %w", err)
	}
	verifier, err := generateVerifier()
	if err != nil {
		return upstreamLeg{}, fmt.Errorf("verifier: %w", err)
	}
	return upstreamLeg{state: state, nonce: nonce, verifier: verifier}, nil
}
