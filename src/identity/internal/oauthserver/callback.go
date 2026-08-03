package oauthserver

import (
	"net/http"
)

// handleCallback is where Zitadel returns. It reopens the sealed authorize context,
// checks the upstream state, exchanges the code, provisions the identity, and then
// either sends the browser to the mandatory form (registration incomplete) or issues
// the downstream code straight back to the client (already registered).
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	var flow authFlow
	if err := s.readSealed(r, authFlowCookie, &flow); err != nil {
		userError(w, http.StatusBadRequest, "sign-in session missing or expired; start again")
		return
	}
	s.clearCookie(w, authFlowCookie)

	q := r.URL.Query()
	if q.Get("state") != flow.UpstreamState {
		userError(w, http.StatusBadRequest, "sign-in state mismatch")
		return
	}
	if q.Get("error") != "" {
		// The redirect target is now trusted; report a fixed denial rather than
		// reflecting the upstream's error string back to the client.
		redirectError(w, r, flow.RedirectURI, flow.ClientState,
			oauthErr{code: "access_denied", desc: "upstream sign-in was denied"})
		return
	}

	claims, err := s.cfg.Upstream.Exchange(r.Context(), q.Get("code"), flow.UpstreamVerifier, flow.UpstreamNonce)
	if err != nil {
		logError(r, "oauthserver.callback.exchange", err)
		userError(w, http.StatusBadGateway, "upstream sign-in failed")
		return
	}
	subdomain, needsForm, err := s.cfg.SignUp.SignIn(r.Context(), claims)
	if err != nil {
		s.unavailableOrServerError(w, r, "oauthserver.callback.provision", err)
		return
	}
	logInfo(r, "oauthserver.signin.ok", "subdomain", subdomain, "needs_form", needsForm)

	csrf, err := randomToken(16)
	if err != nil {
		s.serverError(w, r, "oauthserver.callback.entropy", err)
		return
	}
	p := pending{
		ClientID:        flow.ClientID,
		ClientName:      flow.ClientName,
		RedirectURI:     flow.RedirectURI,
		ClientState:     flow.ClientState,
		ClientChallenge: flow.ClientChallenge,
		Issuer:          claims.Issuer,
		Subject:         claims.Subject,
		Subdomain:       subdomain,
		CSRFToken:       csrf,
	}
	if err := s.setSealed(w, pendingCookie, p, pendingTTL); err != nil {
		s.serverError(w, r, "oauthserver.callback.seal", err)
		return
	}
	// The developer is authenticated and provisioned. A new developer fills the
	// mandatory licensing form first; then every developer must approve the
	// requesting client on the consent screen before any code is issued —
	// authentication is not authorization, so a client the resource owner never
	// approved (e.g. a phisher's self-registered client) gets no code.
	if needsForm {
		http.Redirect(w, r, FormPath, http.StatusFound)
		return
	}
	http.Redirect(w, r, ConsentPath, http.StatusFound)
}

// issueCodeAndRedirect mints a one-time authorization code bound to cg through the
// grant service and 302s the browser back to the client. It is the single exit both
// the "already registered" callback path and the completed-form path funnel through.
func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request, cg codeGrant) {
	code, err := s.grant.issue(r.Context(), cg)
	if err != nil {
		s.unavailableOrServerError(w, r, "oauthserver.code.issue", err)
		return
	}
	redirectSuccess(w, r, cg.redirectURI, code, cg.clientState)
}
