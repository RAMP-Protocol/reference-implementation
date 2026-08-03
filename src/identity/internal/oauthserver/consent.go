package oauthserver

import (
	"bytes"
	"net/http"
	"strings"
)

// consentField and consentApprove are the decision control on the consent form: the
// code is issued only when the developer submits decision=approve; anything else
// (including the deny button) is treated as a refusal.
const (
	consentField   = "decision"
	consentApprove = "approve"
)

// consentView is the consent template's data: the requesting client, the developer's
// minted subdomain, the exact redirect the code would be sent to (so the developer
// can spot a phishing target), and the CSRF token.
type consentView struct {
	ClientName  string
	Subdomain   string
	RedirectURI string
	CSRFToken   string
}

// handleConsentGet renders the consent screen for the authenticated, provisioned
// developer to approve or deny the requesting client. It is the resource-owner
// authorization step: a self-registered client (open Dynamic Client Registration)
// cannot obtain a code for the developer's identity without this explicit approval.
func (s *Server) handleConsentGet(w http.ResponseWriter, r *http.Request) {
	var p pending
	if err := s.readSealed(r, pendingCookie, &p); err != nil {
		userError(w, http.StatusBadRequest, "no active sign-in session; start again")
		return
	}
	s.renderConsent(w, r, consentView{
		ClientName:  consentClientName(p.ClientName),
		Subdomain:   p.Subdomain,
		RedirectURI: p.RedirectURI,
		CSRFToken:   p.CSRFToken,
	})
}

// handleConsentPost issues the authorization code only when the developer approves
// with a valid CSRF token. A denial — or any decision other than approve — returns
// access_denied to the client and issues no code. Either way the pending state is
// spent, so a consent decision cannot be replayed.
func (s *Server) handleConsentPost(w http.ResponseWriter, r *http.Request) {
	p, ok := s.readPendingPOST(w, r)
	if !ok {
		return
	}
	s.clearCookie(w, pendingCookie)
	if r.PostFormValue(consentField) != consentApprove {
		redirectError(w, r, p.RedirectURI, p.ClientState,
			oauthErr{code: "access_denied", desc: "the developer did not approve the request"})
		return
	}
	logInfo(r, "oauthserver.consent.approved", "subdomain", p.Subdomain, "client_id", p.ClientID)
	s.issueCodeAndRedirect(w, r, codeGrant{
		clientID:    p.ClientID,
		redirectURI: p.RedirectURI,
		clientState: p.ClientState,
		challenge:   p.ClientChallenge,
		subject:     p.Subdomain,
	})
}

// renderConsent executes the consent template into a buffer first, so a template
// failure becomes a clean 500 rather than a half-written body.
func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, view consentView) {
	var buf bytes.Buffer
	if err := s.cfg.Templates.ExecuteTemplate(&buf, consentTemplateName, view); err != nil {
		logError(r, "oauthserver.consent.render", err)
		userError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(buf.Bytes())
}

// consentClientName falls back to a neutral label when a client registered without a
// name, so the consent screen never shows an empty subject.
func consentClientName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "An unnamed application"
	}
	return name
}
