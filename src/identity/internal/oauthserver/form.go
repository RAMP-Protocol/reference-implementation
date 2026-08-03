package oauthserver

import (
	"bytes"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
)

// csrfField is the hidden form field carrying the synchronizer token bound into
// the sealed pending cookie. A cross-site submit cannot read the sealed cookie, so
// it cannot present a matching token — this defends /form even on a SameSite-unaware
// agent, where the cookie alone would not.
const csrfField = "csrf_token"

// formView is the registration form template's data: the minted subdomain to show,
// the prior values to re-fill on a rejected submit, the per-field error messages,
// and the CSRF token echoed into the hidden field.
type formView struct {
	Subdomain string
	Values    signup.FormInput
	Errors    map[string]string
	CSRFToken string
}

// handleFormGet renders the mandatory registration form for a browser that just
// authenticated and still needs to supply the licensing fields.
func (s *Server) handleFormGet(w http.ResponseWriter, r *http.Request) {
	var p pending
	if err := s.readSealed(r, pendingCookie, &p); err != nil {
		userError(w, http.StatusBadRequest, "no active sign-up session; start again")
		return
	}
	s.renderForm(w, r, http.StatusOK, formView{Subdomain: p.Subdomain, CSRFToken: p.CSRFToken})
}

// handleFormPost validates the submission. On a validation error it re-renders the
// form with every problem shown and no state changed; on success it records the
// licensing fields and issues the code back to the client. This is the mandatory
// gate — the code is released only once the three fields are valid.
func (s *Server) handleFormPost(w http.ResponseWriter, r *http.Request) {
	p, ok := s.readPendingPOST(w, r)
	if !ok {
		return
	}
	in := signup.FormInput{
		LegalEntity:         r.PostFormValue(signup.FieldLegalEntity),
		Address:             r.PostFormValue(signup.FieldAddress),
		JurisdictionCountry: r.PostFormValue(signup.FieldJurisdiction),
	}
	_, verr, err := s.cfg.SignUp.CompleteRegistration(r.Context(), p.Issuer, p.Subject, in)
	if err != nil {
		s.unavailableOrServerError(w, r, "oauthserver.form.complete", err)
		return
	}
	if verr != nil {
		s.renderForm(w, r, http.StatusOK, formView{
			Subdomain: p.Subdomain, Values: in, Errors: verr.Fields, CSRFToken: p.CSRFToken,
		})
		return
	}
	logInfo(r, "oauthserver.registration.complete", "subdomain", p.Subdomain)
	// The licensing gate is satisfied, but the developer must still approve the
	// requesting client. Keep the sealed pending state (it carries the client and
	// the CSRF token) and hand off to the consent screen, which issues the code.
	http.Redirect(w, r, ConsentPath, http.StatusFound)
}

// renderForm executes the form template into a buffer first, so a template failure
// becomes a clean 500 rather than a half-written body.
func (s *Server) renderForm(w http.ResponseWriter, r *http.Request, status int, view formView) {
	var buf bytes.Buffer
	if err := s.cfg.Templates.ExecuteTemplate(&buf, formTemplateName, view); err != nil {
		logError(r, "oauthserver.form.render", err)
		userError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
