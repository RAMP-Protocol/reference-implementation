package oauthserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	authFlowCookie = "ramp_authflow"
	pendingCookie  = "ramp_pending"

	authFlowTTL = 10 * time.Minute
	pendingTTL  = 20 * time.Minute
)

// authFlow is the state sealed at /authorize and reopened at /callback. It holds the
// downstream client's request (to rebuild the redirect and bind the code) and the
// service's own upstream-leg secrets (state, nonce, PKCE verifier) that the browser
// must not read or forge.
type authFlow struct {
	ClientID         string `json:"cid"`
	ClientName       string `json:"cnm"`
	RedirectURI      string `json:"ruri"`
	ClientState      string `json:"cst"`
	ClientChallenge  string `json:"cch"`
	UpstreamState    string `json:"ust"`
	UpstreamNonce    string `json:"unc"`
	UpstreamVerifier string `json:"uvf"`
}

// pending is the state sealed at /callback (when the form is still needed) and
// reopened at /form. It carries the downstream client's request forward so the code
// can be issued after the form, plus the authenticated developer identity and the
// subdomain minted for it.
type pending struct {
	ClientID        string `json:"cid"`
	ClientName      string `json:"cnm"`
	RedirectURI     string `json:"ruri"`
	ClientState     string `json:"cst"`
	ClientChallenge string `json:"cch"`
	Issuer          string `json:"iss"`
	Subject         string `json:"sub"`
	Subdomain       string `json:"sd"`
	// CSRFToken is the synchronizer token minted at /callback, sealed here (so the
	// browser cannot read or forge it), and echoed as a hidden field on the form.
	// /form verifies the submitted field against it, making CSRF protection
	// independent of SameSite support.
	CSRFToken string `json:"csrf"`
}

// errWrongPurpose marks a sealed cookie that decrypted under the wrong name — a
// value sealed for one cookie presented under another. It cannot cross user
// boundaries (the key is server-side), but binding the purpose closes the gap
// where two payloads that share JSON field names could be substituted.
var errWrongPurpose = errors.New("oauthserver: sealed cookie opened under the wrong purpose")

// purposeEnvelope binds a cookie's name into its sealed payload so a value sealed
// for one cookie (authFlowCookie) cannot be opened as another (pendingCookie),
// even though the codec key is shared and the payloads share JSON field names.
type purposeEnvelope struct {
	Purpose string          `json:"p"`
	Data    json.RawMessage `json:"d"`
}

// setCookie writes a cookie with the sign-up flow's fixed security attributes
// (Path=/, HttpOnly, SameSite=Lax — the flow returns via top-level GET redirects —
// and Secure tracking the deployment scheme so a local http compose stack still
// works). Only value and maxAge vary; a negative maxAge expires the cookie.
// Centralized so the set and clear paths cannot drift on the security attributes —
// the surface the gosec G124 exclusion covers.
func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

// setSealed seals payload into a cookie, tagged with the cookie name as its purpose.
func (s *Server) setSealed(w http.ResponseWriter, name string, payload any, ttl time.Duration) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	val, err := s.cfg.Codec.Seal(purposeEnvelope{Purpose: name, Data: data}, ttl)
	if err != nil {
		return err
	}
	s.setCookie(w, name, val, int(ttl.Seconds()))
	return nil
}

// readSealed opens the named cookie into dest, returning http.ErrNoCookie when it
// is absent, a session error when it is expired or tampered, and errWrongPurpose
// when the sealed value was minted for a different cookie name.
func (s *Server) readSealed(r *http.Request, name string, dest any) error {
	c, err := r.Cookie(name)
	if err != nil {
		return err
	}
	var env purposeEnvelope
	if err := s.cfg.Codec.Open(c.Value, &env); err != nil {
		return err
	}
	if env.Purpose != name {
		return errWrongPurpose
	}
	return json.Unmarshal(env.Data, dest)
}

// clearCookie expires the named cookie so a spent flow leaves nothing behind.
func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	s.setCookie(w, name, "", -1)
}

// readPendingPOST is the prelude the /form and /consent POST handlers share: open the
// sealed pending cookie, parse a size-bounded form body, and verify the CSRF token.
// It writes the 400 and returns ok=false on any failure, so the caller returns
// immediately on !ok; on success it returns the reopened pending state.
func (s *Server) readPendingPOST(w http.ResponseWriter, r *http.Request) (pending, bool) {
	var p pending
	if err := s.readSealed(r, pendingCookie, &p); err != nil {
		userError(w, http.StatusBadRequest, "no active sign-up session; start again")
		return pending{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		userError(w, http.StatusBadRequest, "malformed submission")
		return pending{}, false
	}
	if !sameToken(r.PostFormValue(csrfField), p.CSRFToken) {
		userError(w, http.StatusBadRequest, "invalid or expired form token; start again")
		return pending{}, false
	}
	return p, true
}
