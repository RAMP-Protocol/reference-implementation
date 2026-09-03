// Package oauthserver is the Identity Service's OAuth 2.1 authorization server — the
// surface an MCP client drives to sign a developer in. It fronts Dynamic Client
// Registration and the authorize/token endpoints downstream, federates
// authentication to Zitadel upstream (via the oidcup port), and asks the developer to
// approve the requesting client in between: /callback provisions the identity, and
// /consent releases the authorization code back to the client. Nothing here mints
// agent keys itself — it composes the signup service, the oauth store, the session
// codec, the upstream authenticator, and the token issuer.
package oauthserver

import (
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauth"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/session"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

// Endpoint paths. The authorization-server metadata path is the RFC 8414 well-known
// location an MCP client reads to discover the others.
const (
	MetadataPath  = "/.well-known/oauth-authorization-server"
	RegisterPath  = "/register"
	AuthorizePath = "/authorize"
	CallbackPath  = "/callback"
	ConsentPath   = "/consent"
	TokenPath     = "/token"
)

const (
	defaultTokenTTL = time.Hour
	defaultCodeTTL  = 5 * time.Minute

	// maxFormBytes bounds the /consent and /token request bodies — both are small
	// url-encoded submissions, never payloads.
	maxFormBytes = 16 << 10
)

// Config wires a Server. Issuer is this authorization server's own issuer URL (the
// base the metadata endpoints are advertised under); every other field is a
// collaborator the handlers compose.
type Config struct {
	Issuer        string
	Codec         *session.Codec
	Upstream      oidcup.Authenticator
	Clients       oauth.Store
	SignUp        *signup.Service
	Tokens        *token.Issuer
	Templates     *template.Template
	Clock         clock.Clock
	SecureCookies bool
	TokenTTL      time.Duration
	CodeTTL       time.Duration
}

// Server is the authorization-server HTTP surface.
type Server struct {
	cfg   Config
	grant *grant
}

// validate reports the first missing required field, one field per message, and
// refuses an https issuer paired with insecure cookies — a misconfiguration that
// would ship the sealed auth-flow cookies over plaintext in production.
func (cfg Config) validate() error {
	switch {
	case cfg.Issuer == "":
		return errors.New("oauthserver: Config.Issuer is required")
	case cfg.Codec == nil:
		return errors.New("oauthserver: Config.Codec is required")
	case cfg.Upstream == nil:
		return errors.New("oauthserver: Config.Upstream is required")
	case cfg.Clients == nil:
		return errors.New("oauthserver: Config.Clients is required")
	case cfg.SignUp == nil:
		return errors.New("oauthserver: Config.SignUp is required")
	case cfg.Tokens == nil:
		return errors.New("oauthserver: Config.Tokens is required")
	case cfg.Clock == nil:
		return errors.New("oauthserver: Config.Clock is required")
	}
	if strings.HasPrefix(cfg.Issuer, "https://") && !cfg.SecureCookies {
		return errors.New("oauthserver: Config.SecureCookies must be true when Issuer is https")
	}
	return nil
}

// New validates the config, filling defaults, and returns a Server.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Templates == nil {
		tmpl, err := defaultTemplates()
		if err != nil {
			return nil, err
		}
		cfg.Templates = tmpl
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultTokenTTL
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = defaultCodeTTL
	}
	return &Server{
		cfg: cfg,
		grant: &grant{
			clients:  cfg.Clients,
			tokens:   cfg.Tokens,
			clk:      cfg.Clock,
			codeTTL:  cfg.CodeTTL,
			tokenTTL: cfg.TokenTTL,
		},
	}, nil
}

// RegisterRoutes mounts the authorization-server routes on mux. The patterns are
// path-only, alongside the identity service's well-known routes; they do not collide
// (distinct paths), and the endpoints build their URLs from the configured Issuer,
// not the request Host.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+MetadataPath, s.handleMetadata)
	mux.HandleFunc("POST "+RegisterPath, s.handleRegister)
	mux.HandleFunc("GET "+AuthorizePath, s.handleAuthorize)
	mux.HandleFunc("GET "+CallbackPath, s.handleCallback)
	mux.HandleFunc("GET "+ConsentPath, s.handleConsentGet)
	mux.HandleFunc("POST "+ConsentPath, s.handleConsentPost)
	mux.HandleFunc("POST "+TokenPath, s.handleToken)
}

// writeJSON encodes v as a JSON response with a no-store cache policy (these are
// auth responses, never cacheable).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// oauthError writes an RFC 6749 error object (used by /register and /token, which
// answer with JSON rather than a redirect).
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// storeUnavailable reports whether err is a transient backend outage, so a handler
// answers 503 (retryable) rather than a permanent 4xx/5xx that tells a valid client
// its request was wrong. The sign-up flow composes four backends — the account and
// oauth stores, the Vault keystore, and the card store — so this must recognize every
// one's outage sentinel (mirroring publisher's classification); a Vault outage during
// /callback provisioning surfaces as a %w-wrapped keystore.ErrUnavailable, which the
// old account/oauth-only check would have mis-mapped to a bare 500. A partial mapping
// is one 500 served for a condition that had a better answer.
func storeUnavailable(err error) bool {
	return errors.Is(err, oauth.ErrUnavailable) ||
		errors.Is(err, account.ErrUnavailable) ||
		errors.Is(err, keystore.ErrUnavailable) ||
		errors.Is(err, keystore.ErrPermissionDenied) ||
		errors.Is(err, directory.ErrCardUnavailable)
}

// serverError logs an unexpected fault against the request and returns a bare 500,
// never leaking the detail to the caller.
func (s *Server) serverError(w http.ResponseWriter, r *http.Request, tag string, err error) {
	logError(r, tag, err)
	userError(w, http.StatusInternalServerError, "internal error")
}

// unavailableMsg is the single canonical user-facing message for a transient backend
// outage, so every 503 the sign-up server returns — browser or JSON — reads the same.
const unavailableMsg = "the service is temporarily unavailable; try again"

// serviceUnavailable logs a transient outage and answers a browser-facing 503 with
// the canonical message. It is the one place the browser 503 leg is written; the
// compound helper below and the /authorize store branch (whose non-store error is a
// 400, not a 500) both route through it.
func (s *Server) serviceUnavailable(w http.ResponseWriter, r *http.Request, tag string, err error) {
	logUnavailable(r, tag, err)
	userError(w, http.StatusServiceUnavailable, unavailableMsg)
}

// unavailableOrServerError maps a backend error for a browser-facing handler: a
// transient store outage becomes a logged 503 (retryable), anything else a bare 500
// with the detail logged, never leaked. Shared so the 503/500 split is written once.
func (s *Server) unavailableOrServerError(w http.ResponseWriter, r *http.Request, tag string, err error) {
	if storeUnavailable(err) {
		s.serviceUnavailable(w, r, tag, err)
		return
	}
	s.serverError(w, r, tag, err)
}

// unavailableOrJSONError is the RFC 6749 JSON analogue of unavailableOrServerError:
// a transient outage becomes 503 temporarily_unavailable (logged), anything else a
// bare 500 server_error with the detail logged. Used by /register and /token.
func (s *Server) unavailableOrJSONError(w http.ResponseWriter, r *http.Request, tag string, err error) {
	if storeUnavailable(err) {
		logUnavailable(r, tag, err)
		oauthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", unavailableMsg)
		return
	}
	logError(r, tag, err)
	oauthError(w, http.StatusInternalServerError, "server_error", "")
}

// logError records a server-side fault against the request logger without leaking
// detail to the caller. The service prefix mirrors the well-known transport's
// "identity.<component>.<event>" event names.
func logError(r *http.Request, msg string, err error) {
	reqctx.FromContext(r.Context()).ErrorContext(r.Context(), "identity."+msg, "err", err.Error())
}

// logUnavailable records a transient backend outage at WARN before the handler
// answers 503, so operators keep outage visibility on the sign-up paths — the
// sibling identity transport WARN-logs ErrUnavailable the same way, and without
// this the new handlers would answer 503 with no server-side trace.
func logUnavailable(r *http.Request, msg string, err error) {
	reqctx.FromContext(r.Context()).WarnContext(r.Context(), "identity."+msg, "err", err.Error())
}

// logInfo records a sign-up success against the request logger, so a client
// registration and a completed sign-up leave an audit trail the way the sibling
// registration paths do. args are structured slog key/value pairs.
func logInfo(r *http.Request, msg string, args ...any) {
	reqctx.FromContext(r.Context()).InfoContext(r.Context(), "identity."+msg, args...)
}
