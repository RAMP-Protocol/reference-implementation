// Package transport is the Identity Service's HTTP adapter. It serves four documents
// on each agent's per-user subdomain: the Web Bot Auth directory, the Signature Agent
// Card, the key-revocation list, and the RAMP commercial overlay. The
// request Host selects the agent, and the publisher service builds and caches the
// documents. One server fronts the whole wildcard zone (*.<base>), so a new agent
// needs no route, handler, or restart. An unknown host returns 404 and never
// another agent's bytes.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
)

// DocumentService is the publisher surface the handler depends on: fetch a built
// document by subdomain. *publisher.Service satisfies it.
type DocumentService interface {
	Directory(ctx context.Context, subdomain string) ([]byte, error)
	Card(ctx context.Context, subdomain string) ([]byte, error)
	Revocation(ctx context.Context, subdomain string) ([]byte, error)
	Manifest(ctx context.Context, subdomain string) ([]byte, error)
}

// Handler dispatches the well-known documents by request Host across the
// wildcard zone. It holds no per-agent state; everything is resolved per request
// through the publisher service.
type Handler struct {
	base         string // the identity zone, e.g. "rampmcp.org"
	svc          DocumentService
	cacheControl string
}

// NewHandler builds a directory Handler for the zone base, serving documents from
// svc. maxAge sets the Cache-Control freshness advertised to CDNs and verifiers;
// it should track the publisher's TTL so a cache does not pin a document longer
// than the service itself would.
func NewHandler(base string, svc DocumentService, maxAge time.Duration) *Handler {
	return &Handler{
		base:         strings.ToLower(strings.TrimPrefix(base, ".")),
		svc:          svc,
		cacheControl: fmt.Sprintf("public, max-age=%d", int(maxAge.Seconds())),
	}
}

// RegisterRoutes mounts the well-known routes on mux at their fixed paths. The
// patterns are path-only; the Host is matched inside the handlers, not by the mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+rampwellknown.WBAPath, h.serveWBA)
	mux.HandleFunc("GET "+directory.CardPath, h.serveCard)
	mux.HandleFunc("GET "+rampwellknown.RevocationPath, h.serveRevocation)
	mux.HandleFunc("GET "+rampwellknown.Path, h.serveManifest)
}

// RouteRegistrar mounts additional routes on the identity mux. The OAuth sign-up
// server registers its endpoints through this, alongside the well-known
// routes, so transport composes it without importing the oauthserver package.
type RouteRegistrar interface {
	RegisterRoutes(mux *http.ServeMux)
}

// ServerOption configures NewServer.
type ServerOption func(*serverConfig)

type serverConfig struct {
	registrars []RouteRegistrar
}

// WithRoutes mounts an additional route registrar on the identity mux. The OAuth
// sign-up server and the MCP adapter are both mounted this way, so transport
// composes them without importing either package.
//
// A nil registrar is ignored, so a caller may pass an optional component through
// without branching at the call site.
func WithRoutes(reg RouteRegistrar) ServerOption {
	return func(c *serverConfig) {
		if reg == nil {
			return
		}
		c.registrars = append(c.registrars, reg)
	}
}

// NewServer assembles the identity service's full HTTP handler: the well-known
// routes, a /healthz probe, any additional registrars (the sign-up auth server), and
// the request-id middleware, exactly as production runs it — so a test that drives
// this exercises the real chain (X-Request-ID, health, host dispatch), not a
// hand-rolled subset. health is the readiness check /healthz reports on (e.g. a DB
// ping); a nil health check always reports healthy.
func NewServer(
	logger *slog.Logger, h *Handler, health func(context.Context) error, opts ...ServerOption,
) http.Handler {
	var cfg serverConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler(health))
	h.RegisterRoutes(mux)
	for _, reg := range cfg.registrars {
		reg.RegisterRoutes(mux)
	}
	return RequestIDMiddleware(logger, mux)
}

// healthHandler reports 200 when health passes (or is nil) and 503 when it fails, so
// an orchestrator's probe drains an instance whose database is unreachable instead of
// routing card requests that would 500.
func healthHandler(health func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if health != nil {
			if err := health(r.Context()); err != nil {
				http.Error(w, "unhealthy", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func (h *Handler) serveWBA(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, directory.WBAMediaType, h.svc.Directory)
}

func (h *Handler) serveCard(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, directory.CardMediaType, h.svc.Card)
}

func (h *Handler) serveRevocation(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, directory.RevocationMediaType, h.svc.Revocation)
}

// serveManifest answers the RAMP commercial overlay. The media type is the plain
// application/json every RAMP participant serves this document as; the shared
// rampwellknown/server handler that Exchanges and Brokers mount uses the same value.
func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request) {
	h.serve(w, r, "application/json", h.svc.Manifest)
}

// serve resolves the subdomain from the Host, fetches the selected document, and
// writes it — mapping an absent document to 404, a backend outage to 503, and any
// other fault to 500. The fault detail is logged, never written to the caller.
func (h *Handler) serve(
	w http.ResponseWriter, r *http.Request, mediaType string,
	fetch func(context.Context, string) ([]byte, error),
) {
	subdomain, ok := parseHost(r.Host, h.base)
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := fetch(r.Context(), subdomain)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", mediaType)
		w.Header().Set("Cache-Control", h.cacheControl)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
	case errors.Is(err, publisher.ErrAbsent):
		http.NotFound(w, r)
	case errors.Is(err, publisher.ErrUnavailable):
		reqctx.FromContext(r.Context()).WarnContext(r.Context(),
			"identity.directory.unavailable", "subdomain", subdomain, "err", err.Error())
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	default:
		reqctx.FromContext(r.Context()).ErrorContext(r.Context(),
			"identity.directory.error", "subdomain", subdomain, "err", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// parseHost validates that host is a single-label child of the zone and returns
// the full FQDN, which is the storage key the KeyStore and card store use. A
// single label is required because the wildcard TLS certificate for *.<base>
// covers exactly one label; a multi-label host, the apex, or a foreign host is
// rejected (→ 404). The subdomain grammar itself is enforced downstream by the
// publisher (keystore.ValidSubdomain), so a malformed but single-label host 404s
// without a backend call rather than 500ing.
func parseHost(host, base string) (string, bool) {
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)

	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return "", false
	}
	label := strings.TrimSuffix(host, suffix)
	if label == "" || strings.Contains(label, ".") {
		return "", false
	}
	return host, true
}
