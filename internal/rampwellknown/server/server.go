// Package server builds and serves the two RAMP discovery documents for a
// single participant role: the commercial overlay manifest at
// /.well-known/ramp.json and the pure Web Bot Auth directory (WBAFile) at
// /.well-known/http-message-signatures-directory. Every in-repo producer
// (exchange, broker, edge, mcp shim) assembles both through Build/BuildWBA and
// serves them through Handler so the wire shape, enum encoding, and schema
// conformance are identical across roles.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// KeySource yields the JWKs to publish in the WBA directory, in document order.
// A producer that rotates keys returns the live set on each call; Handler.Rebuild
// re-reads it. A WBA directory always publishes at least one key.
type KeySource interface {
	Keys() []*rampwellknown.Key
}

type staticKeys struct{ keys []*rampwellknown.Key }

func (s staticKeys) Keys() []*rampwellknown.Key { return s.keys }

// StaticKeys returns a KeySource that serves a fixed key list verbatim — the
// common case for a producer whose keys are injected at construction.
func StaticKeys(keys ...*rampwellknown.Key) KeySource { return staticKeys{keys: keys} }

// Config describes a commercial overlay manifest to build. Role/Domain are
// always required; remaining fields are populated per role
// (exchanges/catalog_contributors for publishers, capability fields for
// exchanges). Identity keys are NOT part of the overlay — see WBAConfig.
type Config struct {
	Role    rampwellknown.Role
	Domain  string
	Contact string

	// Publisher-only.
	Exchanges           []*rampv1.AuthorizedExchange
	CatalogContributors []*rampv1.CatalogContributor

	// Exchange-only capability fields.
	Name                string
	Operator            string
	Endpoint            string
	HealthEndpoint      string
	CatalogEndpoint     string
	BaseCurrency        string
	SupportedProfiles   []string
	MaxIntermediaryHops *int32
}

// WBAConfig describes a WBA directory to build. Keys is required (a directory
// publishes at least one key); RevocationURL is the optional directory-level
// emergency revocation channel advertised to peers.
type WBAConfig struct {
	Keys          KeySource
	RevocationURL string
}

// Build assembles, marshals, and schema-validates the overlay manifest for cfg,
// returning the protojson bytes (snake_case fields, full enum names). A
// validation failure is a producer-side configuration error.
func Build(cfg Config) ([]byte, error) {
	m, err := assemble(cfg)
	if err != nil {
		return nil, err
	}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("rampwellknown/server: marshal: %w", err)
	}
	if err := rampwellknown.ValidateManifest(raw); err != nil {
		return nil, fmt.Errorf("rampwellknown/server: built manifest invalid: %w", err)
	}
	return raw, nil
}

// BuildWBA assembles, marshals, and schema-validates the WBA directory for cfg,
// returning the protojson bytes. A validation failure (e.g. no keys) is a
// producer-side configuration error.
func BuildWBA(cfg WBAConfig) ([]byte, error) {
	f := &rampwellknown.WBAFile{}
	if cfg.Keys != nil {
		f.Keys = cfg.Keys.Keys()
	}
	if cfg.RevocationURL != "" {
		f.RevocationUrl = proto.String(cfg.RevocationURL)
	}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("rampwellknown/server: marshal wba: %w", err)
	}
	if err := rampwellknown.ValidateWBA(raw); err != nil {
		return nil, fmt.Errorf("rampwellknown/server: built wba directory invalid: %w", err)
	}
	return raw, nil
}

func assemble(cfg Config) (*rampwellknown.Manifest, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("rampwellknown/server: domain required")
	}
	if cfg.Role == rampwellknown.RoleUnspecified {
		return nil, fmt.Errorf("rampwellknown/server: role required")
	}
	m := &rampwellknown.Manifest{
		Ver:    rampwellknown.Version,
		Role:   cfg.Role,
		Domain: cfg.Domain,
	}
	setOptional(m, cfg)
	return m, nil
}

// setOptional fills the optional / role-specific fields, leaving unset proto
// optionals absent in the marshaled output.
func setOptional(m *rampwellknown.Manifest, cfg Config) {
	if cfg.Contact != "" {
		m.Contact = proto.String(cfg.Contact)
	}
	m.Exchanges = cfg.Exchanges
	m.CatalogContributors = cfg.CatalogContributors
	if cfg.Name != "" {
		m.Name = proto.String(cfg.Name)
	}
	if cfg.Operator != "" {
		m.Operator = proto.String(cfg.Operator)
	}
	if cfg.Endpoint != "" {
		m.Endpoint = proto.String(cfg.Endpoint)
	}
	if cfg.HealthEndpoint != "" {
		m.HealthEndpoint = proto.String(cfg.HealthEndpoint)
	}
	if cfg.CatalogEndpoint != "" {
		m.CatalogEndpoint = proto.String(cfg.CatalogEndpoint)
	}
	if cfg.BaseCurrency != "" {
		m.BaseCurrency = proto.String(cfg.BaseCurrency)
	}
	m.SupportedProfiles = cfg.SupportedProfiles
	m.MaxIntermediaryHops = cfg.MaxIntermediaryHops
}

// Handler serves one built discovery document (overlay manifest or WBA
// directory) at its canonical path. Serialized bytes are cached in an
// atomic.Pointer so ServeHTTP is lock-free; Rebuild swaps in a freshly
// marshaled document (e.g. after key rotation).
type Handler struct {
	build       func() ([]byte, error)
	contentType string
	path        string
	bytes       atomic.Pointer[[]byte]
}

// NewHandler builds the initial overlay manifest and returns a ready Handler
// that serves it at /.well-known/ramp.json.
func NewHandler(cfg Config) (*Handler, error) {
	return newHandler(func() ([]byte, error) { return Build(cfg) },
		"application/json", rampwellknown.Path)
}

// NewWBAHandler builds the initial WBA directory and returns a ready Handler
// that serves it at /.well-known/http-message-signatures-directory with the
// JWK-Set content type.
func NewWBAHandler(cfg WBAConfig) (*Handler, error) {
	return newHandler(func() ([]byte, error) { return BuildWBA(cfg) },
		"application/jwk-set+json", rampwellknown.WBAPath)
}

func newHandler(build func() ([]byte, error), contentType, path string) (*Handler, error) {
	h := &Handler{build: build, contentType: contentType, path: path}
	if err := h.Rebuild(); err != nil {
		return nil, err
	}
	return h, nil
}

// Rebuild re-runs the document builder (re-reading the KeySource) and re-marshals.
func (h *Handler) Rebuild() error {
	raw, err := h.build()
	if err != nil {
		return err
	}
	h.bytes.Store(&raw)
	return nil
}

// Bytes returns the currently served document.
func (h *Handler) Bytes() []byte {
	if p := h.bytes.Load(); p != nil {
		return *p
	}
	return nil
}

// ServeHTTP writes the cached document with its content type.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", h.contentType)
	_, _ = w.Write(h.Bytes())
}

// RegisterRoutes mounts the document route on mux at its canonical path.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+h.path, h.ServeHTTP)
}

// Handlers bundles a participant's two discovery-surface handlers — the RAMP
// commercial overlay manifest (/.well-known/ramp.json) and the pure Web Bot Auth
// directory (/.well-known/http-message-signatures-directory) — so a caller mounts
// both routes with a single RegisterRoutes call. Every in-repo producer that
// serves both documents (exchange, broker) returns this pair.
type Handlers struct {
	Manifest *Handler
	WBA      *Handler
}

// RegisterRoutes mounts both the overlay-manifest and WBA-directory routes on mux.
func (h Handlers) RegisterRoutes(mux *http.ServeMux) {
	h.Manifest.RegisterRoutes(mux)
	h.WBA.RegisterRoutes(mux)
}

// RebuildIntervalFor returns how often a service must re-derive its served
// discovery documents, given the validity lifetime its published keys carry.
// The two values are one invariant: windows are stamped at build time, so a
// document rebuilt less often than its keys' lifetime would eventually serve
// only lapsed windows while the process stays healthy. Deriving the interval
// here — a quarter of the lifetime, capped at one day — keeps the result
// below the lifetime by construction, so no service can pair a short lifetime
// with a long interval and freeze its directory.
func RebuildIntervalFor(keyLifetime time.Duration) time.Duration {
	interval := keyLifetime / 4
	if interval > 24*time.Hour {
		interval = 24 * time.Hour
	}
	return interval
}

// RunRefresher rebuilds both served documents every interval until ctx ends.
// A discovery document embeds build-time state — validity windows read from
// the producer's clock — so a long-lived process must re-derive it
// periodically: a document served unchanged for months would eventually
// publish only lapsed windows while the process itself stays healthy. A
// failed rebuild keeps the previously served bytes and logs a warning; the
// surface never goes dark because one rebuild attempt failed.
func (h Handlers) RunRefresher(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, hd := range []*Handler{h.Manifest, h.WBA} {
				if err := hd.Rebuild(); err != nil {
					logger.WarnContext(ctx, "wellknown.rebuild_failed", "path", hd.path, "err", err)
				}
			}
		}
	}
}
