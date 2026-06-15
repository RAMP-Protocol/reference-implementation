// Package server builds and serves a RAMP /.well-known/ramp.json document for
// a single participant role. Every in-repo producer (exchange, broker, edge,
// mcp shim) assembles its manifest through Build/Handler so the wire shape,
// enum encoding, and schema conformance are identical across roles.
package server

import (
	"fmt"
	"net/http"
	"sync/atomic"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// KeySource yields the JWKs to publish in public_keys, in document order. A
// producer that rotates keys returns the live set on each call; Handler.Rebuild
// re-reads it. Roles that publish no keys (e.g. a publisher declaring only
// authorized exchanges) may supply a nil KeySource.
type KeySource interface {
	Keys() []*rampwellknown.Key
}

type staticKeys struct{ keys []*rampwellknown.Key }

func (s staticKeys) Keys() []*rampwellknown.Key { return s.keys }

// StaticKeys returns a KeySource that serves a fixed key list verbatim — the
// common case for a producer whose keys are injected at construction.
func StaticKeys(keys ...*rampwellknown.Key) KeySource { return staticKeys{keys: keys} }

// Config describes a manifest to build. Role/Domain are always required;
// remaining fields are populated per role (exchanges/catalog_contributors for
// publishers, capability fields for exchanges, keys for agents/brokers/exchanges).
type Config struct {
	Role            rampwellknown.Role
	Domain          string
	Contact         string
	InvalidationURL string
	Keys            KeySource

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

// Build assembles, marshals, and schema-validates the manifest for cfg,
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
	if cfg.Keys != nil {
		m.PublicKeys = cfg.Keys.Keys()
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
	if cfg.InvalidationURL != "" {
		m.InvalidationUrl = proto.String(cfg.InvalidationURL)
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

// Handler serves the manifest at GET /.well-known/ramp.json. Serialized bytes
// are cached in an atomic.Pointer so ServeHTTP is lock-free; Rebuild swaps in a
// freshly marshaled document (e.g. after key rotation).
type Handler struct {
	cfg   Config
	bytes atomic.Pointer[[]byte]
}

// NewHandler builds the initial manifest and returns a ready Handler.
func NewHandler(cfg Config) (*Handler, error) {
	h := &Handler{cfg: cfg}
	if err := h.Rebuild(); err != nil {
		return nil, err
	}
	return h, nil
}

// Rebuild re-reads the KeySource and re-marshals the manifest.
func (h *Handler) Rebuild() error {
	raw, err := Build(h.cfg)
	if err != nil {
		return err
	}
	h.bytes.Store(&raw)
	return nil
}

// Bytes returns the currently served manifest document.
func (h *Handler) Bytes() []byte {
	if p := h.bytes.Load(); p != nil {
		return *p
	}
	return nil
}

// ServeHTTP writes the cached manifest document.
func (h *Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(h.Bytes())
}

// RegisterRoutes mounts the manifest route on mux at the canonical path.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+rampwellknown.Path, h.ServeHTTP)
}
