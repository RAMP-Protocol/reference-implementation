// Package wellknown serves the Exchange's public discovery surface after the
// WBA split: the RAMP commercial overlay manifest at /.well-known/ramp.json
// (WellKnownManifest, role=ROLE_EXCHANGE, no identity keys) AND the pure Web
// Bot Auth directory at /.well-known/http-message-signatures-directory (the
// Ed25519 offer-signing key as a JWK Set).
//
// The offer-signing key lives ONLY in the WBA directory and is referenced
// elsewhere by RFC 7638 thumbprint (the RFC 9421 keyid), never republished in
// the overlay. The CloudFront RSA key remains an out-of-band edge-provisioning
// concern (CloudFront verifies natively against a trusted key group), so it is
// not served here.
package wellknown

import (
	"crypto/ed25519"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/wellknownbuild"
)

// Config carries the inputs the Exchange discovery documents need. The
// offer-signing Ed25519 key is published in the WBA directory;
// KeyNotBefore/KeyNotAfter bound its validity window. Time values are supplied
// by the caller (a production root or a test) so this package never reads the
// wall clock directly.
type Config struct {
	Domain              string
	Endpoint            string // ExchangeService endpoint
	CatalogEndpoint     string // CatalogService endpoint
	BaseCurrency        string
	SupportedProfiles   []string
	MaxIntermediaryHops *int32

	OfferKey     ed25519.PublicKey
	KeyNotBefore time.Time
	KeyNotAfter  time.Time
}

// New builds the Exchange's role=ROLE_EXCHANGE overlay-manifest handler plus its
// WBA directory handler, bundled as a server.Handlers pair a caller mounts with a
// single RegisterRoutes call. The compose lives in the shared wellknownbuild
// builder, which schema-validates both documents at construction, so a
// misconfiguration surfaces here rather than at the first request.
func New(cfg Config) (server.Handlers, error) {
	offerKey := rampwellknown.NewKey(cfg.OfferKey, cfg.KeyNotBefore, cfg.KeyNotAfter)
	// The Exchange WBA directory advertises no revocation_url: the offer-signing
	// key is retired by rotation with a dual-key grace period (design-exchange
	// §17), not by a keyed revocation list. Keyed revocation (ADR-003 §5) is the
	// Broker's channel for the agent/relay kids it hosts, not the Exchange's.
	return wellknownbuild.Build(wellknownbuild.Config{
		Manifest: server.Config{
			Role:                rampwellknown.RoleExchange,
			Domain:              cfg.Domain,
			Endpoint:            cfg.Endpoint,
			CatalogEndpoint:     cfg.CatalogEndpoint,
			BaseCurrency:        cfg.BaseCurrency,
			SupportedProfiles:   cfg.SupportedProfiles,
			MaxIntermediaryHops: cfg.MaxIntermediaryHops,
		},
		Keys: server.StaticKeys(offerKey),
	})
}
