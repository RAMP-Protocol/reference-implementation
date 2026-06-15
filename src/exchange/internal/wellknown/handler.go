// Package wellknown serves the Exchange's public discovery surface: the
// canonical RAMP manifest at /.well-known/ramp.json (WellKnownManifest,
// role=ROLE_EXCHANGE).
//
// RAMP v1 collapses the previously separate jwks.json (offer-signing key) and
// cdn-keys.json (CloudFront RSA key) routes: the Ed25519 offer-signing key is
// now published inline in public_keys[], and the CloudFront RSA key is an
// out-of-band edge-provisioning concern (CloudFront verifies natively against a
// trusted key group), so it is no longer served here.
package wellknown

import (
	"crypto/ed25519"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
)

// Config carries the inputs the Exchange manifest needs. The offer-signing
// Ed25519 key is folded into public_keys[]; KeyNotBefore/KeyNotAfter bound its
// validity window. Time values are supplied by the caller (a production root or
// a test) so this package never reads the wall clock directly.
type Config struct {
	Domain              string
	Endpoint            string // ExchangeService endpoint
	CatalogEndpoint     string // CatalogService endpoint
	BaseCurrency        string
	SupportedProfiles   []string
	MaxIntermediaryHops *int32
	InvalidationURL     string

	OfferKeyID   string
	OfferKey     ed25519.PublicKey
	KeyNotBefore time.Time
	KeyNotAfter  time.Time
}

// New builds the Exchange's role=ROLE_EXCHANGE manifest handler. The returned
// *server.Handler serves GET /.well-known/ramp.json; mount it with
// RegisterRoutes. The built manifest is schema-validated at construction, so a
// misconfiguration surfaces here rather than at the first request.
func New(cfg Config) (*server.Handler, error) {
	offerKey := rampwellknown.NewKey(cfg.OfferKeyID, cfg.OfferKey, cfg.KeyNotBefore, cfg.KeyNotAfter)
	return server.NewHandler(server.Config{
		Role:                rampwellknown.RoleExchange,
		Domain:              cfg.Domain,
		Endpoint:            cfg.Endpoint,
		CatalogEndpoint:     cfg.CatalogEndpoint,
		BaseCurrency:        cfg.BaseCurrency,
		SupportedProfiles:   cfg.SupportedProfiles,
		MaxIntermediaryHops: cfg.MaxIntermediaryHops,
		InvalidationURL:     cfg.InvalidationURL,
		Keys:                server.StaticKeys(offerKey),
	})
}
