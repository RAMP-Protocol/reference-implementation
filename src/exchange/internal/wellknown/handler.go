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
	"fmt"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/wellknownbuild"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
)

// keyClockSkew backdates the published not_before so a verifier whose clock
// runs slightly behind the Exchange never rejects a freshly built document.
// One hour matches the allowance every other issuer applies (the Broker's
// directory and the deployment key-generation tooling).
const keyClockSkew = time.Hour

// OfferKeyLifetime is the validity lifetime the production Exchange publishes
// for its offer-signing key (the composition root passes it as
// Config.KeyLifetime). Long-lived deliberately: offer-signature verification
// happens close to issuance, and rotation is manual today.
const OfferKeyLifetime = 10 * 365 * 24 * time.Hour

// RebuildInterval is how often a long-lived Exchange re-derives its served
// discovery documents (server.Handlers.RunRefresher, started by run()). It is
// DERIVED from OfferKeyLifetime — never an independent literal — so
// shortening the published lifetime automatically tightens the rebuild
// cadence instead of leaving a frozen directory serving a lapsed window.
var RebuildInterval = server.RebuildIntervalFor(OfferKeyLifetime)

// Config carries the inputs the Exchange discovery documents need. The
// offer-signing Ed25519 key is published in the WBA directory with a validity
// window of [Clock.Now() - keyClockSkew, Clock.Now() + KeyLifetime), re-read
// from Clock at every document build so the periodic refresher re-anchors the
// served window. The clock is supplied by the caller (a production root or a
// test) so this package never reads the wall clock directly.
type Config struct {
	Domain              string
	Endpoint            string // ExchangeService endpoint
	CatalogEndpoint     string // CatalogService endpoint
	BaseCurrency        string
	SupportedProfiles   []string
	MaxIntermediaryHops *int32

	// TermsURI is the terms of service document this Exchange serves and
	// TermsDigest pins which revision of it, so a registration can state which
	// document its operator accepted. The digest is published next to the URI
	// rather than inside the registration block on purpose: an Exchange that
	// inspects no registration data still needs to version its terms.
	TermsURI    string
	TermsDigest string

	// RegistrationDataSchema is the schema this Exchange publishes as the
	// registration_data shape it expects on Register. It is the loaded value the
	// Register gate will check payloads against, which is what keeps the
	// published schema and the enforced schema the same document. nil omits the
	// block, which is the wire's way of saying this Exchange inspects nothing.
	//
	// The type is the loaded *regschema.Schema rather than a bare Struct on
	// purpose. Only regschema.Load produces a usable one, so whatever reaches
	// this field has been held to the protocol's rules for a published schema —
	// a Struct here would have left that resting on the composition root
	// passing the checked variable rather than an unchecked one.
	RegistrationDataSchema *regschema.Schema

	OfferKey    ed25519.PublicKey
	Clock       clock.Clock
	KeyLifetime time.Duration
}

// offerKeySource publishes the offer-signing key with a window anchored to
// the clock at each document build — Handler.Rebuild re-reads this source, so
// running the returned pair's RunRefresher keeps the served window fresh.
type offerKeySource struct {
	key      ed25519.PublicKey
	clk      clock.Clock
	lifetime time.Duration
}

func (s offerKeySource) Keys() []*rampwellknown.Key {
	now := s.clk.Now()
	return []*rampwellknown.Key{
		rampwellknown.NewKey(s.key, now.Add(-keyClockSkew), now.Add(s.lifetime)),
	}
}

// New builds the Exchange's role=ROLE_EXCHANGE overlay-manifest handler plus its
// WBA directory handler, bundled as a server.Handlers pair a caller mounts with a
// single RegisterRoutes call. The compose lives in the shared wellknownbuild
// builder, which schema-validates both documents at construction, so a
// misconfiguration surfaces here rather than at the first request.
func New(cfg Config) (server.Handlers, error) {
	if cfg.Clock == nil || cfg.KeyLifetime <= 0 {
		return server.Handlers{}, fmt.Errorf("wellknown: Config requires a Clock and a positive KeyLifetime")
	}
	// The Exchange WBA directory advertises no revocation_url: the offer-signing
	// key is retired by rotation, publishing the old and the new key together
	// for a grace period, rather than by a keyed revocation list. Keyed
	// revocation (ADR-003 §5) is the Broker's channel for the agent and relay
	// key ids it hosts, not the Exchange's.
	return wellknownbuild.Build(wellknownbuild.Config{
		Manifest: server.Config{
			Role:                rampwellknown.RoleExchange,
			Domain:              cfg.Domain,
			Endpoint:            cfg.Endpoint,
			CatalogEndpoint:     cfg.CatalogEndpoint,
			BaseCurrency:        cfg.BaseCurrency,
			SupportedProfiles:   cfg.SupportedProfiles,
			MaxIntermediaryHops: cfg.MaxIntermediaryHops,
			TermsURI:            cfg.TermsURI,
			TermsDigest:         cfg.TermsDigest,
			// Document() is nil on a nil schema, which leaves the block absent.
			RegistrationDataSchema: cfg.RegistrationDataSchema.Document(),
		},
		Keys: offerKeySource{key: cfg.OfferKey, clk: cfg.Clock, lifetime: cfg.KeyLifetime},
	})
}
