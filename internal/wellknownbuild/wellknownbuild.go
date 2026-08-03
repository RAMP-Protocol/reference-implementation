// Package wellknownbuild composes a service's public discovery surface — the
// RAMP commercial overlay manifest at /.well-known/ramp.json plus the pure Web
// Bot Auth key directory at /.well-known/http-message-signatures-directory —
// from one shared builder. Both the Exchange and the Broker serve the same
// handler pair over internal/rampwellknown/server; the compose (manifest
// handler + WBA handler, each schema-validated at construction) is written
// once here and parameterized on the role/manifest config, the WBA key
// source, and the optional revocation URL, so the two services cannot drift
// on the sequence. It is discovery plumbing shared BELOW both services (never
// importing either), not a service/orchestration layer.
package wellknownbuild

import (
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
)

// Config carries the inputs a service's discovery surface needs: the overlay
// manifest config (role, domain, endpoints, currency, profiles), the WBA key
// source publishing the service's signing key(s), and the optional
// revocation_url the WBA directory advertises (Broker-only today: the
// Exchange retires its offer-signing key by rotation with a dual-key grace
// period, not by a keyed revocation list, so it leaves the field empty).
type Config struct {
	Manifest      server.Config
	Keys          server.KeySource
	RevocationURL string
}

// Build constructs the overlay-manifest handler plus the WBA directory
// handler, bundled as a server.Handlers pair a caller mounts with a single
// RegisterRoutes call. Both documents are schema-validated at construction,
// so a misconfiguration surfaces here rather than at the first request.
func Build(cfg Config) (server.Handlers, error) {
	manifest, err := server.NewHandler(cfg.Manifest)
	if err != nil {
		return server.Handlers{}, err
	}
	wba, err := server.NewWBAHandler(server.WBAConfig{
		Keys:          cfg.Keys,
		RevocationURL: cfg.RevocationURL,
	})
	if err != nil {
		return server.Handlers{}, err
	}
	return server.Handlers{Manifest: manifest, WBA: wba}, nil
}
