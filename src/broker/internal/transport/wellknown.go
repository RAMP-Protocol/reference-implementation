package transport

import (
	"fmt"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// brokerKeyNotBefore / brokerKeyNotAfter bound the validity window the Broker
// publishes for its relay key and the agent keys folded in from the registry.
// The registry's on-disk JWKS carries no per-key window, so every folded agent
// key inherits this single flattened window.
//
// LIMITATION: because the window is operator-flattened, a registry key cannot
// express its own expiry through this surface — an expired agent key keeps
// verifying until removed from the file. Benign while the registry is statically
// operator-provisioned (the file IS the source of truth); it becomes a latent
// expiry bypass once dynamic agent registration lands, at which point folded
// keys must carry their own not_before/not_after. Agents that rotate today
// publish bounded windows in their OWN manifests, not here.
var (
	brokerKeyNotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	brokerKeyNotAfter  = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
)

// WellKnownConfig carries the inputs the Broker's role=ROLE_BROKER manifest
// needs. It mirrors the Exchange's wellknown.Config shape so both producers
// construct their server.Handler the same way — a Config in, a
// (*server.Handler, error) out, with no wrapper type and no construction-time
// panic.
type WellKnownConfig struct {
	Signer          *signing.CoSigner
	BrokerID        string
	Keys            *KeyRegistry
	InvalidationURL string
}

// NewWellKnown builds the Broker's role=ROLE_BROKER manifest handler, carrying
// the relay key plus every key in the agent registry so RFC 9421 verifiers
// resolve every kid the Broker speaks for from one canonical document. The
// returned *server.Handler serves GET /.well-known/ramp.json (mount it with
// RegisterRoutes) and is schema-validated at construction, so a misconfiguration
// surfaces here rather than at the first request — the shared handler never
// fails at serve time. v1 requires an agent registry; a nil Keys is a
// configuration error returned to the caller. invalidationURL, when non-empty,
// is published as the manifest's invalidation_url so verifiers learn where to
// poll the Broker's KeyInvalidationList (ADR-003 §5); empty omits the field.
//
// The manifest reflects a snapshot of the registry taken at construction. If
// dynamic agent registration is added, the mutation site must rebuild the served
// document (server.Handler.Rebuild re-reads the KeySource); the flattened key
// window above must also gain per-key bounds at that point.
func NewWellKnown(cfg WellKnownConfig) (*server.Handler, error) {
	if cfg.Keys == nil {
		return nil, fmt.Errorf("transport: broker well-known requires a non-nil *KeyRegistry")
	}
	return server.NewHandler(server.Config{
		Role:            rampwellknown.RoleBroker,
		Domain:          cfg.Signer.Domain(),
		Keys:            brokerKeySource{signer: cfg.Signer, brokerID: cfg.BrokerID, keys: cfg.Keys},
		InvalidationURL: cfg.InvalidationURL,
	})
}

// brokerKeySource yields the relay key plus the registry's agent keys as
// published JWKs. The relay key is always present (even when the registry is
// empty) so verifiers can confirm Broker→Exchange signatures.
type brokerKeySource struct {
	signer   *signing.CoSigner
	brokerID string
	keys     *KeyRegistry
}

func (s brokerKeySource) Keys() []*rampwellknown.Key {
	relayKid := s.brokerID + "-ed25519"
	keys := []*rampwellknown.Key{
		rampwellknown.NewKey(relayKid, s.signer.PublicKey(), brokerKeyNotBefore, brokerKeyNotAfter),
	}
	seen := map[string]struct{}{relayKid: {}}
	notBefore := brokerKeyNotBefore.Format(time.RFC3339)
	notAfter := brokerKeyNotAfter.Format(time.RFC3339)
	for _, k := range s.keys.Document().Keys {
		if _, dup := seen[k.Kid]; dup {
			continue
		}
		seen[k.Kid] = struct{}{}
		// Registry entries are pre-filtered to OKP/Ed25519 with a valid 32-byte
		// x (see KeyRegistry.LoadBytes), and X is already base64url, so the
		// shared KeyFromEncodedX helper stamps the fixed RAMP headers.
		keys = append(keys, rampwellknown.KeyFromEncodedX(k.Kid, k.X, notBefore, notAfter))
	}
	return keys
}
