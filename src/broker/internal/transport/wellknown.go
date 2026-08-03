package transport

import (
	"fmt"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/wellknownbuild"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// brokerKeyLifetime bounds the validity window the Broker publishes for its OWN
// relay key: not_before is the issued-at instant (the signer clock at document
// build) and not_after is issued-at + brokerKeyLifetime. A bounded window means a
// rotated-out relay key stops verifying on its own rather than remaining valid
// for decades.
const brokerKeyLifetime = 90 * 24 * time.Hour

// agentKeyNotBefore / agentKeyNotAfter are the wide placeholder window every
// agent key folded in from the registry inherits. The registry's on-disk JWKS
// carries no per-key window, so there is nothing tighter to publish for them yet.
//
// LIMITATION: because this window is operator-flattened, a registry key cannot
// express its own expiry through this surface — an expired agent key keeps
// verifying until removed from the file. Benign while the registry is statically
// operator-provisioned (the file IS the source of truth); it becomes a latent
// expiry bypass once dynamic agent registration lands, at which point folded
// keys must carry their own not_before/not_after. Agents that rotate today
// publish bounded windows in their OWN WBA directories, not here.
//
// TODO: fold per-key not_before/not_after through the registry (KeyEntry +
// KeyRegistry) so agent keys express their own bounded window instead of
// inheriting this placeholder — a follow-up beyond the broker-own-key window fix.
var (
	agentKeyNotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	agentKeyNotAfter  = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
)

// WellKnownConfig carries the inputs the Broker's discovery surface needs: a
// role=ROLE_BROKER commercial overlay manifest (no identity keys) plus a WBA
// directory carrying the relay key and every folded agent key.
type WellKnownConfig struct {
	Signer        *signing.CoSigner
	BrokerID      string
	Keys          *KeyRegistry
	RevocationURL string
}

// NewWellKnown builds the Broker's role=ROLE_BROKER overlay-manifest handler
// plus its WBA directory handler. The WBA directory carries the relay key plus
// every key in the agent registry so RFC 9421 verifiers resolve every
// thumbprint the Broker speaks for from one canonical document. Both documents
// are schema-validated at construction, so a misconfiguration surfaces here
// rather than at the first request. v1 requires an agent registry; a nil Keys is
// a configuration error returned to the caller. RevocationURL, when non-empty,
// is published as the WBA directory's revocation_url so verifiers learn where to
// poll the Broker's KeyRevocationList; empty omits the field.
//
// The WBA directory reflects a snapshot of the registry taken at construction.
// If dynamic agent registration is added, the mutation site must rebuild the
// served document (server.Handler.Rebuild re-reads the KeySource); the flattened
// key window above must also gain per-key bounds at that point.
func NewWellKnown(cfg WellKnownConfig) (server.Handlers, error) {
	if cfg.Keys == nil {
		return server.Handlers{}, fmt.Errorf("transport: broker well-known requires a non-nil *KeyRegistry")
	}
	return wellknownbuild.Build(wellknownbuild.Config{
		Manifest: server.Config{
			Role:   rampwellknown.RoleBroker,
			Domain: cfg.Signer.Domain(),
		},
		Keys:          brokerKeySource{signer: cfg.Signer, keys: cfg.Keys},
		RevocationURL: cfg.RevocationURL,
	})
}

// brokerKeySource yields the relay key plus the registry's agent keys as
// published JWKs. The relay key is always present (even when the registry is
// empty) so verifiers can confirm Broker→Exchange signatures. Keys carry no
// kid — identity is the RFC 7638 thumbprint — so dedup is by the JWK `x`.
type brokerKeySource struct {
	signer *signing.CoSigner
	keys   *KeyRegistry
}

func (s brokerKeySource) Keys() []*rampwellknown.Key {
	relayX := rampwellknown.EncodeEd25519X(s.signer.PublicKey())
	// The broker's OWN relay key carries a realistic issued-at → bounded not-after
	// window anchored to the signer clock; the folded agent keys still inherit the
	// wide placeholder window (the registry carries no per-key bounds — see TODO).
	issuedAt := s.signer.Now()
	keys := []*rampwellknown.Key{
		rampwellknown.NewKey(s.signer.PublicKey(), issuedAt, issuedAt.Add(brokerKeyLifetime)),
	}
	seen := map[string]struct{}{relayX: {}}
	notBefore := agentKeyNotBefore.Format(time.RFC3339)
	notAfter := agentKeyNotAfter.Format(time.RFC3339)
	for _, k := range s.keys.Document().Keys {
		if _, dup := seen[k.X]; dup {
			continue
		}
		seen[k.X] = struct{}{}
		// Registry entries are pre-filtered to OKP/Ed25519 with a valid 32-byte
		// x (see KeyRegistry.LoadBytes), and X is already base64url, so the
		// shared KeyFromEncodedX helper stamps the fixed RAMP headers.
		keys = append(keys, rampwellknown.KeyFromEncodedX(k.X, notBefore, notAfter))
	}
	return keys
}
