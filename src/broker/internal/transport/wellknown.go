package transport

import (
	"fmt"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/wellknownbuild"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
)

// brokerKeyLifetime bounds the validity window the Broker publishes for every
// key it speaks for — the co-signing identity key and every registry key (the
// relay key). Each window is [now - brokerKeyClockSkew, now + brokerKeyLifetime),
// with now read from the signer clock at each document build. A bounded window
// means a rotated-out key stops verifying on its own rather than remaining
// valid for decades in a verifier's stale cached directory.
const brokerKeyLifetime = 90 * 24 * time.Hour

// brokerKeyClockSkew backdates every published not_before so a verifier whose
// clock runs slightly behind the Broker never rejects a freshly built
// document. The window start recurs at every rebuild (daily), not just at
// boot, so without this allowance the rejection edge would too. One hour
// matches the allowance the deployment key-generation tooling applies to the
// static WBA documents it renders.
const brokerKeyClockSkew = time.Hour

// WellKnownRebuildInterval is how often the Broker re-derives its served
// discovery documents (server.Handlers.RunRefresher, started by run()). It is
// DERIVED from brokerKeyLifetime — never an independent literal — so
// shortening the lifetime automatically tightens the rebuild cadence instead
// of leaving a frozen directory serving lapsed windows.
var WellKnownRebuildInterval = server.RebuildIntervalFor(brokerKeyLifetime)

// WellKnownConfig carries the inputs the Broker's discovery surface needs: a
// role=ROLE_BROKER commercial overlay manifest (no identity keys) plus a WBA
// directory carrying the Broker's own keys (the co-signing identity key and
// the relay key).
type WellKnownConfig struct {
	Signer        *signing.CoSigner
	BrokerID      string
	Keys          *KeyRegistry
	RevocationURL string
}

// NewWellKnown builds the Broker's role=ROLE_BROKER overlay-manifest handler
// plus its WBA directory handler. The WBA directory carries the Broker's own
// keys — the co-signing identity key plus every registry key (the relay key) —
// so RFC 9421 verifiers resolve every thumbprint the Broker speaks for from one
// canonical document. Both documents are schema-validated at construction, so a
// misconfiguration surfaces here rather than at the first request. A nil Keys
// is a configuration error returned to the caller. RevocationURL, when
// non-empty, is published as the WBA directory's revocation_url so verifiers
// learn where to poll the Broker's KeyRevocationList; empty omits the field.
//
// The registry's KEY SET is fixed at construction, but the published validity
// windows depend on the clock at build time — so the served documents do need
// periodic rebuilding. The caller keeps them fresh by running the returned
// pair's RunRefresher (run() starts it at WellKnownRebuildInterval); without
// it, a Broker up longer than brokerKeyLifetime would serve only lapsed
// windows.
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

// brokerKeySource yields the co-signing identity key plus the registry's keys
// (the relay key) as published JWKs. The identity key is always present (even
// when the registry is empty); the relay key lets verifiers confirm
// Broker→Exchange signatures. Keys carry no kid — identity is the RFC 7638
// thumbprint — so dedup is by the JWK `x`.
type brokerKeySource struct {
	signer *signing.CoSigner
	keys   *KeyRegistry
}

func (s brokerKeySource) Keys() []*rampwellknown.Key {
	identityX := rampwellknown.EncodeEd25519X(s.signer.PublicKey())
	// Every published key carries the same bounded window, anchored to the
	// signer clock at THIS build. Handler.Rebuild re-reads this source, so the
	// periodic refresher re-anchors the served windows on every rebuild. The
	// window starts brokerKeyClockSkew before the build instant so verifiers
	// with slightly-behind clocks accept a just-built document.
	issuedAt := s.signer.Now()
	notBefore := issuedAt.Add(-brokerKeyClockSkew)
	notAfter := issuedAt.Add(brokerKeyLifetime)
	keys := []*rampwellknown.Key{
		rampwellknown.NewKey(s.signer.PublicKey(), notBefore, notAfter),
	}
	seen := map[string]struct{}{identityX: {}}
	for _, pub := range s.keys.Keys() {
		x := rampwellknown.EncodeEd25519X(pub)
		if _, dup := seen[x]; dup {
			continue
		}
		seen[x] = struct{}{}
		keys = append(keys, rampwellknown.NewKey(pub, notBefore, notAfter))
	}
	return keys
}
