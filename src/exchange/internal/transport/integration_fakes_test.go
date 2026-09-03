//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
)

// allowAllRegistry stores callers in memory and always accepts their
// registration. Tests that exercise the happy PushResources path use this to
// skip the RFC 9421 signature gate without wiring a full fixture origin.
type allowAllRegistry struct {
	mu   sync.Mutex
	keys map[string]ed25519.PublicKey
}

func newAllowAllRegistry() *allowAllRegistry {
	return &allowAllRegistry{keys: map[string]ed25519.PublicKey{}}
}

func (r *allowAllRegistry) put(id string, pub ed25519.PublicKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[id] = pub
}

func (r *allowAllRegistry) LookupPublicKey(_ context.Context, id string) (ed25519.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if k, ok := r.keys[id]; ok {
		return k, nil
	}
	return nil, agentreg.ErrUnknown
}

func (r *allowAllRegistry) RegisterFromDirectory(_ context.Context, _ string, _ string) error {
	return errors.New("allowAllRegistry: self-signup not supported in tests")
}

func (r *allowAllRegistry) RefreshDirectoryKey(_ context.Context, _ string) error {
	return errors.New("allowAllRegistry: directory refresh not supported in tests")
}

// harnessResourceOwner is the resource_owner_id the catch-all manifest stub
// attests for every push, so accepted entries carry a payee and pass the gate.
const harnessResourceOwner = "owner-test"

// allowAllManifestCache returns a publisher manifest that lists the caller as a
// catalog_contributor for the requested domain AND attests resourceOwner on
// exchangeDomain, so both the contributor gate (Gate 2) and the resource-owner
// gate accept in the catch-all test harness. It satisfies service.ManifestCache.
type allowAllManifestCache struct {
	caller         string
	exchangeDomain string
	resourceOwner  string
}

// newAllowAllManifestCache builds the catch-all stub that authorizes caller and
// attests harnessResourceOwner on harnessExchangeDomain, so both the contributor
// gate and the resource-owner gate accept. Use this everywhere rather than the
// bare struct literal, so no construction site forgets the attestation.
func newAllowAllManifestCache(caller string) *allowAllManifestCache {
	return &allowAllManifestCache{
		caller:         caller,
		exchangeDomain: harnessExchangeDomain,
		resourceOwner:  harnessResourceOwner,
	}
}

func (c *allowAllManifestCache) Get(_ context.Context, domain string) (*rampwellknown.Manifest, error) {
	ext, err := structpb.NewStruct(map[string]any{"resource_owner_id": c.resourceOwner})
	if err != nil {
		return nil, err
	}
	return &rampwellknown.Manifest{
		Ver:    rampwellknown.Version,
		Role:   rampwellknown.RolePublisher,
		Domain: domain,
		CatalogContributors: []*rampv1.CatalogContributor{
			{Domain: c.caller, Relationship: "publisher"},
		},
		Exchanges: []*rampv1.AuthorizedExchange{
			{Domain: c.exchangeDomain, Ext: ext},
		},
	}, nil
}
