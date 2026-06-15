// Package service holds the Exchange business logic. Services accept narrow
// repo interfaces and return proto types at the boundary so the transport
// layer stays a thin adapter.
package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	radix "github.com/armon/go-radix"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// RejectionReasonNotInContributors is the machine-readable reason emitted in
// CatalogPushRejection when the caller is authenticated but is not listed
// as a contributor in the publisher's ramp.json.
//
// The upstream proto sync (W1 of t3vk) collapsed PushResourcesResponse to a
// pair of int32 counts, so rejection detail is no longer carried on the wire;
// it is retained here for structured logging and future obligation routing
// (the planned per-entry result vocabulary will reintroduce the wire field).
const RejectionReasonNotInContributors = "caller_not_in_catalog_contributors"

// CatalogPushRejection captures a single rejected entry along with its
// machine-readable reason. Internal type — no longer a proto message because
// the canonical PushResourcesResponse only carries counts.
type CatalogPushRejection struct {
	URI    string
	Reason string
}

// defaultCatalogURIScheme is the scheme used to materialize a CatalogEntry
// URI from the `(domain, path)` pair in a ResourceEntry message. Production
// always uses "https"; the e2e compose stack overrides via
// EXCHANGE_CATALOG_URI_SCHEME so catalog URIs can route through the in-network
// http edge worker. Exported via SetCatalogURIScheme for test overrides; the
// Exchange binary calls it once at startup from runhttp.EnvOr.
const defaultCatalogURIScheme = "https"

var catalogURIScheme atomic.Value // stores string

// SetCatalogURIScheme overrides the scheme used when materializing
// catalog URIs in entryFromProto and uriFromEntry. Call once at startup
// (or in a test setup) with the value from EXCHANGE_CATALOG_URI_SCHEME.
// Empty scheme falls back to defaultCatalogURIScheme.
func SetCatalogURIScheme(scheme string) {
	if scheme == "" {
		scheme = defaultCatalogURIScheme
	}
	catalogURIScheme.Store(scheme)
}

func currentCatalogURIScheme() string {
	if v, ok := catalogURIScheme.Load().(string); ok && v != "" {
		return v
	}
	return defaultCatalogURIScheme
}

// CatalogSnapshot is the published, read-only view consumed by the
// Exchange service. Built by the CatalogService and swapped atomically.
type CatalogSnapshot struct {
	trie   *radix.Tree
	byID   map[string]repo.CatalogEntry
	tenant map[string]string // resource_id -> tenant_id (redundant, for readability)
}

// LookupVerdict describes how a catalog lookup resolved.
type LookupVerdict int

const (
	// LookupMiss means no catalog entry matches the requested URI.
	LookupMiss LookupVerdict = iota
	// LookupHitPublic means an entry matched. The v1 surface emits a
	// per-request offer.
	LookupHitPublic
)

// Lookup returns the single catalog entry that matches uri by longest prefix.
// Returns (entry, LookupHitPublic) on hit; (zero, LookupMiss) on miss.
func (s *CatalogSnapshot) Lookup(uri string) (repo.CatalogEntry, LookupVerdict) {
	if s == nil || s.trie == nil {
		return repo.CatalogEntry{}, LookupMiss
	}
	_, raw, ok := s.trie.LongestPrefix(uri)
	if !ok {
		return repo.CatalogEntry{}, LookupMiss
	}
	entry, typed := raw.(repo.CatalogEntry)
	if !typed {
		return repo.CatalogEntry{}, LookupMiss
	}
	return entry, LookupHitPublic
}

// ManifestCache is the narrow port the CatalogService needs from the shared
// publisher-manifest cache: fetch a host's manifest (a 404 surfaces as
// rampwellknown.ErrNoManifest). Composed from rampwellknown.Cache at wiring
// time so the service depends only on the read it makes (CLAUDE.md rule 3).
type ManifestCache interface {
	Get(ctx context.Context, host string) (*rampwellknown.Manifest, error)
}

// CatalogService handles the CatalogService.PushResources RPC and owns the
// in-memory radix trie rebuilt on every push.
type CatalogService struct {
	repo      repo.CatalogRepo
	registry  agentreg.Registry
	manifests ManifestCache
	tx        db.TxRunner
	snapshot  atomic.Pointer[CatalogSnapshot]
	// clk drives any time-dependent CatalogService state. Defaults to
	// clock.System{} per ADR-008 D1; integration tests inject a
	// DeterministicClock via SetClock so deadline gates can be driven
	// without sleeping. The public-offer materialisation path that used
	// this field was removed in W3 of t3vk along with the ye6f-9
	// OffersService; the field is retained for future per-entry clock
	// hooks (e.g. catalog entry valid_until enforcement).
	clk clock.Clock
}

// NewCatalogService constructs the service. registry and manifests are used
// by PushResources to enforce caller-signature auth (Gate 1) and per-entry
// contributor authorization (Gate 2); callers must supply real implementations
// — passing zero values is a programmer error, not silently tolerated.
func NewCatalogService(
	r repo.CatalogRepo, registry agentreg.Registry, manifests ManifestCache, tx db.TxRunner,
) *CatalogService {
	return &CatalogService{repo: r, registry: registry, manifests: manifests, tx: tx, clk: clock.System{}}
}

// SetClock replaces the clock used for time-dependent CatalogService state.
// Test-only seam so integration tests can drive deadline gates without
// sleeping; production wires clock.System{} via NewCatalogService and never
// calls this.
func (s *CatalogService) SetClock(c clock.Clock) {
	s.clk = c
}

// Bootstrap loads existing rows into the snapshot so that discovery works
// after a service restart without requiring a PushResources first.
func (s *CatalogService) Bootstrap(ctx context.Context) error {
	return s.rebuild(ctx)
}

// Snapshot returns the current catalog snapshot (never nil after Bootstrap).
func (s *CatalogService) Snapshot() *CatalogSnapshot {
	snap := s.snapshot.Load()
	if snap == nil {
		empty := newEmptySnapshot()
		s.snapshot.Store(empty)
		return empty
	}
	return snap
}

// PushResources upserts the entries and swaps the in-memory snapshot. Gate 1
// (caller-signature) is enforced by the transport layer before invocation;
// this method enforces Gate 2 (contributor authorization) per entry.
func (s *CatalogService) PushResources(
	ctx context.Context,
	req *rampv1.PushResourcesRequest,
) (*rampv1.PushResourcesResponse, error) {
	if req == nil {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "nil request")
	}
	if req.GetTenantId() == "" {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "tenant_id required")
	}
	if req.GetCallerId() == "" {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "caller_id required")
	}
	if len(req.GetEntries()) == 0 {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "entries required")
	}

	accepted, rejections, err := s.partitionByContributor(ctx, req)
	if err != nil {
		return nil, err
	}
	// The accepted entries upsert atomically: a mid-batch failure rolls the
	// whole batch back rather than leaving the catalog half-written (Arch rule 7).
	// The snapshot rebuild reads committed state, so it runs after the commit.
	if len(accepted) > 0 {
		if err := s.tx.WithTx(ctx, func(tx pgx.Tx) error {
			for _, entry := range accepted {
				if _, err := s.repo.UpsertTx(ctx, tx, entry); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, exchange.Wrap(exchange.KindInternal, err, "upsert catalog entries")
		}
		if err := s.rebuild(ctx); err != nil {
			return nil, exchange.Wrap(exchange.KindInternal, err, "rebuild catalog snapshot")
		}
	}
	return &rampv1.PushResourcesResponse{
		Accepted: int32(len(accepted)),   //nolint:gosec // per-request batch size fits in int32
		Rejected: int32(len(rejections)), //nolint:gosec // per-request batch size fits in int32
	}, nil
}

// partitionByContributor walks req.Entries, resolving each entry's provider
// manifest and checking caller authorization. Entries whose domain either
// publishes no manifest or does not list the caller as a contributor are
// appended to the rejections slice; everything else is converted to the repo
// shape and returned in accepted order.
func (s *CatalogService) partitionByContributor(
	ctx context.Context,
	req *rampv1.PushResourcesRequest,
) ([]repo.CatalogEntry, []CatalogPushRejection, error) {
	accepted := make([]repo.CatalogEntry, 0, len(req.GetEntries()))
	rejections := make([]CatalogPushRejection, 0)
	for _, e := range req.GetEntries() {
		entry, err := entryFromProto(req.GetTenantId(), e)
		if err != nil {
			rejections = append(rejections, CatalogPushRejection{
				URI:    uriFromEntry(e),
				Reason: "invalid_entry",
			})
			continue
		}
		manifest, err := s.manifests.Get(ctx, e.GetDomain())
		if err != nil {
			if errors.Is(err, rampwellknown.ErrNoManifest) {
				rejections = append(rejections, CatalogPushRejection{
					URI:    entry.URI,
					Reason: RejectionReasonNotInContributors,
				})
				continue
			}
			return nil, nil, exchange.Wrap(exchange.KindInternal, err, "fetch publisher manifest")
		}
		if !rampwellknown.AuthorizesContributor(manifest, req.GetCallerId()) {
			rejections = append(rejections, CatalogPushRejection{
				URI:    entry.URI,
				Reason: RejectionReasonNotInContributors,
			})
			continue
		}
		accepted = append(accepted, entry)
	}
	return accepted, rejections, nil
}

func (s *CatalogService) rebuild(ctx context.Context) error {
	rows, err := s.repo.ListAll(ctx)
	if err != nil {
		return err
	}
	snap := newEmptySnapshot()
	for _, row := range rows {
		snap.trie.Insert(row.URIPrefix, row)
		snap.byID[row.ResourceID] = row
		snap.tenant[row.ResourceID] = row.TenantID
	}
	s.snapshot.Store(snap)
	return nil
}

func newEmptySnapshot() *CatalogSnapshot {
	return &CatalogSnapshot{
		trie:   radix.New(),
		byID:   map[string]repo.CatalogEntry{},
		tenant: map[string]string{},
	}
}

// entryFromProto converts a ResourceEntry message into the repo.CatalogEntry
// shape, materializing the stable resource_id and the pricing JSON payload.
func entryFromProto(tenantID string, e *rampv1.ResourceEntry) (repo.CatalogEntry, error) {
	if e.GetDomain() == "" || e.GetPath() == "" {
		return repo.CatalogEntry{}, fmt.Errorf("missing domain/path")
	}
	uri := currentCatalogURIScheme() + "://" + e.GetDomain() + e.GetPath()
	id := e.GetContentId()
	if id == "" {
		id = uuid.NewString()
	}
	pricing := defaultPricing(e)
	pjson, err := json.Marshal(pricing)
	if err != nil {
		return repo.CatalogEntry{}, fmt.Errorf("marshal pricing: %w", err)
	}
	return repo.CatalogEntry{
		ResourceID:     id,
		TenantID:       tenantID,
		URI:            uri,
		URIPrefix:      uri,
		PricingJSON:    pjson,
		LicensingJSON:  []byte(`{}`),
		DeliveryMethod: "INSTRUCTIONS",
	}, nil
}

// uriFromEntry reconstructs the URI from an entry even when the proto is
// missing fields — used only for the rejection message so invalid pushes show
// up as "uri": "" rather than being silently dropped.
func uriFromEntry(e *rampv1.ResourceEntry) string {
	if e.GetDomain() == "" && e.GetPath() == "" {
		return ""
	}
	return currentCatalogURIScheme() + "://" + e.GetDomain() + e.GetPath()
}

// PricingDoc is the JSONB shape persisted in catalog.pricing. Service stores
// it verbatim and projects back into a rampv1.Pricing on discovery.
type PricingDoc struct {
	Model    string  `json:"model"`
	Rate     float64 `json:"rate"`
	Currency string  `json:"currency"`
	UnitCost float64 `json:"unit_cost"`
	Unit     string  `json:"unit"`
	EstQty   int32   `json:"estimated_quantity,omitempty"`
}

// defaultPricing fills in reasonable defaults for the scrappy demo: per-access
// pricing at $0.05 denominated in USD, estimated_quantity carried through when
// the catalog push supplied it.
func defaultPricing(e *rampv1.ResourceEntry) PricingDoc {
	return PricingDoc{
		Model:    rampv1.PricingModel_PRICING_MODEL_PER_ACCESS.String(),
		Rate:     0.05,
		Currency: "USD",
		UnitCost: 0.05,
		Unit:     "access",
		EstQty:   e.GetEstimatedQuantity(),
	}
}
