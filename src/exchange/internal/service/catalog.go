// Package service holds the Exchange business logic. Services accept narrow
// repo interfaces and return proto types at the boundary so the transport
// layer stays a thin adapter.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	radix "github.com/armon/go-radix"
	"github.com/google/uuid"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// CatalogSnapshot is the published, read-only view consumed by the
// Marketplace service. Built by the CatalogService and swapped atomically.
type CatalogSnapshot struct {
	trie   *radix.Tree
	byID   map[string]repo.CatalogEntry
	tenant map[string]string // resource_id -> tenant_id (redundant, for readability)
}

// Lookup returns the single catalog entry that matches uri by longest prefix.
// Returns (entry, true) on hit; (zero, false) on miss.
func (s *CatalogSnapshot) Lookup(uri string) (repo.CatalogEntry, bool) {
	if s == nil || s.trie == nil {
		return repo.CatalogEntry{}, false
	}
	_, raw, ok := s.trie.LongestPrefix(uri)
	if !ok {
		return repo.CatalogEntry{}, false
	}
	entry, typed := raw.(repo.CatalogEntry)
	if !typed {
		return repo.CatalogEntry{}, false
	}
	return entry, true
}

// CatalogService handles the CatalogService.PushResources RPC and owns the
// in-memory radix trie rebuilt on every push.
type CatalogService struct {
	repo     repo.CatalogRepo
	snapshot atomic.Pointer[CatalogSnapshot]
}

// NewCatalogService constructs the service. Call Bootstrap after wiring to
// populate the initial snapshot from the DB.
func NewCatalogService(r repo.CatalogRepo) *CatalogService {
	return &CatalogService{repo: r}
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

// PushResources upserts the entries and swaps the in-memory snapshot.
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
	if len(req.GetEntries()) == 0 {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "entries required")
	}
	var accepted, rejected int32
	for _, e := range req.GetEntries() {
		entry, err := entryFromProto(req.GetTenantId(), e)
		if err != nil {
			rejected++
			continue
		}
		if _, err := s.repo.Upsert(ctx, entry); err != nil {
			return nil, exchange.Wrap(exchange.KindInternal, err, "upsert catalog entry")
		}
		accepted++
	}
	if err := s.rebuild(ctx); err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "rebuild catalog snapshot")
	}
	return &rampv1.PushResourcesResponse{Accepted: accepted, Rejected: rejected}, nil
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
	uri := "https://" + e.GetDomain() + e.GetPath()
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
