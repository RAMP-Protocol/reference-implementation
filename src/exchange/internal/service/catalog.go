// Package service holds the Exchange business logic. Services accept narrow
// repo interfaces and return proto types at the boundary so the transport
// layer stays a thin adapter.
package service

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

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
// rampwellknown.ErrNoDocument). Composed from rampwellknown.Cache at wiring
// time so the service depends only on the read it makes: ports stay narrow.
type ManifestCache interface {
	Get(ctx context.Context, host string) (*rampwellknown.Manifest, error)
}

// CatalogService handles the CatalogService.PushResources RPC and owns the
// in-memory radix trie rebuilt on every push.
type CatalogService struct {
	repo      repo.CatalogRepo
	tenants   repo.TenantReadRepo
	registry  agentreg.Registry
	manifests ManifestCache
	tx        db.TxRunner
	// exchangeDomain is this Exchange's own canonical domain (EXCHANGE_DOMAIN). It
	// selects the AuthorizedExchange entry in an owner's manifest from which the
	// resource_owner_id payee is read at push. Required: an empty value matches no
	// entry, so every push would be rejected for a missing payee attestation.
	exchangeDomain string
	snapshot       atomic.Pointer[CatalogSnapshot]
	// clk drives any time-dependent CatalogService state. Defaults to
	// clock.System{} per ADR-008 D1; integration tests inject a DeterministicClock
	// via SetClock. Retained for future per-entry clock hooks (e.g. valid_until).
	clk clock.Clock
	// supportedProfiles is the Exchange's advertised extension-profile set, set
	// via SetSupportedProfiles before Bootstrap. rebuild() pre-renders the CoMP
	// projection for these profiles into the snapshot; empty = no
	// pre-render (no comp ext). Single source = cmd/server exchangeSupportedProfiles().
	supportedProfiles []string
}

// NewCatalogService constructs the service. registry and manifests enforce
// caller-signature auth (Gate 1) and per-entry contributor authorization (Gate
// 2); tenants resolves each entry's owning tenant_id server-side from its
// publisher domain (tenant isolation, Arch rule 4). exchangeDomain is this
// Exchange's own canonical domain (EXCHANGE_DOMAIN), used to read the
// resource_owner_id payee from an owner's manifest. Callers must supply real
// implementations — zero values are a programmer error.
func NewCatalogService(
	r repo.CatalogRepo, tenants repo.TenantReadRepo,
	registry agentreg.Registry, manifests ManifestCache, tx db.TxRunner,
	exchangeDomain string,
) *CatalogService {
	return &CatalogService{
		repo:           r,
		tenants:        tenants,
		registry:       registry,
		manifests:      manifests,
		tx:             tx,
		exchangeDomain: exchangeDomain,
		clk:            clock.System{},
	}
}

// SetClock replaces the clock used for time-dependent CatalogService state.
// Test-only seam so integration tests can drive deadline gates without
// sleeping; production wires clock.System{} via NewCatalogService and never
// calls this.
func (s *CatalogService) SetClock(c clock.Clock) {
	s.clk = c
}

// SetSupportedProfiles sets the extension-profile set rebuild() pre-renders into
// the snapshot. Call BEFORE Bootstrap so the first rebuild renders.
// Both production (cmd/server) and the integration harness must call it with the
// SAME list the Exchange advertises, else the CoMP cache is empty.
func (s *CatalogService) SetSupportedProfiles(profiles []string) {
	s.supportedProfiles = profiles
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

	accepted, rejections, warnings, err := s.partitionByContributor(ctx, req)
	if err != nil {
		return nil, err
	}
	// All-or-nothing: a submission is accepted only if EVERY entry is
	// valid. Any per-entry rejection => persist NOTHING and reject the
	// whole submission with per-item reasons, so the publisher fixes and
	// resubmits the whole set. No partial acceptance. Term rules run in two
	// tiers before this point: the wire tier (the protovalidate interceptor —
	// term shape and cross-field rules, refused before this method runs) and
	// the ingest tier (the SDK helpers, in classifyEntry, over canonicalized
	// terms). The gates the Exchange owns — tenant derivation, contributor
	// authorization, resource-owner attestation, URI ownership — run in the
	// same per-entry chain, and this refusal of the whole set is the
	// Exchange's.
	if len(rejections) > 0 {
		return nil, exchange.Newf(exchange.KindInvalidRequest,
			"push rejected, nothing persisted; fix and resubmit: %s", formatRejections(rejections))
	}
	// The accepted entries upsert atomically: a mid-batch failure rolls the
	// whole batch back rather than leaving the catalog half-written (Arch rule 7).
	// The snapshot rebuild reads committed state, so it runs after the commit.
	if len(accepted) > 0 {
		if err := s.persistAccepted(ctx, accepted); err != nil {
			return nil, err
		}
		if err := s.rebuild(ctx); err != nil {
			return nil, exchange.Wrap(exchange.KindInternal, err, "rebuild catalog snapshot")
		}
	}
	return &rampv1.PushResourcesResponse{
		Ver:      helpers.ProtocolVersion,
		Accepted: int32(len(accepted)), //nolint:gosec // per-request batch size fits in int32
		Warnings: warnings,
	}, nil
}

// persistAccepted upserts the accepted entries in one transaction (Arch rule
// 7: a mid-batch failure rolls the whole batch back). The guarded upsert
// refuses a URI move for an existing resource_id — the race-safe backstop
// behind the rejectURIConflicts precheck — and a push that loses that race is
// a caller-fixable conflict, not an infrastructure failure.
func (s *CatalogService) persistAccepted(ctx context.Context, accepted []repo.CatalogEntry) error {
	err := s.tx.WithTx(ctx, func(tx pgx.Tx) error {
		for _, entry := range accepted {
			if _, err := s.repo.UpsertTx(ctx, tx, entry); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, repo.ErrCatalogURIImmutable) {
		return exchange.Wrap(exchange.KindInvalidRequest, err,
			"push rejected, nothing persisted: catalog uri is immutable for an existing resource")
	}
	return exchange.Wrap(exchange.KindInternal, err, "upsert catalog entries")
}

// partitionByContributor walks req.Entries, classifying each through the full
// per-entry gate chain (classifyEntry). Rejected entries are appended to the
// rejections slice; accepted entries are converted to the repo shape and
// returned in accepted order. A non-nil error is an infrastructure failure that
// aborts the whole batch.
func (s *CatalogService) partitionByContributor(
	ctx context.Context,
	req *rampv1.PushResourcesRequest,
) ([]repo.CatalogEntry, []CatalogPushRejection, []string, error) {
	accepted := make([]repo.CatalogEntry, 0, len(req.GetEntries()))
	rejections := make([]CatalogPushRejection, 0)
	var warnings []string
	for _, e := range req.GetEntries() {
		entry, rej, entryWarnings, err := s.classifyEntry(ctx, req, e)
		if err != nil {
			return nil, nil, nil, err
		}
		if rej != nil {
			rejections = append(rejections, *rej)
			continue
		}
		warnings = append(warnings, entryWarnings...)
		accepted = append(accepted, entry)
	}
	// URI-ownership gate: drop any accepted entry whose URI is already
	// owned by a different resource_id (in the catalog or earlier in this batch).
	// Runs after per-entry classification so it sees the materialized URIs and the
	// tenant-scoped resource_ids, and keeps the failure a per-entry rejection
	// rather than the batch-aborting UNIQUE(uri) violation it backstops.
	accepted, uriRejections, err := s.rejectURIConflicts(ctx, accepted)
	if err != nil {
		return nil, nil, nil, err
	}
	rejections = append(rejections, uriRejections...)
	logRejections(ctx, rejections)
	return accepted, rejections, warnings, nil
}

// classifyEntry runs the full per-entry gate chain and returns exactly one of:
// an accepted entry (rej == nil) or a rejection (zero entry, rej != nil). A
// non-nil error is an infrastructure failure that aborts the whole batch.
//
// Chain order: token canonicalization (the SDK's NormalizeResourceEntry, in
// place); server-side tenant derivation (tenant_id comes from the publisher
// domain, never the wire); proto→repo conversion with a tenant-scoped
// resource_id; contributor authorization (Gate 2) and resource-owner
// attestation, both read off the owner manifest; the SDK's ingest-tier term
// checks (validateEntryTerms).
func (s *CatalogService) classifyEntry(
	ctx context.Context,
	req *rampv1.PushResourcesRequest,
	e *rampv1.ResourceEntry,
) (repo.CatalogEntry, *CatalogPushRejection, []string, error) {
	// The terms[] length is not checked here. ResourceEntry.terms carries its
	// cap on the wire, so the validate interceptor refuses an over-cap entry —
	// and with it the whole submission — at the RPC boundary, before this chain
	// runs; a per-entry check here would be unreachable.
	//
	// Canonicalize tokens in place before conversion and validation, so the
	// persisted row and the DiscoverResources→Offer.terms projection carry
	// canonical tokens and the ingest-tier checks compare canonical values.
	helpers.NormalizeResourceEntry(e)
	tenantID, rej, err := s.deriveTenantID(ctx, req, e)
	if err != nil || rej != nil {
		return repo.CatalogEntry{}, rej, nil, err
	}
	entry, err := entryFromProto(tenantID, e)
	if err != nil {
		// A malformed entry drops as a per-entry rejection, not a batch abort.
		rej := reject(uriFromEntry(e), RejectionReasonInvalidEntry)
		return repo.CatalogEntry{}, rej, nil, nil //nolint:nilerr // err->rejection
	}
	// Contributor authorization (Gate 2) and resource-owner attestation both read
	// the owner manifest; resolveManifestGates fetches it once and runs both. A
	// missing manifest, unlisted caller, or un-attested payee drops the entry.
	ownerID, rej, err := s.resolveManifestGates(ctx, e, req.GetCallerId(), entry.URI)
	if err != nil || rej != nil {
		return repo.CatalogEntry{}, rej, nil, err
	}
	entry.ResourceOwnerID = ownerID
	// One term failing the SDK's ingest-tier checks drops the whole entry, with
	// the SDK's message as the rejection detail; lint warnings on accepted
	// terms surface in PushResourcesResponse.warnings[].
	entryWarnings, rej := validateEntryTerms(ctx, entry.URI, e)
	if rej != nil {
		return repo.CatalogEntry{}, rej, nil, nil
	}
	return entry, nil, entryWarnings, nil
}

// deriveTenantID resolves the entry's owning tenant_id server-side from its
// publisher domain via the UNIQUE tenants.domain mapping. A domain with
// no tenant is rejected; a caller-supplied req.tenant_id that disagrees with the
// derived tenant is rejected rather than honoured. The returned tenant_id —
// never req.GetTenantId() — is authoritative.
func (s *CatalogService) deriveTenantID(
	ctx context.Context,
	req *rampv1.PushResourcesRequest,
	e *rampv1.ResourceEntry,
) (string, *CatalogPushRejection, error) {
	tenant, err := s.tenants.ByDomain(ctx, e.GetDomain())
	if err != nil {
		if errors.Is(err, repo.ErrTenantNotFound) {
			return "", reject(uriFromEntry(e), RejectionReasonUnknownPublisherDomain), nil //nolint:nilerr // err->rejection
		}
		return "", nil, exchange.Wrap(exchange.KindInternal, err, "derive tenant from domain")
	}
	if req.GetTenantId() != "" && req.GetTenantId() != tenant.ID {
		return "", reject(uriFromEntry(e), RejectionReasonTenantMismatch), nil
	}
	return tenant.ID, nil, nil
}

// resolveManifestGates fetches the entry's owner manifest once and runs the two
// manifest-backed gates in order: contributor authorization (Gate 2), then
// resource-owner attestation. It returns the attested resource_owner_id payee on
// success. A missing manifest or an unlisted caller yields
// RejectionReasonNotInContributors; a manifest that does not attest a
// resource_owner_id for this Exchange yields RejectionReasonMissingResourceOwner
// (the payee is never inferred — there is no tenant_id fallback). Any other fetch
// error aborts the batch.
func (s *CatalogService) resolveManifestGates(
	ctx context.Context,
	e *rampv1.ResourceEntry,
	callerID, uri string,
) (string, *CatalogPushRejection, error) {
	manifest, err := s.manifests.Get(ctx, e.GetDomain())
	if err != nil {
		if errors.Is(err, rampwellknown.ErrNoDocument) {
			return "", reject(uri, RejectionReasonNotInContributors), nil //nolint:nilerr // err->rejection
		}
		return "", nil, exchange.Wrap(exchange.KindInternal, err, "fetch publisher manifest")
	}
	if !rampwellknown.AuthorizesContributor(manifest, callerID, agentid.FromDirectory) {
		return "", reject(uri, RejectionReasonNotInContributors), nil
	}
	ownerID, ok := rampwellknown.ResourceOwnerID(manifest, s.exchangeDomain)
	if !ok {
		return "", reject(uri, RejectionReasonMissingResourceOwner), nil
	}
	return ownerID, nil, nil
}

// validateEntryTerms runs the SDK's ingest-tier checks
// (helpers.ValidateLicenseTerm) over every term on the entry. It returns either
// the accumulated lint warnings — each RuleWarning.Message verbatim, in term
// order and, within a term, in the SDK's order, the strings that become
// PushResourcesResponse.warnings[] — or, on the first hard violation, the
// RejectionReasonInvalidTerms rejection that drops the whole entry, carrying
// the SDK's message as its Detail. The terms were canonicalized in place by
// helpers.NormalizeResourceEntry at the top of classifyEntry, so the checks see
// canonical tokens.
//
// The per-term face is deliberate: the Exchange never calls
// helpers.ValidateResourceEntry, for three reasons. That face re-runs
// protovalidate over the whole entry, which the validate interceptor already
// did once per request. It normalizes a proto.Clone and returns a verdict,
// while the Exchange must persist canonical tokens and so needs the in-place
// face. And it reports every violation, for a publisher fixing a feed, whereas
// the Exchange stops at the first hard violation per entry (all-or-nothing),
// which is ValidateLicenseTerm's contract.
//
// A refusal is logged at Warn with the entry URI and the violation's rule,
// path and token, so an operator can name the offending value without the
// publisher's feed. The path is made entry-relative ("terms[i].<path>"), the
// form the SDK's entry verdict reports.
//
// This is the SECOND line a term refusal produces, and it is deliberate. Every
// refused entry, whatever refused it, gets one line from logRejections carrying
// the URI and the machine-readable reason. That vocabulary has no place for a
// rule id, a field path or a token, and those three are what an operator names
// the bad value from — so the gate that holds them writes them here, one level
// deeper, rather than widening the shape every refusal shares.
func validateEntryTerms(
	ctx context.Context, uri string, e *rampv1.ResourceEntry,
) ([]string, *CatalogPushRejection) {
	var warnings []string
	for i, term := range e.GetTerms() {
		termWarnings, err := helpers.ValidateLicenseTerm(term)
		if err != nil {
			violation := asRuleViolation(err)
			reqctx.FromContext(ctx).WarnContext(
				ctx, "license term refused at ingest",
				"uri", uri,
				"rule", violation.Rule,
				"path", fmt.Sprintf("terms[%d].%s", i, violation.Path),
				"token", violation.Token,
			)
			rej := reject(uri, RejectionReasonInvalidTerms)
			rej.Detail = violation.Message
			return nil, rej
		}
		for _, w := range termWarnings {
			warnings = append(warnings, w.Message)
		}
	}
	return warnings, nil
}

// asRuleViolation unwraps the error helpers.ValidateLicenseTerm returns into the
// *helpers.RuleViolation it documents. Any other error type is still a refusal
// — the entry must not persist — carried with its message alone.
func asRuleViolation(err error) *helpers.RuleViolation {
	var violation *helpers.RuleViolation
	if errors.As(err, &violation) {
		return violation
	}
	return &helpers.RuleViolation{Message: err.Error()}
}

// rebuild reloads the WHOLE catalog (all tenants) into the in-memory radix trie.
//
// admin:cross_tenant — the ListAll read is DELIBERATELY un-tenant-filtered
// and carries the explicit cross-tenant marker. Discovery spans every
// publisher, so the trie is a single global index. Isolation is preserved at the
// WRITE boundary: tenant_id is derived server-side from the publisher domain
// and a URI belongs to exactly one row (UNIQUE(uri)), so the
// global read cannot surface a cross-tenant shadowing. Lookup() inherits this —
// it returns the single owning row, never another tenant's.
func (s *CatalogService) rebuild(ctx context.Context) error {
	rows, err := s.repo.ListAll(ctx) // admin:cross_tenant — intentional global read; see doc above
	if err != nil {
		return err
	}
	snap := newEmptySnapshot()
	for _, row := range rows {
		snap.trie.Insert(row.URIPrefix, row)
		snap.byURI[row.URI] = row
		snap.tenant[row.ResourceID] = row.TenantID
		// Decode the row's terms ONCE here. A row whose stored JSONB fails
		// to decode is cached as zero terms (decodeRowTerms logs + returns nil), so
		// one bad row cannot poison the snapshot or crash rebuild.
		snap.terms[row.ResourceID] = decodeRowTerms(ctx, row)
		// Decode the row's metadata ONCE here too (same rationale). A row without
		// metadata or whose document fails to decode caches nil and yields no
		// metadata on the Offer.
		if md := decodeRowMetadata(ctx, row); md != nil {
			snap.metadata[row.ResourceID] = md
		}
		// Pre-render the CoMP projection for each stored term x supported profile
		// ONCE here, so the discovery hot path looks up a blob rather
		// than rendering per request. Runs AFTER terms+metadata are cached for the row.
		renderRowProfiles(ctx, snap, row.ResourceID, s.supportedProfiles)
	}
	s.snapshot.Store(snap)
	return nil
}
