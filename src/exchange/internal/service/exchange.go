package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// ExchangeConfig bundles wiring knobs for the service.
type ExchangeConfig struct {
	Exchange       string        // canonical exchange domain (echoed in ResourceResponse)
	OfferTTL       time.Duration // default 5m
	URLTTL         time.Duration // default 5m
	ReportWindow   time.Duration // default 24h
	IdempotencyLRU int           // default 1024
}

func (c ExchangeConfig) withDefaults() ExchangeConfig {
	if c.OfferTTL == 0 {
		c.OfferTTL = 5 * time.Minute
	}
	if c.URLTTL == 0 {
		c.URLTTL = 5 * time.Minute
	}
	if c.ReportWindow == 0 {
		c.ReportWindow = 24 * time.Hour
	}
	if c.IdempotencyLRU == 0 {
		c.IdempotencyLRU = 1024
	}
	return c
}

// ExchangeService implements DiscoverResources, ExecuteTransaction, and
// ReportUsage. It depends on narrow repos, a billing adapter, a URL-signer
// dispatcher, and an offer signer.
type ExchangeService struct {
	tx           db.TxRunner
	catalog      *CatalogService
	tenants      repo.TenantRepo
	agents       repo.AgentRepo
	agentReg     agentreg.Registry
	transactions repo.TransactionRepo
	obligations  repo.ObligationRepo
	billing      billing.Adapter
	offerSigner  *signing.Ed25519Signer
	keyStore     signing.KeyStore
	clk          clock.Clock
	cfg          ExchangeConfig
	logger       *slog.Logger

	idemMu  sync.Mutex
	idemHit map[string]string // tx_request_id -> transaction_id (LRU-bounded)
	idemSeq []string
}

// ExchangeDeps bundles the wiring dependencies.
type ExchangeDeps struct {
	// TxRunner opens transactions for multi-statement writes. Wiring passes
	// db.PoolRunner{Pool: pool}; the service depends only on this narrow
	// port (CLAUDE.md Rule 3 + Rule 7).
	TxRunner db.TxRunner
	Catalog  *CatalogService
	Tenants  repo.TenantRepo
	Agents   repo.AgentRepo
	// AgentReg drives ADR-009 D2 lazy registration: when resolveCaller meets
	// a keyID with no ramp.agents row, the service pulls the caller's own
	// /.well-known/ramp.json, verifies the key is published there, persists
	// the row, and proceeds. nil disables lazy registration (an unknown keyID
	// stays Unauthenticated) — used by tests that pre-seed every agent.
	AgentReg     agentreg.Registry
	Transactions repo.TransactionRepo
	Obligations  repo.ObligationRepo
	Billing      billing.Adapter
	OfferSigner  *signing.Ed25519Signer
	KeyStore     signing.KeyStore
	// Clk is the time source consulted by the offer-expiry, signed-URL
	// expiry and reporting-grace deadlines. nil defaults to clock.System{};
	// integration tests pass a DeterministicClock so the gates are driven
	// without sleeping. See ADR-008 D1.
	Clk clock.Clock
	// Logger is the structured-logging sink. Every ExecuteTransaction /
	// ReportUsage outcome (success or rejection) emits one log line via
	// this logger with request_id + caller_keyid + outcome attributes
	// (CLAUDE.md Rule 8). nil → slog.Default().
	Logger *slog.Logger
	Config ExchangeConfig
}

// NewExchangeService assembles the service.
func NewExchangeService(d ExchangeDeps) *ExchangeService {
	clk := d.Clk
	if clk == nil {
		clk = clock.System{}
	}
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &ExchangeService{
		tx:           d.TxRunner,
		catalog:      d.Catalog,
		tenants:      d.Tenants,
		agents:       d.Agents,
		agentReg:     d.AgentReg,
		transactions: d.Transactions,
		obligations:  d.Obligations,
		billing:      d.Billing,
		offerSigner:  d.OfferSigner,
		keyStore:     d.KeyStore,
		clk:          clk,
		cfg:          d.Config.withDefaults(),
		logger:       logger,
		idemHit:      map[string]string{},
	}
}

// DiscoverResources resolves URIs against the catalog, signs offers, returns
// them grouped per URI:
//   - catalog hit  → per-request offer in the OfferGroup
//   - catalog miss → empty group, OFFER_ABSENCE_REASON_NOT_IN_CATALOG
//
// The canonical v1 path is batch-shaped: ResourceQuery.requester.uris is
// always a list, and the response carries one OfferGroup per requested URI.
// The flat `offers` field mirrors the assembled per-request offers as a
// convenience aggregate; per ramp.proto §ResourceResponse, callers are
// expected to read OfferGroup.
func (s *ExchangeService) DiscoverResources(
	ctx context.Context,
	req *rampv1.ResourceQuery,
) (*rampv1.ResourceResponse, error) {
	_ = ctx // unused; kept for interface symmetry with ExecuteTransaction
	if req == nil || req.GetRequester() == nil {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "requester required")
	}
	if req.GetRequester().GetId() == "" {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "requester.id required")
	}
	uris := req.GetRequester().GetUris()
	if len(uris) == 0 {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "at least one uri required")
	}
	snap := s.catalog.Snapshot()
	flatOffers := make([]*rampv1.Offer, 0, len(uris))
	groups := make([]*rampv1.OfferGroup, 0, len(uris))
	for _, uri := range uris {
		entry, verdict := snap.Lookup(uri)
		group, groupOffers, err := s.groupFor(uri, entry, verdict)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
		flatOffers = append(flatOffers, groupOffers...)
	}
	resp := &rampv1.ResourceResponse{
		Ver:         rampproto.Ver,
		Id:          req.GetId(),
		Exchange:    s.cfg.Exchange,
		Offers:      flatOffers,
		OfferGroups: groups,
	}
	// Per-URI absence reasons are surfaced via OfferGroup.absence_reason,
	// populated by groupFor(). The canonical ramp.proto carries no
	// request-level absence-reason field.
	return resp, nil
}

// ExecuteTransaction verifies the caller's identity, the offer, and the
// billing authorization, then writes the transaction log in a single
// transaction and returns the signed URL. Write-before-sign is enforced: the
// signed URL hash lands in the DB in the same transaction as all other
// transaction fields, and the URL is only returned after commit.
func (s *ExchangeService) ExecuteTransaction(
	ctx context.Context,
	req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	if err := s.validateTxRequest(req); err != nil {
		return nil, err
	}
	if rec, found := s.idempotencyHit(req.GetId()); found {
		return nil, exchange.Newf(exchange.KindIdempotent, "tx_request_id already processed: %s", rec)
	}
	resolved, err := s.resolveOfferForTx(req)
	if err != nil {
		return nil, err
	}
	tenant, err := s.tenants.ByID(ctx, resolved.entry.TenantID)
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "load tenant")
	}
	// Resolve caller (single-sig or multisig), authorize, and compute the agent
	// binding. resolveCallerAndBinding runs the authz gate internally and binds
	// the delivery URL to the proven caller key (its RFC 7638 thumbprint is the
	// URL's agent_id param, echoed on the response — ADR-013). Binding is
	// computed before billing so a (near-impossible) bad-key failure reserves
	// no funds.
	//
	// Runs BEFORE resolveAgentID: a self-acting caller whose keyID is not yet in
	// ramp.agents is lazy-registered here (ADR-009 D2), populating the row that
	// resolveAgentID then attributes the transaction to. Authz compares the
	// proven caller against the wire requester.id; resolveAgentID returns that
	// same id once validated, so passing it in directly is equivalent. (A broker
	// relaying for an unregistered agent still fails resolveAgentID with
	// NotFound — only the authenticated caller's own keyID lazy-registers.)
	caller, binding, err := s.resolveCallerAndBinding(ctx, req.GetRequester().GetId(), tenant)
	if err != nil {
		return nil, err
	}
	agentID, err := s.resolveAgentID(ctx, req)
	if err != nil {
		return nil, err
	}
	// Deny agents holding an overdue reporting obligation before any funds are
	// reserved (v1.1 enforce-reporting-overdue gate): runs after authorization
	// so an unauthorized caller is rejected first, and before resolveBilling so
	// a blocked agent reserves no funds.
	if oerr := s.denyIfReportingOverdue(ctx, caller, &tenant, agentID); oerr != nil {
		return nil, oerr
	}
	// idempotencyKey anchors the whole billing lifecycle for this transaction:
	// Authorize/Record/Release share it so a retry of ExecuteTransaction reuses
	// the chain. A Release frees the key adapter-side, so a retry after a
	// hot-path failure re-authorizes fresh and charges (no stale-hold leak).
	idempotencyKey := req.GetId()
	auth, err := s.resolveBilling(ctx, billingResolution{
		tenantID: tenant.ID, agentID: agentID, pricing: resolved.pricing, idempotencyKey: idempotencyKey,
	})
	if err != nil {
		return nil, err
	}
	signed, err := s.mintSignedURL(ctx, tenant, resolved.entry, binding.thumbprint)
	if err != nil {
		s.releaseHold(ctx, auth.BillingID, idempotencyKey, "url sign failed")
		return nil, err
	}
	rec, err := s.persistTransaction(ctx, persistInput{
		tenant: tenant, entry: resolved.entry, pricing: resolved.pricing,
		req: req, agentID: agentID, auth: auth, signed: signed, agentHash: binding.digest,
	})
	if err != nil {
		s.releaseHold(ctx, auth.BillingID, idempotencyKey, "persist failed")
		return nil, err
	}
	// DOUBLE-CHARGE INVARIANT: Record MUST run after persistTransaction. The
	// in-memory idempotency LRU (idempotencyHit) is bounded and may evict; the
	// durable backstop against a re-charged retry is the tx_request_id UNIQUE
	// constraint (db/migrations 000001), which fails the persist INSERT before
	// Record is ever reached. Reordering Record ahead of persist would charge a
	// duplicate tx_request_id before the UNIQUE violation can block it.
	//
	// Record at Execute, best-effort, with the estimated quantity. Failure is
	// logged and the transaction stays committed — the agent already has the
	// signed URL and the transaction_log row is durable. Reconciliation /
	// adapter-side idempotency cover the gap (design-exchange.md:555-569).
	//
	// PERSISTED-ADAPTER MIGRATION: the in-memory adapter's Record cannot
	// fail with a live hold (its only error is ErrUnknownBillingID = no hold), so
	// no hold leaks today. A persisted adapter (TigerBeetle) whose Record can
	// transiently fail WITH the hold still live leaves that hold neither recorded
	// nor released, and best-effort means it is never retried — the reconciliation
	// job owns recovering these orphaned holds.
	if rErr := s.billing.Record(ctx, auth.BillingID, int64(resolved.pricing.EstQty), idempotencyKey); rErr != nil {
		s.logger.ErrorContext(ctx, "exchange.execute_transaction billing record failed (best-effort)",
			"transaction_id", rec.TransactionID,
			"billing_id", auth.BillingID,
			"err", rErr.Error())
	}
	s.idempotencyRecord(req.GetId(), rec.TransactionID)
	s.logOutcome(ctx, "execute_transaction", "VALIDATED", caller, &tenant, agentID, rec.TransactionID, nil)
	return s.buildTxResponse(req, rec, signed, resolved.pricing, binding.thumbprint), nil
}

// releaseHold returns a previously-held reservation on the ExecuteTransaction
// hot-path failure (URL signing failed, persist failed). The caller is already
// returning an error to the agent; Release's own failure cannot fail the
// request again. ErrUnknownBillingID is treated as a successful no-op
// (idempotent — Release was already called or the reservation was already
// consumed by Record).
func (s *ExchangeService) releaseHold(ctx context.Context, billingID, idempotencyKey, reason string) {
	err := s.billing.Release(ctx, billingID, idempotencyKey)
	if err != nil && !errors.Is(err, billing.ErrUnknownBillingID) {
		s.logger.ErrorContext(ctx, "exchange.execute_transaction release hold failed",
			"billing_id", billingID,
			"reason", reason,
			"err", err.Error())
	}
}

// resolvedOffer carries the outcome of matching the caller's offer_id to a
// catalog entry, with pricing rebuilt to reflect the selected variant.
type resolvedOffer struct {
	entry   repo.CatalogEntry
	pricing PricingDoc
}

// resolveOfferForTx maps req.offer_id to a catalog entry and verifies the
// caller's offer signature against the reconstructed offer.
func (s *ExchangeService) resolveOfferForTx(req *rampv1.TransactionRequest) (resolvedOffer, error) {
	offerID := req.GetOfferId()
	snap := s.catalog.Snapshot()
	entry, ok := snap.byID[offerID]
	if !ok {
		return resolvedOffer{}, exchange.Newf(exchange.KindNotFound, "offer %q not found in catalog", offerID)
	}
	var pricing PricingDoc
	if err := json.Unmarshal(entry.PricingJSON, &pricing); err != nil {
		return resolvedOffer{}, exchange.Wrap(exchange.KindInternal, err, "unmarshal pricing")
	}
	if err := s.verifyOffer(entry, req.GetOfferSignature()); err != nil {
		return resolvedOffer{}, err
	}
	return resolvedOffer{entry: entry, pricing: pricing}, nil
}

type persistInput struct {
	tenant  repo.Tenant
	entry   repo.CatalogEntry
	pricing PricingDoc
	req     *rampv1.TransactionRequest
	agentID string
	auth    billing.AuthorizeResult
	signed  signing.SignedURL
	// agentHash is the 32-byte SHA-256 digest of the agent's RFC 7638
	// thumbprint, persisted to transaction_log.agent_identity_hash (ADR-013
	// 17.6). Same value whose base64url form rides in the URL's agent_id param.
	agentHash []byte
}

func (s *ExchangeService) persistTransaction(ctx context.Context, in persistInput) (repo.TransactionRecord, error) {
	intent := s.buildPersistIntent(in)
	var rec repo.TransactionRecord
	err := s.tx.WithTx(ctx, func(tx pgx.Tx) error {
		created, err := s.transactions.CreateForOffer(ctx, tx, intent)
		if err != nil {
			return err
		}
		rec = created
		_, err = s.obligations.CreateForOffer(ctx, tx, intent)
		return err
	})
	if err != nil {
		return repo.TransactionRecord{}, exchange.Wrap(exchange.KindInternal, err, "write transaction")
	}
	return rec, nil
}

// buildPersistIntent assembles the PersistTxIntent the repos consume. All
// derived values (IDs, agent-identity hash, reporting-policy defaults,
// obligation window/deadline) are computed here so persistTransaction
// reduces to "build intent, run tx, call both repos".
func (s *ExchangeService) buildPersistIntent(in persistInput) repo.PersistTxIntent {
	policy := decodeReportingPolicy(in.tenant.ReportingPolicy)
	tolerance := defaultQuantityTolerance
	if policy.QuantityTolerance != nil {
		tolerance = *policy.QuantityTolerance
	}
	windowSeconds := windowSecondsForObligation(policy, s.cfg.ReportWindow)
	// Normalize required_fields to a non-nil slice so the NOT NULL TEXT[]
	// column receives an empty array rather than NULL when the tenant
	// policy did not pin any fields. sqlc passes the Go slice straight
	// through, so a nil here would violate the column constraint.
	requiredFields := policy.RequiredFields
	if requiredFields == nil {
		requiredFields = []string{}
	}
	return repo.PersistTxIntent{
		TransactionID:     uuid.NewString(),
		TxRequestID:       in.req.GetId(),
		ObligationID:      uuid.NewString(),
		TenantID:          in.tenant.ID,
		AgentID:           in.agentID,
		ResourceID:        in.entry.ResourceID,
		OfferID:           in.entry.ResourceID,
		AgentIdentityHash: in.agentHash,
		SignedURLHash:     in.signed.Hash,
		Expiry:            in.signed.Expiry,
		BillingID:         in.auth.BillingID,
		UnitCostDecimal:   fmt.Sprintf("%.8f", in.pricing.UnitCost),
		Currency:          in.pricing.Currency,
		State:             repo.ObligationStatePending,
		WindowSeconds:     windowSeconds,
		Deadline:          s.clk.Now().Add(time.Duration(windowSeconds) * time.Second),
		RequiredFields:    requiredFields,
		EstimatedQuantity: int64(in.pricing.EstQty),
		QuantityTolerance: tolerance,
	}
}

// reportingPolicy is the JSON shape the tenant's reporting_policy column
// carries. All fields optional; missing keys fall back to defaults.
type reportingPolicy struct {
	RequiredFields    []string `json:"required_fields,omitempty"`
	QuantityTolerance *float64 `json:"quantity_tolerance,omitempty"`
	// WindowSeconds, when set, overrides cfg.ReportWindow for new obligations
	// minted against this tenant. The §B independent finding called for
	// sourcing the window from the offer's ReportingObligation.window, but
	// the wire TransactionRequest carries no reporting block — so the
	// tenant-policy JSONB is the substitute granularity that does not
	// require a protocol bump.
	WindowSeconds *int32 `json:"window_seconds,omitempty"`
}

// decodeReportingPolicy unmarshals the raw JSONB blob. A blank / missing /
// malformed policy yields a zero-value struct (no required fields, tolerance
// falls back to the service default) — we deliberately do not surface decode
// errors to the request path because the column has a `{}` DEFAULT and any
// older row that survives is safe to treat as "no policy".
func decodeReportingPolicy(raw []byte) reportingPolicy {
	var p reportingPolicy
	if len(raw) == 0 {
		return p
	}
	_ = json.Unmarshal(raw, &p)
	return p
}

// windowSecondsForObligation returns the obligation's reporting window:
// tenants.reporting_policy.window_seconds when set (so publishers can shorten
// or extend the protocol default per tenant), otherwise the service default
// from cfg.ReportWindow. Encoded as int32 seconds on the obligation row.
func windowSecondsForObligation(policy reportingPolicy, fallback time.Duration) int32 {
	if policy.WindowSeconds != nil && *policy.WindowSeconds > 0 {
		return *policy.WindowSeconds
	}
	return int32(fallback.Seconds())
}

// logOutcome emits one structured log line per ExecuteTransaction or
// ReportUsage attempt — CLAUDE.md Rule 8. tenant may be nil (e.g. for
// failures that happen before tenant resolution). err is the
// outcome-classifying error; nil on success.
func (s *ExchangeService) logOutcome(
	ctx context.Context, op, outcome string,
	caller Caller, tenant *repo.Tenant,
	agentID, transactionID string,
	err *exchange.Error,
) {
	attrs := []any{
		"op", op,
		"outcome", outcome,
		"caller_keyid", caller.KeyID,
		"caller_kind", callerKindLabel(caller.Kind),
		"agent_id", agentID,
		"transaction_id", transactionID,
	}
	if tenant != nil {
		attrs = append(attrs, "tenant_id", tenant.ID)
	}
	if err != nil {
		attrs = append(attrs, "kind", err.Kind.String(), "err", err.Message)
		s.logger.WarnContext(ctx, "exchange."+op, attrs...)
		return
	}
	s.logger.InfoContext(ctx, "exchange."+op, attrs...)
}

func callerKindLabel(k CallerKind) string {
	switch k {
	case CallerAgent:
		return "agent"
	case CallerBroker:
		return "broker"
	default:
		return "unknown"
	}
}
