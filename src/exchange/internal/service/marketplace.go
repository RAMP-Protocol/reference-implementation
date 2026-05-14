package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"
	"golang.org/x/sync/singleflight"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// MarketplaceConfig bundles wiring knobs for the service.
type MarketplaceConfig struct {
	Marketplace    string        // canonical exchange domain (echoed in ResourceResponse)
	OfferTTL       time.Duration // default 5m
	URLTTL         time.Duration // default 5m
	ReportWindow   time.Duration // default 24h
	IdempotencyLRU int           // default 1024
}

func (c MarketplaceConfig) withDefaults() MarketplaceConfig {
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

// MarketplaceService implements DiscoverResources, ExecuteTransaction, and
// ReportUsage. It depends on narrow repos, a billing adapter, a URL-signer
// dispatcher, and an offer signer.
type MarketplaceService struct {
	pool         *pgxpool.Pool
	catalog      *CatalogService
	tenants      repo.TenantRepo
	agents       repo.AgentRepo
	transactions repo.TransactionRepo
	obligations  repo.ObligationRepo
	billing      billing.Adapter
	offerSigner  *signing.Ed25519Signer
	keyStore     signing.KeyStore
	cfg          MarketplaceConfig

	txGroup  singleflight.Group
	idemMu   sync.Mutex
	idemHit  map[string]string // tx_request_id -> transaction_id (LRU-bounded)
	idemRing lruRing
}

// MarketplaceDeps bundles the wiring dependencies.
type MarketplaceDeps struct {
	Pool         *pgxpool.Pool
	Catalog      *CatalogService
	Tenants      repo.TenantRepo
	Agents       repo.AgentRepo
	Transactions repo.TransactionRepo
	Obligations  repo.ObligationRepo
	Billing      billing.Adapter
	OfferSigner  *signing.Ed25519Signer
	KeyStore     signing.KeyStore
	Config       MarketplaceConfig
}

// NewMarketplaceService assembles the service.
func NewMarketplaceService(d MarketplaceDeps) *MarketplaceService {
	return &MarketplaceService{
		pool:         d.Pool,
		catalog:      d.Catalog,
		tenants:      d.Tenants,
		agents:       d.Agents,
		transactions: d.Transactions,
		obligations:  d.Obligations,
		billing:      d.Billing,
		offerSigner:  d.OfferSigner,
		keyStore:     d.KeyStore,
		cfg:          d.Config.withDefaults(),
		idemHit:      map[string]string{},
		idemRing:     newLRURing(d.Config.withDefaults().IdempotencyLRU),
	}
}

// DiscoverResources resolves URIs against the catalog, signs offers, returns them.
func (s *MarketplaceService) DiscoverResources(
	_ context.Context,
	req *rampv1.ResourceQuery,
) (*rampv1.ResourceResponse, error) {
	if req == nil || req.GetRequester() == nil {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "requester required")
	}
	uris := req.GetRequester().GetUris()
	if len(uris) == 0 {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "at least one uri required")
	}
	snap := s.catalog.Snapshot()
	offers := make([]*rampv1.Offer, 0, len(uris))
	for _, uri := range uris {
		entry, ok := snap.Lookup(uri)
		if !ok {
			continue
		}
		offer, err := s.buildOffer(entry)
		if err != nil {
			return nil, exchange.Wrap(exchange.KindInternal, err, "build offer")
		}
		offers = append(offers, offer)
	}
	return &rampv1.ResourceResponse{
		Ver:         "1.0",
		Id:          req.GetId(),
		Marketplace: s.cfg.Marketplace,
		Offers:      offers,
	}, nil
}

func (s *MarketplaceService) buildOffer(entry repo.CatalogEntry) (*rampv1.Offer, error) {
	var pricing PricingDoc
	if err := json.Unmarshal(entry.PricingJSON, &pricing); err != nil {
		return nil, fmt.Errorf("unmarshal pricing: %w", err)
	}
	expires := time.Now().Add(s.cfg.OfferTTL)
	offer := &rampv1.Offer{
		OfferId: entry.ResourceID,
		Pricing: &rampv1.Pricing{
			Model:    rampv1.PricingModel(rampv1.PricingModel_value[pricing.Model]),
			Rate:     pricing.Rate,
			Currency: pricing.Currency,
			UnitCost: &pricing.UnitCost,
			Unit:     &pricing.Unit,
		},
		DeliveryMethod: rampv1.DeliveryMethod_DELIVERY_METHOD_INSTRUCTIONS,
		ExpiresAt:      timestamppb.New(expires),
		Identity: &rampv1.ResourceIdentity{
			CanonicalUrl: strPtr(entry.URI),
		},
	}
	if pricing.EstQty > 0 {
		offer.Pricing.EstimatedQuantity = &pricing.EstQty
	}
	sig, err := s.offerSigner.SignOffer(offer)
	if err != nil {
		return nil, fmt.Errorf("sign offer: %w", err)
	}
	offer.Signature = sig
	offer.SignatureAlgorithm = signing.SignatureAlgorithm
	return offer, nil
}

func strPtr(s string) *string { return &s }

// ExecuteTransaction verifies, authorizes billing, writes the transaction log
// in a transaction, then returns the signed URL. The URL is only returned
// after the DB commit succeeds (commit-before-return). Any failure after
// billing authorization triggers a compensating Cancel so no balance is lost.
//
// Concurrent requests with the same tx_request_id are collapsed via
// singleflight: only one goroutine runs the body; the rest receive the same
// result without touching billing or the DB.
func (s *MarketplaceService) ExecuteTransaction(
	ctx context.Context,
	req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	if err := s.validateTxRequest(req); err != nil {
		return nil, err
	}
	v, err, _ := s.txGroup.Do(req.GetId(), func() (any, error) {
		return s.executeTransactionInner(ctx, req)
	})
	if err != nil {
		return nil, err
	}
	return v.(*rampv1.TransactionResponse), nil
}

func (s *MarketplaceService) executeTransactionInner(
	ctx context.Context,
	req *rampv1.TransactionRequest,
) (resp *rampv1.TransactionResponse, returnErr error) {
	if txID, found := s.idempotencyHit(req.GetId()); found {
		return nil, exchange.Newf(exchange.KindIdempotent, "tx_request_id already processed: %s", txID)
	}
	if existing, err := s.transactions.ByRequestID(ctx, req.GetId()); err == nil {
		s.idempotencyRecord(req.GetId(), existing.TransactionID)
		return nil, exchange.Newf(exchange.KindIdempotent, "tx_request_id already processed: %s", existing.TransactionID)
	} else if !errors.Is(err, repo.ErrTransactionNotFound) {
		return nil, exchange.Wrap(exchange.KindInternal, err, "idempotency check")
	}

	resourceID := req.GetOfferId()
	entry, ok := s.catalog.Snapshot().byID[resourceID]
	if !ok {
		return nil, exchange.Newf(exchange.KindNotFound, "offer %q not found in catalog", resourceID)
	}
	var pricing PricingDoc
	if err := json.Unmarshal(entry.PricingJSON, &pricing); err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "unmarshal pricing")
	}
	if err := s.verifyOffer(entry, req.GetOfferSignature()); err != nil {
		return nil, err
	}
	tenant, err := s.tenants.ByID(ctx, entry.TenantID)
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "load tenant")
	}
	auth, err := s.authorizeBilling(ctx, tenant.ID, req.GetRequester().GetId(), pricing)
	if err != nil {
		return nil, err
	}
	defer func() {
		if returnErr != nil {
			_ = s.billing.Cancel(ctx, auth.BillingID)
		}
	}()
	// Pre-generate the transaction_id so it can be embedded as an audit
	// query param in the signed URL before signing. Lambda@Edge logs the
	// querystring verbatim, so an access-log row carries the same tx_id
	// the transaction_log row will be keyed by.
	txID := uuid.NewString()
	signed, err := s.mintSignedURL(ctx, tenant, entry, txID, req.GetId())
	if err != nil {
		return nil, err
	}
	rec, err := s.persistTransaction(ctx, persistInput{
		tenant:  tenant,
		entry:   entry,
		pricing: pricing,
		req:     req,
		auth:    auth,
		signed:  signed,
		txID:    txID,
		// Persist both halves of the cryptographic chain verbatim so the
		// /admin/ledger endpoint can show them side-by-side with the
		// matching Lambda@Edge access-log entry without re-deriving from
		// keys. Offer signature is what the agent presented; URL signature
		// is what the Exchange minted.
		offerSignature:     req.GetOfferSignature(),
		signedURLSignature: signing.ExtractSignatureFromURL(signed.URL),
	})
	if err != nil {
		return nil, err
	}
	if err := s.billing.Record(ctx, auth.BillingID, int64(pricing.EstQty)); err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "billing record")
	}
	s.idempotencyRecord(req.GetId(), rec.TransactionID)
	return s.buildTxResponse(req, rec, signed, pricing), nil
}

type persistInput struct {
	tenant             repo.Tenant
	entry              repo.CatalogEntry
	pricing            PricingDoc
	req                *rampv1.TransactionRequest
	auth               billing.AuthorizeResult
	signed             signing.SignedURL
	txID               string // pre-generated by ExecuteTransaction so the URL can carry it
	offerSignature     string // verbatim, as the agent presented it
	signedURLSignature string // signature substring extracted from the issued URL
}

func (s *MarketplaceService) persistTransaction(ctx context.Context, in persistInput) (*repo.TransactionRecord, error) {
	txID := in.txID
	if txID == "" {
		// Fallback for any caller that hasn't been updated; preserves
		// pre-audit-correlator behaviour (no embedded tx_id in URL).
		txID = uuid.NewString()
	}
	obligationID := uuid.NewString()
	agentHash := sha256.Sum256([]byte(in.req.GetRequester().GetId() + "|" + in.req.GetId()))
	var rec *repo.TransactionRecord
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		created, err := s.transactions.Create(ctx, tx, repo.TransactionRecord{
			TransactionID:      txID,
			TxRequestID:        in.req.GetId(),
			TenantID:           in.tenant.ID,
			AgentID:            in.req.GetRequester().GetId(),
			ResourceID:         in.entry.ResourceID,
			OfferID:            in.entry.ResourceID,
			AgentIdentityHash:  agentHash[:],
			SignedURLHash:      in.signed.Hash,
			Expiry:             in.signed.Expiry,
			BillingID:          in.auth.BillingID,
			UnitCostDecimal:    fmt.Sprintf("%.8f", in.pricing.UnitCost),
			Currency:           in.pricing.Currency,
			OfferSignature:     in.offerSignature,
			SignedURLSignature: in.signedURLSignature,
		})
		if err != nil {
			return err
		}
		rec = created
		_, err = s.obligations.Create(ctx, tx, repo.Obligation{
			ID:            obligationID,
			TransactionID: created.TransactionID,
			State:         "PENDING",
			WindowSeconds: int32(s.cfg.ReportWindow.Seconds()),
			Deadline:      time.Now().Add(s.cfg.ReportWindow),
		})
		return err
	})
	if err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "write transaction")
	}
	return rec, nil
}

// ReportUsage flips the obligation for the transaction to RECEIVED.
func (s *MarketplaceService) ReportUsage(
	ctx context.Context,
	req *rampv1.UsageReport,
) (*rampv1.UsageReportResponse, error) {
	if req == nil || req.GetTransactionId() == "" {
		return nil, exchange.Newf(exchange.KindInvalidRequest, "transaction_id required")
	}
	ob, err := s.obligations.ByTransaction(ctx, req.GetTransactionId())
	if err != nil {
		if errors.Is(err, repo.ErrObligationNotFound) {
			return nil, exchange.Newf(exchange.KindNotFound, "no obligation for transaction %q", req.GetTransactionId())
		}
		return nil, exchange.Wrap(exchange.KindInternal, err, "load obligation")
	}
	qty := "0"
	if req.GetUsage() != nil {
		qty = fmt.Sprintf("%d", req.GetUsage().GetConsumedQuantity())
	}
	if _, err := s.obligations.MarkReceived(ctx, ob.ID, qty); err != nil {
		return nil, exchange.Wrap(exchange.KindInternal, err, "mark obligation received")
	}
	return &rampv1.UsageReportResponse{Accepted: true, ReportId: uuid.NewString()}, nil
}
