package service_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	rampv1 "github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// ---- stub repo / billing implementations -----------------------------------

type stubCatalogRepo struct{ entries []repo.CatalogEntry }

func (r *stubCatalogRepo) ListAll(_ context.Context) ([]repo.CatalogEntry, error) {
	return r.entries, nil
}
func (r *stubCatalogRepo) Upsert(_ context.Context, e repo.CatalogEntry) (repo.CatalogEntry, error) {
	return e, nil
}
func (r *stubCatalogRepo) ByID(_ context.Context, id string) (repo.CatalogEntry, error) {
	for _, e := range r.entries {
		if e.ResourceID == id {
			return e, nil
		}
	}
	return repo.CatalogEntry{}, repo.ErrCatalogNotFound
}

type stubTransactionRepo struct {
	byRequestIDFn func(ctx context.Context, id string) (*repo.TransactionRecord, error)
}

func (r *stubTransactionRepo) Create(_ context.Context, _ pgx.Tx, _ repo.TransactionRecord) (*repo.TransactionRecord, error) {
	panic("Create not expected in unit tests")
}
func (r *stubTransactionRepo) ByRequestID(ctx context.Context, id string) (*repo.TransactionRecord, error) {
	if r.byRequestIDFn != nil {
		return r.byRequestIDFn(ctx, id)
	}
	return nil, repo.ErrTransactionNotFound
}
func (r *stubTransactionRepo) ByID(_ context.Context, _ string) (*repo.TransactionRecord, error) {
	return nil, repo.ErrTransactionNotFound
}

type stubTenantRepo struct {
	tenant repo.Tenant
	err    error
}

func (r *stubTenantRepo) ByID(_ context.Context, _ string) (repo.Tenant, error) {
	return r.tenant, r.err
}
func (r *stubTenantRepo) ByDomain(_ context.Context, _ string) (repo.Tenant, error) {
	return r.tenant, r.err
}

type stubAgentRepo struct{}

func (r *stubAgentRepo) ByID(_ context.Context, _ string) (repo.Agent, error) {
	return repo.Agent{}, repo.ErrAgentNotFound
}
func (r *stubAgentRepo) Upsert(_ context.Context, a repo.Agent) (repo.Agent, error) { return a, nil }

type stubObligationRepo struct {
	byTransactionFn func(ctx context.Context, txID string) (repo.Obligation, error)
	markReceivedFn  func(ctx context.Context, id, qty string) (repo.Obligation, error)
}

func (r *stubObligationRepo) Create(_ context.Context, _ pgx.Tx, o repo.Obligation) (repo.Obligation, error) {
	panic("Create not expected in unit tests")
}
func (r *stubObligationRepo) ByTransaction(ctx context.Context, txID string) (repo.Obligation, error) {
	if r.byTransactionFn != nil {
		return r.byTransactionFn(ctx, txID)
	}
	return repo.Obligation{}, repo.ErrObligationNotFound
}
func (r *stubObligationRepo) MarkReceived(ctx context.Context, id, qty string) (repo.Obligation, error) {
	if r.markReceivedFn != nil {
		return r.markReceivedFn(ctx, id, qty)
	}
	return repo.Obligation{State: "RECEIVED"}, nil
}

type stubBilling struct {
	authorizeFn func(ctx context.Context, req billing.AuthorizeRequest) (billing.AuthorizeResult, error)
}

func (b *stubBilling) Authorize(ctx context.Context, req billing.AuthorizeRequest) (billing.AuthorizeResult, error) {
	if b.authorizeFn != nil {
		return b.authorizeFn(ctx, req)
	}
	return billing.AuthorizeResult{Approved: false, Reason: "stub: not configured"}, nil
}
func (b *stubBilling) Record(_ context.Context, _ string, _ int64) error { return nil }
func (b *stubBilling) Cancel(_ context.Context, _ string) error          { return nil }
func (b *stubBilling) GetBalance(_ context.Context, _ string) (billing.Amount, error) {
	return billing.Amount{}, nil
}
func (b *stubBilling) GetQuota(_ context.Context, _ string) (int64, error) { return 0, nil }

// ---- harness ---------------------------------------------------------------

type marketplaceOpts struct {
	entries      []repo.CatalogEntry
	transactions *stubTransactionRepo
	obligations  *stubObligationRepo
	tenants      *stubTenantRepo
	bill         billing.Adapter
	signer       *signing.Ed25519Signer
}

func newMarketplace(t *testing.T, o marketplaceOpts) (*service.MarketplaceService, *signing.Ed25519Signer) {
	t.Helper()
	signer := o.signer
	if signer == nil {
		var err error
		signer, err = signing.GenerateEd25519Signer()
		if err != nil {
			t.Fatalf("gen signer: %v", err)
		}
	}
	catalogRepo := &stubCatalogRepo{entries: o.entries}
	catalogSvc := service.NewCatalogService(catalogRepo)
	if err := catalogSvc.Bootstrap(context.Background()); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}
	txRepo := o.transactions
	if txRepo == nil {
		txRepo = &stubTransactionRepo{}
	}
	oblRepo := o.obligations
	if oblRepo == nil {
		oblRepo = &stubObligationRepo{}
	}
	tenantRepo := o.tenants
	if tenantRepo == nil {
		tenantRepo = &stubTenantRepo{}
	}
	bill := o.bill
	if bill == nil {
		bill = &stubBilling{}
	}
	mp := service.NewMarketplaceService(service.MarketplaceDeps{
		Pool:         nil, // nil — unit tests must not reach persistTransaction
		Catalog:      catalogSvc,
		Tenants:      tenantRepo,
		Agents:       &stubAgentRepo{},
		Transactions: txRepo,
		Obligations:  oblRepo,
		Billing:      bill,
		OfferSigner:  signer,
		KeyStore:     signing.NewInMemoryKeyStore(),
		Config:       service.MarketplaceConfig{Marketplace: "exchange.test"},
	})
	return mp, signer
}

// ---- fixtures --------------------------------------------------------------

func mustPricingJSON(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(service.PricingDoc{
		Model:    "PRICING_MODEL_PER_ACCESS",
		Rate:     0.05,
		Currency: "USD",
		UnitCost: 0.05,
		Unit:     "access",
	})
	if err != nil {
		t.Fatalf("marshal pricing: %v", err)
	}
	return b
}

func testEntry(t *testing.T) repo.CatalogEntry {
	t.Helper()
	return repo.CatalogEntry{
		ResourceID:     "res-unit-1",
		TenantID:       "tenant-unit-1",
		URI:            "https://example.com/content/unit",
		URIPrefix:      "https://example.com/content/unit",
		PricingJSON:    mustPricingJSON(t),
		LicensingJSON:  []byte(`{}`),
		DeliveryMethod: "INSTRUCTIONS",
	}
}

func asExchangeError(t *testing.T, err error) *exchange.Error {
	t.Helper()
	var de *exchange.Error
	if !errors.As(err, &de) {
		t.Fatalf("expected *exchange.Error, got %T: %v", err, err)
	}
	return de
}

// discoverSignedOffer calls DiscoverResources and returns the first offer's
// (offer_id, signature) pair. Fails fast if discovery returns no offers.
func discoverSignedOffer(t *testing.T, mp *service.MarketplaceService, uri string) (offerID, sig string) {
	t.Helper()
	resp, err := mp.DiscoverResources(context.Background(), &rampv1.ResourceQuery{
		Id: "q-discover",
		Requester: &rampv1.Requester{
			Id:   "ag-discover",
			Uris: []string{uri},
		},
	})
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	if len(resp.GetOffers()) == 0 {
		t.Fatal("no offers returned from DiscoverResources")
	}
	return resp.GetOffers()[0].GetOfferId(), resp.GetOffers()[0].GetSignature()
}

// ---- validateTxRequest (via ExecuteTransaction) ----------------------------

func TestValidateTxRequest_NilRequest(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	_, err := mp.ExecuteTransaction(context.Background(), nil)
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

func TestValidateTxRequest_EmptyID(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

func TestValidateTxRequest_MissingOfferFields(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	offerID := "some-offer"
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id:        "req-1",
		OfferId:   &offerID,
		Requester: &rampv1.Requester{Id: "agent-1"},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

func TestValidateTxRequest_MissingRequester(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	offerID := "some-offer"
	offerSig := "deadbeef"
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id:             "req-1",
		OfferId:        &offerID,
		OfferSignature: &offerSig,
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

// ---- DiscoverResources -----------------------------------------------------

func TestDiscoverResources_MissingRequester(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	_, err := mp.DiscoverResources(context.Background(), nil)
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

func TestDiscoverResources_EmptyURIs(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	_, err := mp.DiscoverResources(context.Background(), &rampv1.ResourceQuery{
		Requester: &rampv1.Requester{Id: "ag"},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

func TestDiscoverResources_UnknownURI(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	resp, err := mp.DiscoverResources(context.Background(), &rampv1.ResourceQuery{
		Requester: &rampv1.Requester{
			Id:   "ag",
			Uris: []string{"https://unknown.example/nope"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetOffers()) != 0 {
		t.Fatalf("expected no offers, got %d", len(resp.GetOffers()))
	}
}

func TestDiscoverResources_HappyPath(t *testing.T) {
	t.Parallel()
	entry := testEntry(t)
	mp, _ := newMarketplace(t, marketplaceOpts{entries: []repo.CatalogEntry{entry}})
	resp, err := mp.DiscoverResources(context.Background(), &rampv1.ResourceQuery{
		Id: "q-1",
		Requester: &rampv1.Requester{
			Id:   "ag-1",
			Uris: []string{entry.URI},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetOffers()) != 1 {
		t.Fatalf("expected 1 offer, got %d", len(resp.GetOffers()))
	}
	offer := resp.GetOffers()[0]
	if offer.GetSignature() == "" {
		t.Error("offer signature must be set")
	}
	if offer.GetOfferId() != entry.ResourceID {
		t.Errorf("offer_id = %q, want %q", offer.GetOfferId(), entry.ResourceID)
	}
}

func TestDiscoverResources_InvalidPricingJSON(t *testing.T) {
	t.Parallel()
	entry := testEntry(t)
	entry.PricingJSON = []byte(`not-json`)
	mp, _ := newMarketplace(t, marketplaceOpts{entries: []repo.CatalogEntry{entry}})
	_, err := mp.DiscoverResources(context.Background(), &rampv1.ResourceQuery{
		Requester: &rampv1.Requester{Id: "ag", Uris: []string{entry.URI}},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInternal {
		t.Fatalf("kind = %v, want KindInternal", de.Kind)
	}
}

// ---- ExecuteTransaction early-exit error paths (no pool needed) ------------

func TestExecuteTransaction_OfferNotInCatalog(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	offerID := "nonexistent"
	offerSig := "deadbeef"
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id:             "req-1",
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester:      &rampv1.Requester{Id: "ag"},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindNotFound {
		t.Fatalf("kind = %v, want KindNotFound", de.Kind)
	}
}

func TestExecuteTransaction_SignatureInvalid(t *testing.T) {
	t.Parallel()
	entry := testEntry(t)
	mp, _ := newMarketplace(t, marketplaceOpts{entries: []repo.CatalogEntry{entry}})
	offerID := entry.ResourceID
	// 128 hex chars = 64 bytes, a valid-length but incorrect Ed25519 signature.
	offerSig := "0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id:             "req-badsig",
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester:      &rampv1.Requester{Id: "ag"},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindSignatureInvalid {
		t.Fatalf("kind = %v, want KindSignatureInvalid", de.Kind)
	}
}

// TestExecuteTransaction_BillingDenied verifies that authorizeBilling denial
// surfaces as KindBillingDenied. Uses DiscoverResources to obtain a valid
// offer signature so verifyOffer passes.
func TestExecuteTransaction_BillingDenied(t *testing.T) {
	t.Parallel()
	entry := testEntry(t)
	denied := &stubBilling{
		authorizeFn: func(_ context.Context, _ billing.AuthorizeRequest) (billing.AuthorizeResult, error) {
			return billing.AuthorizeResult{Approved: false, Reason: "insufficient balance"}, nil
		},
	}
	mp, _ := newMarketplace(t, marketplaceOpts{
		entries: []repo.CatalogEntry{entry},
		bill:    denied,
		tenants: &stubTenantRepo{tenant: repo.Tenant{
			ID:            entry.TenantID,
			SigningScheme: "ED25519",
		}},
	})

	offerID, offerSig := discoverSignedOffer(t, mp, entry.URI)
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id:             "req-billing",
		OfferId:        &offerID,
		OfferSignature: &offerSig,
		Requester:      &rampv1.Requester{Id: "ag"},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindBillingDenied {
		t.Fatalf("kind = %v, want KindBillingDenied", de.Kind)
	}
}

// TestExecuteTransaction_DBIdempotencyHit verifies that when ByRequestID
// returns an existing record, ExecuteTransaction returns KindIdempotent.
func TestExecuteTransaction_DBIdempotencyHit(t *testing.T) {
	t.Parallel()
	calls := 0
	txRepo := &stubTransactionRepo{
		byRequestIDFn: func(_ context.Context, id string) (*repo.TransactionRecord, error) {
			calls++
			if calls == 1 {
				return nil, repo.ErrTransactionNotFound
			}
			return &repo.TransactionRecord{TxRequestID: id, TransactionID: "tx-existing"}, nil
		},
	}
	mp, _ := newMarketplace(t, marketplaceOpts{transactions: txRepo})
	offerID := "nonexistent"
	offerSig := "sig"

	// First call: ErrTransactionNotFound → proceeds to catalog miss (KindNotFound).
	_, _ = mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id: "req-idem", OfferId: &offerID, OfferSignature: &offerSig,
		Requester: &rampv1.Requester{Id: "ag"},
	})

	// Second call: ByRequestID returns existing record → KindIdempotent.
	_, err := mp.ExecuteTransaction(context.Background(), &rampv1.TransactionRequest{
		Id: "req-idem", OfferId: &offerID, OfferSignature: &offerSig,
		Requester: &rampv1.Requester{Id: "ag"},
	})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindIdempotent {
		t.Fatalf("kind = %v, want KindIdempotent", de.Kind)
	}
}

// ---- ReportUsage -----------------------------------------------------------

func TestReportUsage_NilRequest(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{})
	_, err := mp.ReportUsage(context.Background(), nil)
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInvalidRequest {
		t.Fatalf("kind = %v, want KindInvalidRequest", de.Kind)
	}
}

func TestReportUsage_ObligationNotFound(t *testing.T) {
	t.Parallel()
	mp, _ := newMarketplace(t, marketplaceOpts{
		obligations: &stubObligationRepo{
			byTransactionFn: func(_ context.Context, _ string) (repo.Obligation, error) {
				return repo.Obligation{}, repo.ErrObligationNotFound
			},
		},
	})
	_, err := mp.ReportUsage(context.Background(), &rampv1.UsageReport{TransactionId: "tx-nope"})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindNotFound {
		t.Fatalf("kind = %v, want KindNotFound", de.Kind)
	}
}

func TestReportUsage_MarkReceivedError(t *testing.T) {
	t.Parallel()
	sentinelErr := errors.New("db write failed")
	mp, _ := newMarketplace(t, marketplaceOpts{
		obligations: &stubObligationRepo{
			byTransactionFn: func(_ context.Context, txID string) (repo.Obligation, error) {
				return repo.Obligation{ID: "ob-1", TransactionID: txID, State: "PENDING"}, nil
			},
			markReceivedFn: func(_ context.Context, _, _ string) (repo.Obligation, error) {
				return repo.Obligation{}, sentinelErr
			},
		},
	})
	_, err := mp.ReportUsage(context.Background(), &rampv1.UsageReport{TransactionId: "tx-1"})
	de := asExchangeError(t, err)
	if de.Kind != exchange.KindInternal {
		t.Fatalf("kind = %v, want KindInternal", de.Kind)
	}
}

func TestReportUsage_HappyPath(t *testing.T) {
	t.Parallel()
	marked := false
	mp, _ := newMarketplace(t, marketplaceOpts{
		obligations: &stubObligationRepo{
			byTransactionFn: func(_ context.Context, txID string) (repo.Obligation, error) {
				return repo.Obligation{ID: "ob-1", TransactionID: txID, State: "PENDING"}, nil
			},
			markReceivedFn: func(_ context.Context, _, _ string) (repo.Obligation, error) {
				marked = true
				return repo.Obligation{State: "RECEIVED"}, nil
			},
		},
	})
	resp, err := mp.ReportUsage(context.Background(), &rampv1.UsageReport{TransactionId: "tx-ok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.GetAccepted() {
		t.Error("expected Accepted = true")
	}
	if !marked {
		t.Error("MarkReceived was not called")
	}
}
