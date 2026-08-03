//go:build integration

package transport_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
)

// TestExecuteTransaction_AuditLogCarriesRequestID is the request-id regression
// guard for structured logging with request_id correlation.
//
// Round-trip honesty: this is a PROTOCOL round-trip. The write leg drives a
// real ExecuteTransaction RPC through the Connect-Go router and the full
// production middleware chain (RequestIDMiddleware → httpsig gate →
// CatalogSignatureMiddleware → handler → service). The OBSERVATION leg reads
// the service's slog output through a buffer-backed handler injected at server
// construction — a logging observation seam, NOT a DB / sqlc / Redis read
// (Testing Doctrine pt9 explicitly permits a log sink as an observation seam).
//
// RequestIDMiddleware binds the inbound X-Request-ID onto the context logger
// (reqctx.IntoContext). The service's execute-outcome line MUST emit through
// that context logger (reqctx.FromContext) so the line carries request_id.
// Before the fix the outcome line logged via the construction-time
// s.logger, which had no request_id attribute and (in this fixture) did not
// even share the buffer — so the VALIDATED outcome line was absent from the
// sink entirely. After the fix the line lands in the sink and carries the
// request_id.
func TestExecuteTransaction_AuditLogCarriesRequestID(t *testing.T) {
	const reqID = "corr-exec-audit-1"

	buf := &safeBuffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	h := newAuditHarness(t, logger)

	offer := h.seedAndDiscover(t)

	requester := &rampv1.Requester{
		Id: "agent-test", Domain: "agent.example",
		Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
	}
	req := connect.NewRequest(&rampv1.TransactionRequest{
		Ver: "1.0", IdempotencyKey: "tx-audit",
		Requester: requester,
		Items: []*rampv1.TransactionItem{
			{Offer: offer, AgentAcceptance: signAcceptanceFor(t, h.callerPriv, offer, requester, "tx-audit")},
		},
	})
	req.Header().Set("X-Request-ID", reqID)

	if _, err := h.client.ExecuteTransaction(h.ctx, req); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// Locate the execute-outcome audit line and assert it carries request_id.
	line := findLogLine(t, buf.String(), "exchange.execute_transaction")
	if got := line["request_id"]; got != reqID {
		t.Fatalf("execute_transaction audit line request_id = %v, want %q\nfull log:\n%s",
			got, reqID, buf.String())
	}
	if got := line["outcome"]; got != "VALIDATED" {
		t.Fatalf("execute_transaction audit line outcome = %v, want VALIDATED", got)
	}
}

// findLogLine scans newline-delimited JSON log records for the first record
// whose "msg" equals wantMsg and returns it decoded. Fails the test if no such
// record exists — that absence is itself the pre-fix symptom (the outcome line
// never reached this sink), so a missing line is a real failure, not a skip.
func findLogLine(t *testing.T, logged, wantMsg string) map[string]any {
	t.Helper()
	for _, raw := range strings.Split(strings.TrimSpace(logged), "\n") {
		if raw == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if rec["msg"] == wantMsg {
			return rec
		}
	}
	t.Fatalf("no log record with msg=%q; got:\n%s", wantMsg, logged)
	return nil
}

// auditHarness is a minimal transport-layer fixture whose middleware AND
// service-layer audit logging both flow through a caller-supplied logger, so a
// test can observe the audit lines the production chain emits. The shared
// newTestHarness fixture discards service logs (io.Discard) and exposes no
// logger seam; this bring-up injects one. It reuses the package's
// startExchangeServer / signing-transport plumbing so the request still
// traverses the production middleware chain.
type auditHarness struct {
	ctx          context.Context
	client       rampconnect.ExchangeServiceClient
	catalog      rampconnect.CatalogServiceClient
	tenantID     string
	tenantDomain string
	callerPriv   ed25519.PrivateKey
}

func newAuditHarness(t *testing.T, logger *slog.Logger) *auditHarness {
	t.Helper()
	const callerID = "agent-test"
	fx := setupExchangeTestDB(t, callerID)

	// Sign with the seeded agent's key so the verified key matches the pinned
	// agents-row key for callerID (identity↔key binding).
	callerPub, callerPriv := fx.agentPub, fx.agentPriv
	registry := newAllowAllRegistry()
	registry.put(callerID, callerPub)
	manifests := newAllowAllManifestCache(callerID)

	// Seed under the billing_ref the caller will register under: the
	// paid ExecuteTransaction this harness drives charges the ref-keyed account.
	bill := billing.NewInMemoryAdapter(billing.InMemoryOptions{
		Balances: map[string]billing.Amount{
			defaultCallerBillingRef: mustBillingAmount(t, "10.00", "USD"),
		},
	})
	offerSigner, err := signing.GenerateEd25519Signer()
	if err != nil {
		t.Fatalf("offer signer: %v", err)
	}

	srv := startExchangeServer(t, exchangeServerDeps{
		pool: fx.pool, queries: fx.queries, registry: registry, manifests: manifests,
		bill: bill, signer: offerSigner, keystore: fx.keystore, logger: logger,
		httpsigKeys:         map[string]ed25519.PublicKey{rwtestutil.MustThumbprintPriv(callerPriv): callerPub},
		defaultTenantDomain: fx.tenantDomain,
		billingRefGen:       func() string { return defaultCallerBillingRef },
	})
	if err := srv.catalogSvc.Bootstrap(fx.ctx); err != nil {
		t.Fatalf("catalog bootstrap: %v", err)
	}

	signingClient := &http.Client{Transport: newSigningTransport(srv.baseTransport, callerID, callerPriv)}
	client := rampconnect.NewExchangeServiceClient(signingClient, srv.server.URL, connect.WithGRPC())
	// Register the caller so its paid transaction authorizes against the ref-keyed
	// account, through the same public Register RPC production uses.
	registerDefaultCaller(t, fx.ctx, client)
	return &auditHarness{
		ctx:          fx.ctx,
		client:       client,
		catalog:      rampconnect.NewCatalogServiceClient(signingClient, srv.server.URL, connect.WithGRPC()),
		tenantID:     fx.tenantID,
		tenantDomain: fx.tenantDomain,
		callerPriv:   callerPriv,
	}
}

// seedAndDiscover pushes a single priced catalog entry and returns the first
// discovered offer, so the ExecuteTransaction happy path has a real offer +
// signature to transact. Mirrors seedCatalog/discoverFirst but threads this
// harness's clients (the shared helpers take *testHarness).
func (h *auditHarness) seedAndDiscover(t *testing.T) *rampv1.Offer {
	t.Helper()
	if _, err := h.catalog.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: "agent-test",
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.tenantDomain,
			Path:   "/articles/hello",
			Terms:  []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil {
		t.Fatalf("seed push: %v", err)
	}
	resp, err := h.client.DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{"https://" + h.tenantDomain + "/articles/hello"},
		Requester: &rampv1.Requester{
			Id: "agent-test", Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	offers := resp.Msg.GetOffers()
	if len(offers) == 0 {
		t.Fatal("no offers returned")
	}
	return offers[0]
}
