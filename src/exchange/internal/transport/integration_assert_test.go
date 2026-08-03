//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// money renders a test-authored float amount to the canonical wire decimal
// STRING the proto money fields now carry (money-as-string). It is the
// single test-side float→canonical-string crossing, matching production's
// FormatMoney semantics (5.0 -> "5", 0.050 -> "0.05", 0 -> "0"). Use it both to
// BUILD Pricing.rate/unit_cost and to express the EXPECTED string in assertions,
// so a test never hard-codes a representation that drifts from the canonical
// form.
func money(t *testing.T, amount float64) string {
	t.Helper()
	s, err := helpers.FormatMoney(decimal.NewFromFloat(amount))
	if err != nil {
		t.Fatalf("FormatMoney(%v): %v", amount, err)
	}
	return s
}

// ceAs is a thin errors.As wrapper for *connect.Error to keep test ergonomics
// compact.
func ceAs(err error, target **connect.Error) bool {
	var ce *connect.Error
	if err == nil {
		return false
	}
	ok := errors.As(err, &ce)
	if ok {
		*target = ce
	}
	return ok
}

// assertConnectCode fails the test unless err is a *connect.Error whose Code
// equals want. The error MUST be non-nil. Consolidated here so every
// transport-layer integration test asserts Connect codes with the same shape.
func assertConnectCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !ceAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	if ce.Code() != want {
		t.Fatalf("code = %v (msg %q), want %v", ce.Code(), ce.Message(), want)
	}
}

// assertConnectError combines assertConnectCode with a substring check on
// the error message. Used to pin the textual field-name detail produced by
// the validator.
func assertConnectError(t *testing.T, err error, want connect.Code, wantInMsg string) {
	t.Helper()
	assertConnectCode(t, err, want)
	var ce *connect.Error
	_ = ceAs(err, &ce)
	if wantInMsg != "" && !strings.Contains(ce.Message(), wantInMsg) {
		t.Errorf("message %q does not contain %q", ce.Message(), wantInMsg)
	}
}

// assertDenialReason fails unless err is a *connect.Error carrying a typed
// proto ErrorDetail whose transaction_denial reason equals want. This pins the
// ADR-019 contract: the machine-readable denial reason travels as a typed
// detail on the transport error (read here through the generated SDK type),
// never as a server-side string the client must parse.
func assertDenialReason(t *testing.T, err error, want rampv1.DenialReason) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !ceAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	for _, d := range ce.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		ed, ok := msg.(*rampv1.ErrorDetail)
		if !ok {
			continue
		}
		if got := ed.GetTransactionDenial().GetReason(); got != want {
			t.Fatalf("denial reason = %v, want %v", got, want)
		}
		// The exchange stamps Domain on every fault, the same
		// ErrorInfo-compatible grouping key the broker uses, so a generic client
		// attributes exchange and broker failures identically.
		if got := ed.GetDomain(); got != "ramp.v1.ExchangeService" {
			t.Fatalf("ErrorDetail.Domain = %q, want %q", got, "ramp.v1.ExchangeService")
		}
		return
	}
	t.Fatalf("no ErrorDetail/transaction_denial detail on error: %v", err)
}

// assertReportRejectionField fails unless err is a *connect.Error carrying a
// typed ErrorDetail whose Domain is the exchange and whose metadata["field"]
// equals wantField. This pins the contract: the offending field identity
// rides structured ErrorDetail.metadata, never the non-authoritative message.
func assertReportRejectionField(t *testing.T, err error, wantField string) {
	t.Helper()
	assertRejectionFieldInDomain(t, err, "ramp.v1.ExchangeService", wantField)
}

// assertCatalogRejectionField is the same assertion for the catalog surface,
// which is a separate service on the wire and stamps its own Domain.
func assertCatalogRejectionField(t *testing.T, err error, wantField string) {
	t.Helper()
	assertRejectionFieldInDomain(t, err, "ramp.v1.CatalogService", wantField)
}

func assertRejectionFieldInDomain(t *testing.T, err error, wantDomain, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !ceAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	for _, d := range ce.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		ed, ok := msg.(*rampv1.ErrorDetail)
		if !ok {
			continue
		}
		if got := ed.GetDomain(); got != wantDomain {
			t.Fatalf("ErrorDetail.Domain = %q, want %q", got, wantDomain)
		}
		if got := ed.GetMetadata()["field"]; got != wantField {
			t.Fatalf("ErrorDetail.metadata[field] = %q, want %q", got, wantField)
		}
		return
	}
	t.Fatalf("no ErrorDetail with field metadata on error: %v", err)
}

// assertErrorDomain fails unless err is a *connect.Error carrying a typed proto
// ErrorDetail whose Domain equals want. This pins the ADR-019 §1 contract that
// EVERY exchange fault — including DiscoverResources faults and non-denial
// ExecuteTransaction faults — stamps the ErrorInfo-compatible grouping key, the
// same way the broker stamps "ramp.v1.BrokerService" on every fault, so a generic
// client attributes exchange and broker failures identically. It mirrors
// assertDenialReason / assertReportRejectionField but checks only GetDomain(),
// read through the public Connect error envelope (Testing Doctrine §9 — never past
// the transport boundary).
func assertErrorDomain(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var ce *connect.Error
	if !ceAs(err, &ce) {
		t.Fatalf("not connect.Error: %v", err)
	}
	for _, d := range ce.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		ed, ok := msg.(*rampv1.ErrorDetail)
		if !ok {
			continue
		}
		if got := ed.GetDomain(); got != want {
			t.Fatalf("ErrorDetail.Domain = %q, want %q", got, want)
		}
		return
	}
	t.Fatalf("no ErrorDetail carrying Domain on error: %v", err)
}

// assertObligationState asserts the (state, validation_outcome) pair on the
// most-recent obligation for the given transaction. validated_at MUST be
// populated whenever wantOutcome is non-empty (every
// validation attempt stamps the audit timestamp).
func assertObligationState(t *testing.T, h *testHarness, txID string, wantState, wantOutcome string) {
	t.Helper()
	// Read through the production repository surface (Testing Doctrine pt9),
	// never the raw sqlc Querier.
	ob, err := repo.NewObligationRepo(h.queries).ByTransaction(h.ctx, txID)
	if err != nil {
		t.Fatalf("ObligationRepo.ByTransaction: %v", err)
	}
	if string(ob.State) != wantState {
		t.Errorf("state = %q, want %q", ob.State, wantState)
	}
	if gotOutcome := string(ob.ValidationOutcome); gotOutcome != wantOutcome {
		t.Errorf("validation_outcome = %q, want %q", gotOutcome, wantOutcome)
	}
	if wantOutcome != "" && ob.ValidatedAt.IsZero() {
		t.Errorf("validated_at not set; expected timestamp for outcome %q", wantOutcome)
	}
}

// readTenant returns h's tenant through the production repository surface — the
// documented Testing-Doctrine §9 tier-2 fallback, because no public tenant-config
// read RPC exists yet. Fatal on read error.
func readTenant(t *testing.T, h *testHarness) repo.Tenant {
	t.Helper()
	tenant, err := repo.NewTenantReadRepo(h.queries).ByID(h.ctx, h.tenantID)
	if err != nil {
		t.Fatalf("read tenant: %v", err)
	}
	return tenant
}

// readAuditRows returns the admin audit rows for tenantID through the production
// repository surface (tier-2 fallback — no public audit read RPC). tenantID is an
// explicit parameter so a negative test can read a MISSING tenant. Fatal on read error.
func readAuditRows(t *testing.T, h *testHarness, tenantID string) []repo.AuditRecord {
	t.Helper()
	rows, err := repo.NewAuditRepo(h.queries).ByTenant(h.ctx, tenantID)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	return rows
}

// readSingleAuditRow asserts exactly one admin audit row exists for tenantID and
// returns it — the shape both PersistsAndAudits tests expect after their single
// setter appends exactly one row.
func readSingleAuditRow(t *testing.T, h *testHarness, tenantID string) repo.AuditRecord {
	t.Helper()
	rows := readAuditRows(t, h, tenantID)
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	return rows[0]
}

// assertAuditAttribution checks the caller-attribution columns every successful
// admin audit row must carry: tenant, source address, request id, and creation
// time. source_addr is the only attribution signal on a plane with no per-operator
// identity, so both setters' PersistsAndAudits tests assert it identically.
func assertAuditAttribution(t *testing.T, h *testHarness, r repo.AuditRecord) {
	t.Helper()
	if r.TenantID != h.tenantID {
		t.Errorf("audit tenant_id = %q, want %q", r.TenantID, h.tenantID)
	}
	if r.SourceAddr == "" {
		t.Error("audit source_addr is empty")
	}
	if r.RequestID == nil || *r.RequestID == "" {
		t.Error("audit request_id is empty (RequestIDMiddleware should mint one)")
	}
	if r.CreatedAt.IsZero() {
		t.Error("audit created_at is zero")
	}
}

// assertNoPersistence fails unless h's tenant is still pristine (default fee 0,
// empty reporting_policy) AND no audit row exists — the shared "a rejected admin
// call mutated nothing" assertion for the negative paths.
func assertNoPersistence(t *testing.T, h *testHarness) {
	t.Helper()
	tenant := readTenant(t, h)
	if tenant.FeeRateBps != 0 || string(tenant.ReportingPolicy) != "{}" {
		t.Errorf("rejected call mutated tenant: fee=%d policy=%q", tenant.FeeRateBps, tenant.ReportingPolicy)
	}
	if rows := readAuditRows(t, h, h.tenantID); len(rows) != 0 {
		t.Errorf("audit rows = %d, want 0", len(rows))
	}
}

// newMultisigClient creates a Connect-Go client that signs with both agent and
// broker keys (a two-label RFC 9421 transport chain). Agent signature first,
// broker signature appended. Retained from v1.1 for the orthogonal catalog
// metadata / CoMP signature-parity tests (catalog_metadata_integration_test.go),
// which sign catalog-contributor requests with two keys. This is a generic
// two-label transport signer — NOT the relay re-package model; the execute
// agent-identity binding is established from the BODY agent-acceptance
// Not from a verbatim multisig chain. It composes the same
// two-SDK-transport chain as newMultisigSigningTransport (relay_r4_helper_test.go).
func newMultisigClient(base http.RoundTripper, serverURL, agentID string, agentPriv ed25519.PrivateKey, brokerID string, brokerPriv ed25519.PrivateKey) rampconnect.ExchangeServiceClient {
	rt := newMultisigSigningTransport(base, agentID, agentPriv, brokerID, brokerPriv)
	return rampconnect.NewExchangeServiceClient(&http.Client{Transport: rt}, serverURL, connect.WithGRPC())
}
