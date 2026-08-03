//go:build integration

package transport_test

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	connect "connectrpc.com/connect"
	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1/rampadminv1connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// startAdminServer stands up the SEPARATE admin listener sharing h's pool/queries by
// calling the SAME transport.WrapAdminSurface the production cmd/server path uses, so
// the test exercises production's wiring (emit-unpopulated codec + the bidirectional
// protovalidate interceptor + NO request-signing, RequestID outermost → IP-allowlist)
// rather than a hand-rebuilt replica. The client is PLAIN (unsigned): the admin plane
// has no verified signer; the allowlist is the only gate. allowCIDRs configures the
// allowlist (e.g. "127.0.0.0/8" to admit the httptest loopback client, or a non-loopback
// range to drive the 403 path). Returns the client and the base URL (the latter for the
// raw-HTTP codec/403 tests).
func startAdminServer(t *testing.T, h *testHarness, allowCIDRs string) (rampadminv1connect.AdminServiceClient, string) {
	t.Helper()
	adminSvc := service.NewAdminServiceFromPool(h.pool, h.queries)
	wrapped, err := transport.WrapAdminSurface(testutil.DiscardLogger(), adminSvc, allowCIDRs)
	if err != nil {
		t.Fatalf("build admin handler: %v", err)
	}
	srv := httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)
	client := rampadminv1connect.NewAdminServiceClient(srv.Client(), srv.URL)
	return client, srv.URL
}

// mustSetFee drives SetTenantFeeRate for h's tenant and fails on error.
func mustSetFee(
	t *testing.T, h *testHarness, admin rampadminv1connect.AdminServiceClient, bps int32, notes *string,
) *connect.Response[rampadminv1.SetTenantFeeRateResponse] {
	t.Helper()
	resp, err := admin.SetTenantFeeRate(h.ctx, connect.NewRequest(&rampadminv1.SetTenantFeeRateRequest{
		Ver:  "1.0",
		Rate: &rampadminv1.TenantFeeRate{TenantId: h.tenantID, FeeRateBps: bps, Notes: notes},
	}))
	if err != nil {
		t.Fatalf("SetTenantFeeRate(bps=%d): %v", bps, err)
	}
	return resp
}

// mustSetPolicy drives SetReportingPolicy for h's tenant (stamping the tenant id
// onto the payload) and fails on error.
func mustSetPolicy(
	t *testing.T, h *testHarness, admin rampadminv1connect.AdminServiceClient, policy *rampadminv1.ReportingPolicy,
) *connect.Response[rampadminv1.SetReportingPolicyResponse] {
	t.Helper()
	policy.TenantId = h.tenantID
	resp, err := admin.SetReportingPolicy(h.ctx, connect.NewRequest(&rampadminv1.SetReportingPolicyRequest{
		Ver:    "1.0",
		Policy: policy,
	}))
	if err != nil {
		t.Fatalf("SetReportingPolicy: %v", err)
	}
	return resp
}

// TestAdmin_SetTenantFeeRate_AppliedAtRecord drives the fee through the admin RPC
// and asserts the settled split on the real TigerBeetle ledger. Order matters: the
// rate is set BEFORE ExecuteTransaction — it is resolved live from the tenant row
// at Authorize and frozen on the hold, then recovered at Record. The default owner
// has no per-owner override, so the tenant default applies.
func TestAdmin_SetTenantFeeRate_AppliedAtRecord(t *testing.T) {
	salt := sharedTB.Salt(t)
	h, _ := newTBHarness(t, salt, 0, harnessOptions{}) // start at 0; set via the admin RPC below
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")
	fundTBAgent(t, salt, h.billingRef, "10.00")

	mustSetFee(t, h, admin, 1000, nil) // 10% via the admin plane

	executeTransactionFor(t, h, 20) // gross = 0.05 × 20 = 1.00
	// Split at 10%: agent −1.00 → 9.00; owner +0.90; platform +0.10.
	h.assertSplitBalances(t, salt, "9.00", "0.90", "0.10")
}

// TestAdmin_SetReportingPolicy_ZeroTolerance_ExactMatch drives quantity_tolerance=0
// through the admin RPC and proves it is enforced as exact-match end to end (the
// bug fixed in this ticket: 0 previously fell back to ±20%). Order matters: the
// policy is snapshotted onto the obligation at Execute, so it is set BEFORE
// ExecuteTransaction.
func TestAdmin_SetReportingPolicy_ZeroTolerance_ExactMatch(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	tol := 0.0
	mustSetPolicy(t, h, admin, &rampadminv1.ReportingPolicy{QuantityTolerance: &tol})

	txID, billingID := executeTransactionFor(t, h, 100)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-tol0", TransactionId: txID, BillingId: billingID,
		Usage: &rampv1.Usage{ConsumedQuantity: 101}, // off by one → exact-match reject
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "outside")
	assertReportRejectionField(t, err, "consumed_quantity")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_TOLERANCE")
}

// TestAdmin_SetReportingPolicy_RequiredFields_Enforced drives a required_fields
// policy through the admin RPC and confirms a report missing that field is
// rejected at ReportUsage. Set BEFORE ExecuteTransaction (snapshot-at-Execute).
func TestAdmin_SetReportingPolicy_RequiredFields_Enforced(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	mustSetPolicy(t, h, admin, &rampadminv1.ReportingPolicy{RequiredFields: []string{"billing_id"}})

	txID, _ := executeTransactionFor(t, h, 100)
	_, err := h.exchangeClient.ReportUsage(h.ctx, connect.NewRequest(&rampv1.UsageReport{
		Ver: "1.0", IdempotencyKey: "r-req", TransactionId: txID, BillingId: "", // required but empty
		Usage: &rampv1.Usage{ConsumedQuantity: 100},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "billing_id")
	assertReportRejectionField(t, err, "billing_id")
	assertObligationState(t, h, txID, "PENDING", "REJECTED_FIELDS")
}

// reportingPolicyJSON mirrors the reporting_policy JSONB shape — shared by the
// persisted-tenant read-back and the audit-detail read-back (both carry the same
// three policy fields).
type reportingPolicyJSON struct {
	RequiredFields    []string `json:"required_fields"`
	QuantityTolerance *float64 `json:"quantity_tolerance"`
	WindowSeconds     *int32   `json:"window_seconds"`
}

// TestAdmin_SetReportingPolicy_PersistsAndAudits asserts the echo, the persisted
// reporting_policy JSONB, and the audit row (action + detail) for a successful
// policy change — the SetReportingPolicy positive that pins the audit-detail
// reconstruction record. Read-backs use the production repository interface
// (tier-2 Testing-Doctrine §9 fallback — no public read RPC yet).
func TestAdmin_SetReportingPolicy_PersistsAndAudits(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	tol := 0.1
	var win int32 = 3600
	resp := mustSetPolicy(t, h, admin, &rampadminv1.ReportingPolicy{
		RequiredFields:    []string{"billing_id", "timestamp"},
		QuantityTolerance: &tol,
		WindowSeconds:     &win,
	})

	// Echo mirrors the persisted payload.
	if resp.Msg.GetVer() != "1.0" {
		t.Errorf("ver = %q, want 1.0", resp.Msg.GetVer())
	}
	if got := resp.Msg.GetPolicy().GetQuantityTolerance(); got != tol {
		t.Errorf("echoed quantity_tolerance = %v, want %v", got, tol)
	}
	if got := resp.Msg.GetPolicy().GetWindowSeconds(); got != win {
		t.Errorf("echoed window_seconds = %d, want %d", got, win)
	}

	// Persisted reporting_policy JSONB (tier-2 repo fallback — no public read RPC).
	tenant := readTenant(t, h)
	var policy reportingPolicyJSON
	if err := json.Unmarshal(tenant.ReportingPolicy, &policy); err != nil {
		t.Fatalf("unmarshal reporting_policy %s: %v", tenant.ReportingPolicy, err)
	}
	if len(policy.RequiredFields) != 2 || policy.RequiredFields[0] != "billing_id" {
		t.Errorf("persisted required_fields = %v, want [billing_id timestamp]", policy.RequiredFields)
	}
	if policy.QuantityTolerance == nil || *policy.QuantityTolerance != tol {
		t.Errorf("persisted quantity_tolerance = %v, want %v", policy.QuantityTolerance, tol)
	}
	if policy.WindowSeconds == nil || *policy.WindowSeconds != win {
		t.Errorf("persisted window_seconds = %v, want %d", policy.WindowSeconds, win)
	}

	// Audit row: action + attribution + the applied-values detail. On a plane with
	// no per-operator identity source_addr is the only attribution signal, so assert
	// the caller attribution here too (parity with the fee-rate twin).
	r := readSingleAuditRow(t, h, h.tenantID)
	if r.Action != "SetReportingPolicy" {
		t.Errorf("audit action = %q, want SetReportingPolicy", r.Action)
	}
	assertAuditAttribution(t, h, r)
	var detail reportingPolicyJSON
	if err := json.Unmarshal(r.Detail, &detail); err != nil {
		t.Fatalf("unmarshal audit detail %s: %v", r.Detail, err)
	}
	if len(detail.RequiredFields) != 2 {
		t.Errorf("detail required_fields = %v, want 2 entries", detail.RequiredFields)
	}
	if detail.QuantityTolerance == nil || *detail.QuantityTolerance != tol {
		t.Errorf("detail quantity_tolerance = %v, want %v", detail.QuantityTolerance, tol)
	}
	if detail.WindowSeconds == nil || *detail.WindowSeconds != win {
		t.Errorf("detail window_seconds = %v, want %d", detail.WindowSeconds, win)
	}
}

// TestAdmin_SetTenantFeeRate_PersistsAndAudits asserts the echo, the persisted
// tenant row, and the audit row for a successful fee change. The read-backs use the
// production repository interface — the documented Testing-Doctrine §9 tier-2
// fallback, because no public tenant-config or audit read RPC exists yet.
func TestAdmin_SetTenantFeeRate_PersistsAndAudits(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	notes := "q3 promo rate"
	resp := mustSetFee(t, h, admin, 250, &notes)

	// Echo mirrors the persisted payload.
	if resp.Msg.GetVer() != "1.0" {
		t.Errorf("ver = %q, want 1.0", resp.Msg.GetVer())
	}
	if got := resp.Msg.GetRate().GetFeeRateBps(); got != 250 {
		t.Errorf("echoed fee_rate_bps = %d, want 250", got)
	}
	if got := resp.Msg.GetRate().GetNotes(); got != notes {
		t.Errorf("echoed notes = %q, want %q", got, notes)
	}

	// Persisted tenant row (tier-2 repo fallback — no public read RPC).
	tenant := readTenant(t, h)
	if tenant.FeeRateBps != 250 {
		t.Errorf("persisted fee_rate_bps = %d, want 250", tenant.FeeRateBps)
	}
	if tenant.FeeRateNotes == nil || *tenant.FeeRateNotes != notes {
		t.Errorf("persisted notes = %v, want %q", tenant.FeeRateNotes, notes)
	}

	// Audit row (tier-2 repo fallback — no public read RPC).
	r := readSingleAuditRow(t, h, h.tenantID)
	if r.Action != "SetTenantFeeRate" {
		t.Errorf("audit action = %q, want SetTenantFeeRate", r.Action)
	}
	assertAuditAttribution(t, h, r)
	// The audit detail JSONB is the sole reconstruction record on this plane — assert
	// the applied values were captured, not merely the action.
	var detail struct {
		TenantID   string  `json:"tenant_id"`
		FeeRateBps int     `json:"fee_rate_bps"`
		Notes      *string `json:"notes"`
	}
	if err := json.Unmarshal(r.Detail, &detail); err != nil {
		t.Fatalf("unmarshal audit detail %s: %v", r.Detail, err)
	}
	if detail.TenantID != h.tenantID {
		t.Errorf("detail tenant_id = %q, want %q", detail.TenantID, h.tenantID)
	}
	if detail.FeeRateBps != 250 {
		t.Errorf("detail fee_rate_bps = %d, want 250", detail.FeeRateBps)
	}
	if detail.Notes == nil || *detail.Notes != notes {
		t.Errorf("detail notes = %v, want %q", detail.Notes, notes)
	}
}

// TestAdmin_SetTenantFeeRate_OmittedNotesClears proves full-replace semantics for
// the note: a second call without a note clears the column to NULL and echoes it
// as absent.
func TestAdmin_SetTenantFeeRate_OmittedNotesClears(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	notes := "temporary"
	mustSetFee(t, h, admin, 250, &notes)

	resp := mustSetFee(t, h, admin, 300, nil) // full replace, no note
	if resp.Msg.GetRate().Notes != nil {
		t.Errorf("echoed notes = %v, want absent after clear", resp.Msg.GetRate().Notes)
	}

	tenant := readTenant(t, h)
	if tenant.FeeRateNotes != nil {
		t.Errorf("persisted notes = %q, want nil (cleared)", *tenant.FeeRateNotes)
	}
	if tenant.FeeRateBps != 300 {
		t.Errorf("persisted fee_rate_bps = %d, want 300", tenant.FeeRateBps)
	}
}
