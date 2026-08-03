//go:build integration

package transport_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampadminv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1"
)

// TestAdmin_SetTenantFeeRate_UnknownTenant_NotFound drives a setter for a tenant
// that does not exist: the rows-affected check turns the no-op into CodeNotFound,
// and — because the audit write shares the setter's transaction and runs only
// after that check — NOTHING is persisted (no tenant mutation, no audit row).
func TestAdmin_SetTenantFeeRate_UnknownTenant_NotFound(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	const missing = "t_does_not_exist"
	_, err := admin.SetTenantFeeRate(h.ctx, connect.NewRequest(&rampadminv1.SetTenantFeeRateRequest{
		Ver:  "1.0",
		Rate: &rampadminv1.TenantFeeRate{TenantId: missing, FeeRateBps: 100},
	}))
	assertConnectError(t, err, connect.CodeNotFound, "")

	rows := readAuditRows(t, h, missing)
	if len(rows) != 0 {
		t.Errorf("audit rows for unknown tenant = %d, want 0 (tx rolled back)", len(rows))
	}
	// The real tenant is untouched (still the default 0).
	tenant := readTenant(t, h)
	if tenant.FeeRateBps != 0 {
		t.Errorf("real tenant fee_rate_bps = %d, want 0 (untouched)", tenant.FeeRateBps)
	}
}

// TestAdmin_SetReportingPolicy_UnknownTenant_NotFound is the SetReportingPolicy dual
// of the fee-rate unknown-tenant test: it drives the rows-affected→KindNotFound→
// rollback path through the SetReportingPolicy RPC directly (not only the shared
// runSetter via the fee RPC), so a regression that broke the not-found check on the
// policy path alone would be caught. The audit write shares the setter's transaction
// and runs only after the rows-affected check, so nothing persists.
func TestAdmin_SetReportingPolicy_UnknownTenant_NotFound(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	const missing = "t_does_not_exist"
	tol := 0.1
	_, err := admin.SetReportingPolicy(h.ctx, connect.NewRequest(&rampadminv1.SetReportingPolicyRequest{
		Ver:    "1.0",
		Policy: &rampadminv1.ReportingPolicy{TenantId: missing, QuantityTolerance: &tol},
	}))
	assertConnectError(t, err, connect.CodeNotFound, "")

	rows := readAuditRows(t, h, missing)
	if len(rows) != 0 {
		t.Errorf("audit rows for unknown tenant = %d, want 0 (tx rolled back)", len(rows))
	}
	// The real tenant is untouched (seed default reporting_policy {}, fee 0) and has
	// no audit row.
	assertNoPersistence(t, h)
}

// TestAdmin_SetReportingPolicy_UnknownToken_InvalidArgument drives a
// required_fields policy naming a token the validator cannot enforce. The token is
// pattern-valid (so it passes the protovalidate interceptor) but not a known field,
// so the service-layer membership check rejects it with CodeInvalidArgument naming
// the token, and nothing persists.
func TestAdmin_SetReportingPolicy_UnknownToken_InvalidArgument(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	_, err := admin.SetReportingPolicy(h.ctx, connect.NewRequest(&rampadminv1.SetReportingPolicyRequest{
		Ver:    "1.0",
		Policy: &rampadminv1.ReportingPolicy{TenantId: h.tenantID, RequiredFields: []string{"bogus_field"}},
	}))
	assertConnectError(t, err, connect.CodeInvalidArgument, "bogus_field")

	assertNoPersistence(t, h)
}

// TestAdmin_ValidateInterceptor_RejectsOutOfRange exercises the buf.validate bounds
// on the admin messages — all rejected by the bidirectional protovalidate
// interceptor (CodeInvalidArgument), never re-implemented in the service — and
// asserts none of the rejected calls persisted anything.
func TestAdmin_ValidateInterceptor_RejectsOutOfRange(t *testing.T) {
	h := newTestHarness(t)
	admin, _ := startAdminServer(t, h, "127.0.0.0/8")

	longNote := strings.Repeat("x", 1025)
	tol := 1.5
	var winZero int32 // 0 violates window_seconds > 0

	cases := []struct {
		name      string
		wantField string
		call      func() error
	}{
		{"fee_rate_bps_too_high", "fee_rate_bps", func() error {
			_, err := admin.SetTenantFeeRate(h.ctx, connect.NewRequest(&rampadminv1.SetTenantFeeRateRequest{
				Ver: "1.0", Rate: &rampadminv1.TenantFeeRate{TenantId: h.tenantID, FeeRateBps: 10000},
			}))
			return err
		}},
		{"notes_too_long", "notes", func() error {
			_, err := admin.SetTenantFeeRate(h.ctx, connect.NewRequest(&rampadminv1.SetTenantFeeRateRequest{
				Ver: "1.0", Rate: &rampadminv1.TenantFeeRate{TenantId: h.tenantID, FeeRateBps: 100, Notes: &longNote},
			}))
			return err
		}},
		{"tolerance_above_one", "quantity_tolerance", func() error {
			_, err := admin.SetReportingPolicy(h.ctx, connect.NewRequest(&rampadminv1.SetReportingPolicyRequest{
				Ver: "1.0", Policy: &rampadminv1.ReportingPolicy{TenantId: h.tenantID, QuantityTolerance: &tol},
			}))
			return err
		}},
		{"window_seconds_zero", "window_seconds", func() error {
			_, err := admin.SetReportingPolicy(h.ctx, connect.NewRequest(&rampadminv1.SetReportingPolicyRequest{
				Ver: "1.0", Policy: &rampadminv1.ReportingPolicy{TenantId: h.tenantID, WindowSeconds: &winZero},
			}))
			return err
		}},
		{"duplicate_required_fields", "required_fields", func() error {
			_, err := admin.SetReportingPolicy(h.ctx, connect.NewRequest(&rampadminv1.SetReportingPolicyRequest{
				Ver:    "1.0",
				Policy: &rampadminv1.ReportingPolicy{TenantId: h.tenantID, RequiredFields: []string{"billing_id", "billing_id"}},
			}))
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Anchor on the offending field name (protovalidate renders the dotted
			// path, e.g. "rate.fee_rate_bps") so a bound loosened for one field can't
			// pass on an unrelated field's rejection.
			assertConnectError(t, tc.call(), connect.CodeInvalidArgument, tc.wantField)
			// Checked per case (not once after the loop) so a case that leaks
			// persistence names itself instead of surfacing at a trailing assert.
			assertNoPersistence(t, h)
		})
	}
}

// TestAdmin_IPAllowlist_RejectsDisallowedSource points the allowlist at a range
// that excludes the httptest loopback client and asserts the middleware returns 403
// (before Connect) and persists nothing. Driven with a raw HTTP POST so the
// assertion is on the HTTP status the middleware sets, not a Connect code mapping.
func TestAdmin_IPAllowlist_RejectsDisallowedSource(t *testing.T) {
	h := newTestHarness(t)
	_, url := startAdminServer(t, h, "10.0.0.0/8") // excludes 127.0.0.1

	body := `{"ver":"1.0","rate":{"tenant_id":"` + h.tenantID + `","fee_rate_bps":100}}`
	resp := adminPostJSON(t, h, url, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}

	assertNoPersistence(t, h)
}

// TestAdmin_IPAllowlist_EmptyDeniesAll drives the fail-closed default: an empty
// ADMIN_ALLOWED_CIDRS admits nothing, so even the loopback httptest client is
// rejected with 403 before Connect and nothing persists. This pins the load-bearing
// "empty allowlist denies everything" default (ADR-022 §8) that no other test drives.
func TestAdmin_IPAllowlist_EmptyDeniesAll(t *testing.T) {
	h := newTestHarness(t)
	_, url := startAdminServer(t, h, "") // empty allowlist → fail-closed

	body := `{"ver":"1.0","rate":{"tenant_id":"` + h.tenantID + `","fee_rate_bps":100}}`
	resp := adminPostJSON(t, h, url, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (empty allowlist denies all)", resp.StatusCode)
	}
	assertNoPersistence(t, h)
}

// TestAdmin_JSONEcho_EmitsZeroFeeAndSnakeCase drives a JSON request and asserts the
// response is snake_case and keeps "fee_rate_bps":0 (default protojson would drop a
// zero singular scalar — the exact value the read-back exists to confirm), with the
// omitted note absent. This exercises the emit-unpopulated codec on the admin mount.
func TestAdmin_JSONEcho_EmitsZeroFeeAndSnakeCase(t *testing.T) {
	h := newTestHarness(t)
	_, url := startAdminServer(t, h, "127.0.0.0/8")

	body := `{"ver":"1.0","rate":{"tenant_id":"` + h.tenantID + `","fee_rate_bps":0}}`
	resp := adminPostJSON(t, h, url, body)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, raw)
	}

	// Parse structurally so the assertion is robust to protojson's whitespace.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal response %s: %v", raw, err)
	}
	if got := string(envelope["ver"]); got != `"1.0"` {
		t.Errorf("ver = %s, want \"1.0\"", got)
	}
	var rate map[string]json.RawMessage
	if err := json.Unmarshal(envelope["rate"], &rate); err != nil {
		t.Fatalf("unmarshal rate: %v", err)
	}
	if got, ok := rate["fee_rate_bps"]; !ok || string(got) != "0" {
		t.Errorf("fee_rate_bps = %s (present=%v), want 0 present (emit-unpopulated)", got, ok)
	}
	if _, ok := rate["feeRateBps"]; ok {
		t.Error("response used camelCase feeRateBps, want snake_case")
	}
	if _, ok := rate["tenant_id"]; !ok {
		t.Error("tenant_id missing from echoed rate")
	}
	if _, ok := rate["notes"]; ok {
		t.Error("omitted notes should be absent from the echo")
	}
}

// adminPostJSON issues a Connect unary JSON POST to the admin procedure. Uses a
// context-bound request (noctx) and the default client (the httptest listener is
// loopback TCP).
func adminPostJSON(t *testing.T, h *testHarness, baseURL, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost,
		baseURL+"/ramp.admin.v1.AdminService/SetTenantFeeRate", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}
