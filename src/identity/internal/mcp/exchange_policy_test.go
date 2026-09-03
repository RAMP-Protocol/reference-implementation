//go:build integration

package mcp_test

import (
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
)

// The Exchange allowlist is a deployment policy lever, and these drive it
// through the report leg. That leg routes through the SAME endpoint resolver the
// account tools do, so a report refused for a domain outside the list is
// evidence the overlay sits where nothing can go around it — not evidence about
// one tool's own argument checking.
//
// The account tools drive the same lever in tools_account_negatives_test.go,
// where what is under test is different: their own refusal, and the manifest
// read that never reaches a resolver at all.

// TestReport_RefusesAnExchangeOutsideTheAllowlist pins the lever ON. The refusal
// has to happen before anything is dialled, so the assertion is not only that
// the tool errored but that the excluded Exchange saw no HTTP request at all —
// not even the manifest read that resolution would start with.
func TestReport_RefusesAnExchangeOutsideTheAllowlist(t *testing.T) {
	// The list names the issuer peer and nobody else, so the other peer is the
	// excluded one and both sides of the lever are reachable in one fixture.
	f := newBoundedFixture(t, func(cfg *app.MCPConfig, p peerSet) {
		cfg.ExchangeAllowlist = p.issuer.Domain(t)
	})

	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion, ReportId: "rep-1"}
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	// A domain outside the list: refused, and nothing dialled.
	before := f.exchange.HTTPRequests()
	msg := callToolErr(t, session, "ramp_report", map[string]any{
		"exchange":        f.exchange.Domain(t),
		"transaction_id":  "tx-1",
		"idempotency_key": "idem-1",
	})
	if msg == "" {
		t.Fatal("a report to an Exchange outside the allowlist was accepted")
	}
	if got := f.exchange.HTTPRequests(); got != before {
		t.Errorf("the excluded Exchange saw %d requests, want none — the refusal must precede the manifest read", got-before)
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("the excluded Exchange received an RPC")
	}

	// A domain inside it still works, so the lever confines rather than blocks.
	out := callTool[reportResult](t, session, "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-2",
		"idempotency_key": "idem-2",
	})
	if out.ReportID != "rep-1" {
		t.Fatalf("a listed Exchange was refused: report_id = %q", out.ReportID)
	}
}

// TestReport_AnEmptyAllowlistPermitsEveryExchange pins the default posture,
// which is the one every deployment that predates the lever runs with. An empty
// list that refused would take all of them down on upgrade.
func TestReport_AnEmptyAllowlistPermitsEveryExchange(t *testing.T) {
	f := newFixture(t)
	f.issuer.reportResp = &rampv1.UsageReportResponse{Ver: helpers.ProtocolVersion, ReportId: "rep-1"}
	a := f.provision(t, "dev-one")

	out := callTool[reportResult](t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-1",
		"idempotency_key": "idem-1",
	})
	if out.ReportID != "rep-1" {
		t.Fatalf("report_id = %q, want rep-1", out.ReportID)
	}
}

// TestBuild_RefusesAMalformedAllowlistEntry pins that the policy is parsed at
// start-up. A dropped entry would leave the operator with a narrower policy than
// they wrote, and the first evidence would be a refused registration.
func TestBuild_RefusesAMalformedAllowlistEntry(t *testing.T) {
	_, err := buildFixture(t, func(cfg *app.MCPConfig, _ peerSet) {
		cfg.ExchangeAllowlist = "exchange.example,https://exchange-b.example"
	})
	if err == nil {
		t.Fatal("app.Build accepted a malformed allowlist entry")
	}
	if !strings.Contains(err.Error(), "https://exchange-b.example") {
		t.Fatalf("the error does not name the offending entry: %v", err)
	}
}
