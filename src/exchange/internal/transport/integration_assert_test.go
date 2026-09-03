//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/shopspring/decimal"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// money renders a test-authored float amount to the canonical wire decimal
// STRING the proto money fields now carry (money-as-string). It is the
// single test-side float→canonical-string crossing, matching production's
// FormatMoney semantics (5.0 -> "5", 0.050 -> "0.05", 0 -> "0"). Use it both to
// BUILD Pricing.rate/unit_cost and to express the EXPECTED string in assertions,
// so a test never hard-codes a representation that drifts from the canonical
// form.
// exchangeServiceDomainLiteral is the ErrorDetail.Domain every ExchangeService
// fault must carry (ADR-019). A client filtering on domain uses it to tell an
// exchange fault from a catalog one, which carries ramp.v1.CatalogService.
//
// Written out rather than read from the production constant, which this external
// test package cannot see anyway. A test that reads the value it is checking
// cannot detect a wrong value — the same reason registrationAuditAction keeps
// its own literal.
//
// It is defined here, with the shared assertions, because six files across this
// package assert on it. Each of them spelled it out separately until they were
// pointed at this one name.
const exchangeServiceDomainLiteral = "ramp.v1.ExchangeService"

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
	ed := testutil.SingleErrorDetail(t, err)
	if got := ed.GetTransactionDenial().GetReason(); got != want {
		t.Fatalf("denial reason = %v, want %v", got, want)
	}
	// The exchange stamps Domain on every fault, the same ErrorInfo-compatible
	// grouping key the broker uses, so a generic client attributes exchange and
	// broker failures identically.
	if got := ed.GetDomain(); got != exchangeServiceDomainLiteral {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, exchangeServiceDomainLiteral)
	}
}

// assertReportRejectionField fails unless err is a *connect.Error carrying a
// typed ErrorDetail whose Domain is the exchange and whose metadata["field"]
// equals wantField. This pins the contract: the offending field identity
// rides structured ErrorDetail.metadata, never the non-authoritative message.
func assertReportRejectionField(t *testing.T, err error, wantField string) {
	t.Helper()
	assertRejectionFieldInDomain(t, err, exchangeServiceDomainLiteral, wantField)
}

// assertCatalogRejectionField is the same assertion for the catalog surface,
// which is a separate service on the wire and stamps its own Domain.
func assertCatalogRejectionField(t *testing.T, err error, wantField string) {
	t.Helper()
	assertRejectionFieldInDomain(t, err, "ramp.v1.CatalogService", wantField)
}

// assertRejectionMeta fails unless err carries an ErrorDetail whose
// metadata[key] equals want. It reads an axis other than the offending field —
// item_index, which tells a client WHICH item of a batch envelope was rejected —
// so a caller can act on the rejection without parsing the message string.
func assertRejectionMeta(t *testing.T, err error, key, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	ed := testutil.SingleErrorDetail(t, err)
	if got := ed.GetMetadata()[key]; got != want {
		t.Fatalf("ErrorDetail.metadata[%q] = %q, want %q", key, got, want)
	}
}

func assertRejectionFieldInDomain(t *testing.T, err error, wantDomain, wantField string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	ed := testutil.SingleErrorDetail(t, err)
	if got := ed.GetDomain(); got != wantDomain {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, wantDomain)
	}
	if got := ed.GetMetadata()["field"]; got != wantField {
		t.Fatalf("ErrorDetail.metadata[field] = %q, want %q", got, wantField)
	}
}

// findLogLine scans newline-delimited JSON log records for the first record
// whose "msg" equals wantMsg and returns it decoded. Fails the test if no such
// record exists — a line that never reached the sink is a real failure, not a
// skip, and it is a different failure from a line that reached it carrying the
// wrong fields.
func findLogLine(t *testing.T, logged, wantMsg string) map[string]any {
	t.Helper()
	return findLogRecord(t, logged, wantMsg, func(map[string]any) bool { return true })
}

// findLogRecord is findLogLine with a predicate over the decoded record, for a
// sink that holds several records with the same msg (one per subtest, say)
// where the caller must pick the one about its own request.
//
// Selecting a record and then reading its fields is how this package asserts on
// a log line. A pair of substring searches over the whole sink is not the same
// check: the sink accumulates, so one record can satisfy the message key while
// a different one satisfies the field, and the assertion passes over two
// requests neither of which did what was claimed.
func findLogRecord(t *testing.T, logged, wantMsg string, match func(map[string]any) bool) map[string]any {
	t.Helper()
	for _, raw := range strings.Split(strings.TrimSpace(logged), "\n") {
		if raw == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(raw), &rec); err != nil {
			continue
		}
		if rec["msg"] == wantMsg && match(rec) {
			return rec
		}
	}
	t.Fatalf("no log record with msg=%q (matching the caller's predicate); got:\n%s", wantMsg, logged)
	return nil
}

// assertRejectOutcome reads the exchange's reject line out of captured JSON log
// output and checks the audit token THAT record carries. An absent reject line
// and a mislabelled one are different failures, and findLogLine reports the
// first before this reads the second.
//
// The outcome is read off the selected record rather than searched for in the
// sink, because the sink holds every record the harness produced: a search
// would pass on a buffer where one request logged the message key and another
// logged the wanted outcome.
//
// It is here rather than beside one scenario because both mounts that can
// refuse a request before it reaches a handler assert on it: the
// ExchangeService mount, where the SDK's verify seam emits the line, and the
// catalog mount, where the capture middleware calls the same observer itself.
func assertRejectOutcome(t *testing.T, logged, want string) {
	t.Helper()
	rec := findLogLine(t, logged, "exchange.httpsig.reject")
	if got, _ := rec["outcome"].(string); got != want {
		t.Errorf("reject line outcome = %q, want %q (line: %v)", got, want, rec)
	}
}

// assertOfferCount is the catalog read leg's persistence probe: one offer means
// the entry reached the catalog, zero means it did not. Every catalog suite
// observes persistence through DiscoverResources rather than the database, so
// this is the shape of that check for the whole package.
func assertOfferCount(t *testing.T, h *pushHarness, uri string, want int) {
	t.Helper()
	if got := discoverOfferCount(t, h, uri); got != want {
		t.Fatalf("DiscoverResources offers for %s = %d, want %d", uri, got, want)
	}
}

// assertCatalogRejectLogged fails unless the server recorded the entry at path
// as refused, under the machine-readable reason it expects.
//
// It is the uniform half of a catalog refusal's audit trail: every refused
// entry gets one of these lines whatever gate refused it, so a reason that
// never had a line of its own is covered here rather than needing a bespoke
// assertion per gate. The record is selected by URI, because the harness's log
// sink accumulates one line per refused entry of every push a test makes.
func assertCatalogRejectLogged(t *testing.T, h *pushHarness, path, wantReason string) {
	t.Helper()
	uri := "https://" + h.publisherDom + path
	line := findLogRecord(t, h.logs.String(), "exchange.catalog_push.reject",
		func(rec map[string]any) bool { return rec["uri"] == uri })
	if got, _ := line["reason"].(string); got != wantReason {
		t.Errorf("catalog reject line reason = %q, want %q (line: %v)", got, wantReason, line)
	}
	if got, _ := line["level"].(string); got != "WARN" {
		t.Errorf("catalog reject line level = %q, want WARN (line: %v)", got, line)
	}
	if got, _ := line["request_id"].(string); got == "" {
		t.Errorf("catalog reject line carries no request_id (line: %v)", line)
	}
}

// assertRecipientRefusal fails unless err carries the recipient interceptor's own
// ErrorDetail with the expected verdict.
//
// It reads the VERDICT rather than the message. The three refusals differ only
// in their sentence, and protovalidate refuses two of the same three inputs with
// a message that also contains the word "exchange" — so a substring assertion
// passes whether or not the interceptor ran at all, which is what these tests
// exist to prove. The verdict token appears in no other rejection.
func assertRecipientRefusal(t *testing.T, err error, wantVerdict string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	got := testutil.SingleErrorDetail(t, err).GetMetadata()["verdict"]
	if got == "" {
		t.Fatalf("the ErrorDetail carries no verdict — the refusal did not come from "+
			"the recipient check: %v", err)
	}
	if got != wantVerdict {
		t.Fatalf("recipient verdict = %q, want %q", got, wantVerdict)
	}
}

// assertRefusedItemIndex fails unless err carries a typed ErrorDetail naming
// which item was refused. It is separate from the field assertion because the
// two answer different questions for a caller holding a batch: which field to
// look at, and which of its items to look at.
func assertRefusedItemIndex(t *testing.T, err error, wantIndex string) {
	t.Helper()
	if got := testutil.SingleErrorDetail(t, err).GetMetadata()["item_index"]; got != wantIndex {
		t.Fatalf("ErrorDetail.metadata[item_index] = %q, want %q", got, wantIndex)
	}
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
	if got := testutil.SingleErrorDetail(t, err).GetDomain(); got != want {
		t.Fatalf("ErrorDetail.Domain = %q, want %q", got, want)
	}
}

// assertObligationState asserts the (state, validation_outcome) pair on the
// obligation for the given transaction, read through the operator evidence RPC —
// the public surface an obligation is read through, and the same one every other
// obligation assertion in this package uses. validated_at MUST be populated
// whenever wantOutcome is non-empty: every validation attempt stamps it.
//
// wantOutcome "" means no report has been validated yet, which the route renders
// by omitting validation_outcome rather than sending an empty string.
func assertObligationState(t *testing.T, h *testHarness, txID string, wantState, wantOutcome string) {
	t.Helper()
	ob := mustObligationView(t, h, txID)
	if ob.State != wantState {
		t.Errorf("state = %q, want %q", ob.State, wantState)
	}
	gotOutcome := ""
	if ob.ValidationOutcome != nil {
		gotOutcome = *ob.ValidationOutcome
	}
	if gotOutcome != wantOutcome {
		t.Errorf("validation_outcome = %q, want %q", gotOutcome, wantOutcome)
	}
	if wantOutcome != "" && ob.ValidatedAt == nil {
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

// adminAuditActions are the actions the ADMIN plane writes. The audit log is
// control-plane wide, not admin-only: agent registration appends a row too, and
// the shared harness registers an agent while it is being built. An admin
// assertion that counted every row for the tenant would therefore count that one
// as well, so every admin count below names the actions it means.
var adminAuditActions = map[string]bool{
	"SetTenantFeeRate":      true,
	"SetReportingPolicy":    true,
	"SetDefaultAgentCredit": true,
}

// readAuditRows returns the ADMIN audit rows for tenantID through the production
// repository surface (tier-2 fallback — no public audit read RPC). tenantID is an
// explicit parameter so a negative test can read a MISSING tenant. Fatal on read error.
func readAuditRows(t *testing.T, h *testHarness, tenantID string) []repo.AuditRecord {
	t.Helper()
	rows, err := repo.NewAuditRepo(h.queries).ByTenant(h.ctx, tenantID)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	out := make([]repo.AuditRecord, 0, len(rows))
	for _, r := range rows {
		if adminAuditActions[r.Action] {
			out = append(out, r)
		}
	}
	return out
}

// readSingleAuditRow asserts exactly one admin audit row exists for tenantID and
// returns it — the shape both PersistsAndAudits tests expect after their single
// setter appends exactly one row.
func readSingleAuditRow(t *testing.T, h *testHarness, tenantID string) repo.AuditRecord {
	t.Helper()
	rows := readAuditRows(t, h, tenantID)
	if len(rows) != 1 {
		t.Fatalf("admin audit rows = %d, want 1", len(rows))
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
		t.Errorf("admin audit rows = %d, want 0", len(rows))
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

// assertWireViolation fails unless err carries the buf.validate.Violations
// detail the validate interceptor attaches, with a violation on fieldPath under
// ruleID. It is what tells a wire-tier refusal apart from every later gate: all
// of them answer InvalidArgument, and only the interceptor attaches this detail,
// so a test that read the code alone would keep passing while a cap quietly
// moved from the wire to a gate further in.
func assertWireViolation(t *testing.T, err error, fieldPath, ruleID string) {
	t.Helper()
	violations := testutil.ValidationViolations(t, err)
	for _, v := range violations {
		if testutil.ViolationFieldPath(v) == fieldPath && v.GetRuleId() == ruleID {
			return
		}
	}
	t.Fatalf("no wire violation on %s under %s; %d violation(s) attached (err=%v)",
		fieldPath, ruleID, len(violations), err)
}

// assertLogContains fails the test for every substring the captured audit log
// does not carry, and prints the whole log once so a missing line is diagnosed
// from one failure rather than from a re-run.
//
// The report-outcome suites all assert their audit lines this way. Left as a
// loop per test, the next one copies whichever version is nearest — and the
// copies had already drifted on where logs.String() was evaluated.
func assertLogContains(t *testing.T, logs *safeBuffer, wants ...string) {
	t.Helper()
	got := logs.String()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("audit log missing %s; got: %s", want, got)
		}
	}
}
