package service

import (
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

var (
	epoch          = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	defaultNow     = epoch.Add(time.Hour)
	exchangeDomain = "exchange.ramp.test"
)

func baseObligation() repo.Obligation {
	return repo.Obligation{
		ID:                "ob-1",
		TransactionID:     "tx-1",
		State:             repo.ObligationStatePending,
		WindowSeconds:     86_400,
		Deadline:          epoch.Add(24 * time.Hour),
		EstimatedQuantity: 100,
		QuantityTolerance: defaultQuantityTolerance,
	}
}

func baseInput() ReportInput {
	return ReportInput{
		Obligation:    baseObligation(),
		TransactionID: "tx-1",
		BillingID:     "bill-abc",
		CreatedAt:     epoch,
		Report: &rampv1.UsageReport{
			Ver:            helpers.ProtocolVersion,
			IdempotencyKey: "r-1",
			TransactionId:  "tx-1",
			BillingId:      "bill-abc",
			Usage:          &rampv1.Usage{ConsumedQuantity: 100},
		},
		Now: defaultNow,
	}
}

// TestReportValidator_TableDriven covers every protocol check in a single
// table-driven function. Each row mutates a fresh
// baseInput() and asserts the outcome + (for failures) the connect-mapped
// code so the boundary contract is pinned too.
func TestReportValidator_TableDriven(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*ReportInput)
		wantOutcome repo.ValidationOutcome
		wantKind    exchange.Kind
		wantInMsg   string
	}{
		{
			name:        "AllPass",
			mutate:      func(_ *ReportInput) {},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		// ---- Required fields -------------------------------------------------
		{
			name: "RequiredField_FirstMissing",
			mutate: func(in *ReportInput) {
				in.Obligation.RequiredFields = []string{"billing_id", "function"}
				in.Report.BillingId = ""
			},
			wantOutcome: repo.ValidationOutcomeRejectedFields,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "billing_id",
		},
		{
			name: "RequiredField_SecondMissing",
			mutate: func(in *ReportInput) {
				in.Obligation.RequiredFields = []string{"billing_id", "function"}
				// billing_id present; function absent → second-row failure
			},
			wantOutcome: repo.ValidationOutcomeRejectedFields,
			wantInMsg:   "function",
		},
		{
			name: "RequiredField_UnknownName_FailsClosed",
			mutate: func(in *ReportInput) {
				in.Obligation.RequiredFields = []string{"billingId"} // typo
			},
			wantOutcome: repo.ValidationOutcomeRejectedFields,
			wantInMsg:   "billingId",
		},
		{
			name: "RequiredField_MissingUsage",
			mutate: func(in *ReportInput) {
				in.Obligation.RequiredFields = []string{"consumed_quantity"}
				in.Report.Usage = nil
			},
			wantOutcome: repo.ValidationOutcomeRejectedFields,
			wantInMsg:   "consumed_quantity",
		},
		// ---- Window: no longer a check ---------------------------------------
		// A report is accepted whatever the time. Rejecting a late one left the
		// obligation PENDING, and a PENDING obligation past its deadline is what
		// the execute gate refuses on, so a missed window locked the agent out
		// with no way back. These two rows are the regression guard: if a window
		// check is ever reintroduced here, both fail.
		{
			name: "Window_LongPastDeadline_Accepted",
			mutate: func(in *ReportInput) {
				in.Now = in.Obligation.Deadline.Add(30 * 24 * time.Hour)
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Window_OneSecondPastDeadline_Accepted",
			mutate: func(in *ReportInput) {
				in.Now = in.Obligation.Deadline.Add(time.Second)
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		// ---- Tolerance -------------------------------------------------------
		{
			name: "Tolerance_BoundaryPlus20",
			mutate: func(in *ReportInput) {
				in.Report.Usage.ConsumedQuantity = 120
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Tolerance_BoundaryMinus20",
			mutate: func(in *ReportInput) {
				in.Report.Usage.ConsumedQuantity = 80
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Tolerance_PlusTwentyOne_Rejected",
			mutate: func(in *ReportInput) {
				in.Report.Usage.ConsumedQuantity = 121
			},
			wantOutcome: repo.ValidationOutcomeRejectedTolerance,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "outside",
		},
		{
			name: "Tolerance_Negative_Rejected",
			mutate: func(in *ReportInput) {
				in.Report.Usage.ConsumedQuantity = -1
			},
			wantOutcome: repo.ValidationOutcomeRejectedTolerance,
			wantInMsg:   "negative",
		},
		{
			name: "Tolerance_ZeroEstimate_NonZeroConsumed_Rejected",
			mutate: func(in *ReportInput) {
				in.Obligation.EstimatedQuantity = 0
				in.Report.Usage.ConsumedQuantity = 1
			},
			wantOutcome: repo.ValidationOutcomeRejectedTolerance,
			wantInMsg:   "zero-estimate",
		},
		{
			name: "Tolerance_ZeroEstimate_ZeroConsumed_Pass",
			mutate: func(in *ReportInput) {
				in.Obligation.EstimatedQuantity = 0
				in.Report.Usage.ConsumedQuantity = 0
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			// A stamped tolerance of 0 is an explicit exact-match policy, not
			// "unset" — planObligation resolves a nil policy to the default
			// before persisting, so 0 on the obligation is always deliberate. An
			// exact report passes. (The ±20% default band is covered by the
			// Tolerance_Boundary* cases, whose obligation carries the default.)
			name: "Tolerance_ExactZero_ExactMatch_Passes",
			mutate: func(in *ReportInput) {
				in.Obligation.QuantityTolerance = 0
				in.Report.Usage.ConsumedQuantity = 100
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			// Exact-match tolerance rejects any deviation, however small — the
			// behaviour the ±20% default silently swallowed before the fix.
			name: "Tolerance_ExactZero_OffByOne_Rejected",
			mutate: func(in *ReportInput) {
				in.Obligation.QuantityTolerance = 0
				in.Report.Usage.ConsumedQuantity = 101
			},
			wantOutcome: repo.ValidationOutcomeRejectedTolerance,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "outside",
		},
		// ---- Billing ID ------------------------------------------------------
		{
			name: "BillingID_Mismatch",
			mutate: func(in *ReportInput) {
				in.Report.BillingId = "wrong-billing"
			},
			wantOutcome: repo.ValidationOutcomeRejectedBillingID,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "billing_id",
		},
		{
			name: "BillingID_EmptyTx_NonEmptyReport_Rejected",
			mutate: func(in *ReportInput) {
				// Free-tier tx: the stored billing_id is empty. A report naming a
				// non-empty handle is a reservation absent from this Exchange's
				// transaction log — a forged handle rejected per threat model T25.
				in.BillingID = ""
				in.Report.BillingId = "anything"
			},
			wantOutcome: repo.ValidationOutcomeRejectedBillingID,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "billing_id",
		},
		{
			name: "BillingID_EmptyTx_EmptyReport_Validated",
			mutate: func(in *ReportInput) {
				// Free-tier tx with a conformant report that carries no billing_id:
				// empty == empty compares equal, so the report validates.
				in.BillingID = ""
				in.Report.BillingId = ""
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		// ---- Timestamp (L6 remainder) ---------------------------------------
		{
			name: "Timestamp_Unset_Pass",
			mutate: func(in *ReportInput) {
				in.Report.Timestamp = nil
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Timestamp_AtNow_Pass",
			mutate: func(in *ReportInput) {
				in.Report.Timestamp = timestamppb.New(in.Now)
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Timestamp_FarFuture_Rejected",
			mutate: func(in *ReportInput) {
				in.Report.Timestamp = timestamppb.New(in.Now.Add(10 * time.Minute))
			},
			wantOutcome: repo.ValidationOutcomeRejectedTimestamp,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "future",
		},
		{
			name: "Timestamp_BeforeTransaction_Rejected",
			mutate: func(in *ReportInput) {
				in.Report.Timestamp = timestamppb.New(in.CreatedAt.Add(-time.Hour))
			},
			wantOutcome: repo.ValidationOutcomeRejectedTimestamp,
			wantInMsg:   "precedes",
		},
		// The recipient the report names is NOT checked here. It is decided by
		// the interceptor on the Connect surface, before this validator's
		// obligation is loaded, and is covered through the ReportUsage RPC in
		// the transport package's recipient tests.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mutate(&in)
			out, err := ValidateUsageReport(in)
			if tc.wantOutcome == repo.ValidationOutcomeValidated {
				if err != nil {
					t.Fatalf("expected pass, got error: %v", err)
				}
				if out != tc.wantOutcome {
					t.Fatalf("outcome = %q, want %q", out, tc.wantOutcome)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected failure with outcome %q, got pass", tc.wantOutcome)
			}
			if out != tc.wantOutcome {
				t.Fatalf("outcome = %q, want %q", out, tc.wantOutcome)
			}
			if tc.wantKind != exchange.KindUnspecified && err.Kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", err.Kind, tc.wantKind)
			}
			if tc.wantInMsg != "" && !contains(err.Message, tc.wantInMsg) {
				t.Fatalf("message %q does not contain %q", err.Message, tc.wantInMsg)
			}
			// The offending field identity now rides structured metadata
			// (ErrorDetail.metadata["field"] at the boundary), never the
			// non-authoritative Message string. Every rejection records it.
			if got := err.Metadata["field"]; got == "" {
				t.Fatalf("rejection %q recorded no field metadata", tc.name)
			}
		})
	}
}

// TestReportHasFieldCoversKnownFields pins knownReportFields and reportHasField
// in lockstep. Every canonical field name must have a real presence case rather
// than fall through to the fail-closed default; an unknown name must be rejected;
// and ValidateRequiredFieldNames must agree with the same set. Adding a name to
// one without the other breaks this test.
func TestReportHasFieldCoversKnownFields(t *testing.T) {
	full := &rampv1.UsageReport{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: "r-1",
		TransactionId:  "tx-1",
		BillingId:      "bill-1",
		Exchange:       exchangeDomain,
		Timestamp:      timestamppb.New(epoch),
		Usage:          &rampv1.Usage{ConsumedQuantity: 1, Function: []string{"summarize"}},
	}
	for name := range knownReportFields {
		if !reportHasField(full, name) {
			t.Errorf("known field %q not recognized by reportHasField (missing switch case?)", name)
		}
	}
	if reportHasField(full, "not_a_real_field") {
		t.Error("unknown field name must never be reported present")
	}
	if err := ValidateRequiredFieldNames([]string{"billing_id", "timestamp", "id"}); err != nil {
		t.Errorf("known names rejected: %v", err)
	}
	err := ValidateRequiredFieldNames([]string{"billing_id", "bogus"})
	if err == nil {
		t.Fatal("unknown name accepted")
	}
	if err.Kind != exchange.KindInvalidRequest {
		t.Errorf("kind = %v, want KindInvalidRequest", err.Kind)
	}
	if !contains(err.Message, "bogus") {
		t.Errorf("message %q does not name the offending token", err.Message)
	}
}

func BenchmarkReportValidator_Validate(b *testing.B) {
	in := baseInput()
	var outcome repo.ValidationOutcome
	b.ResetTimer()
	for range b.N {
		outcome, _ = ValidateUsageReport(in)
	}
	_ = outcome
}

// contains is a tiny strings.Contains shim so the test file does not import
// the strings package just for one call site. Trivial; constant cost.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
