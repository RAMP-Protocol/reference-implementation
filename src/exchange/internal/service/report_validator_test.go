package service

import (
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
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
			Id:            "r-1",
			TransactionId: "tx-1",
			BillingId:     "bill-abc",
			Usage:         &rampv1.Usage{ConsumedQuantity: 100},
		},
		Now:      defaultNow,
		Exchange: exchangeDomain,
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
		// ---- Window ----------------------------------------------------------
		{
			name: "Window_Expired",
			mutate: func(in *ReportInput) {
				in.Now = in.Obligation.Deadline.Add(time.Second)
			},
			wantOutcome: repo.ValidationOutcomeRejectedWindow,
			wantKind:    exchange.KindFailedPrecondition,
			wantInMsg:   "window",
		},
		{
			name: "Window_AtBoundary",
			mutate: func(in *ReportInput) {
				in.Now = in.Obligation.Deadline
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Window_NoDeadlinePersisted",
			mutate: func(in *ReportInput) {
				in.Obligation.Deadline = time.Time{}
				in.Now = epoch.Add(48 * time.Hour) // would fail if deadline was set
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
			name: "Tolerance_DefaultWhenObligationUnset",
			mutate: func(in *ReportInput) {
				// No persisted tolerance → defaultQuantityTolerance kicks in.
				in.Obligation.QuantityTolerance = 0
				in.Report.Usage.ConsumedQuantity = 120
			},
			wantOutcome: repo.ValidationOutcomeValidated,
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
			name: "BillingID_EmptyTx_Skip",
			mutate: func(in *ReportInput) {
				in.BillingID = ""
				in.Report.BillingId = "anything"
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
		// ---- Exchange (L6 remainder) -------------------------------------
		{
			name: "Exchange_Unset_Pass",
			mutate: func(in *ReportInput) {
				in.Report.Exchange = nil
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Exchange_Match_Pass",
			mutate: func(in *ReportInput) {
				m := exchangeDomain
				in.Report.Exchange = &m
			},
			wantOutcome: repo.ValidationOutcomeValidated,
		},
		{
			name: "Exchange_Mismatch_Rejected",
			mutate: func(in *ReportInput) {
				m := "evil.example"
				in.Report.Exchange = &m
			},
			wantOutcome: repo.ValidationOutcomeRejectedExchange,
			wantKind:    exchange.KindInvalidRequest,
			wantInMsg:   "exchange",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := baseInput()
			tc.mutate(&in)
			out, err := Validate(in)
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
		})
	}
}

func BenchmarkReportValidator_Validate(b *testing.B) {
	in := baseInput()
	var outcome repo.ValidationOutcome
	b.ResetTimer()
	for range b.N {
		outcome, _ = Validate(in)
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
