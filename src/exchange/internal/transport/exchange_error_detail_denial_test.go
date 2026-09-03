package transport

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// TestExecuteTxError_DenialDetailCarriesNoMetadata pins the typed-denial wire
// shape: the ErrorDetail attached to a transaction denial carries the
// TransactionDenial reason oneof, the exchange Domain, and the non-authoritative
// Message — and deliberately NO metadata, even when the underlying
// exchange.Error recorded structured field metadata. The generic (no-reason)
// fault path rides metadata (genericFaultError → exchangeMeta); the denial path
// does not — the machine-readable denial payload is the typed reason, and field
// metadata must not start riding along when the envelope build is consolidated
// onto the shared SDK builder.
//
// WHY THIS SEAM AND NOT THE PUBLIC RPC: the branch has NO reachable surface.
// batchDenialResult and txDenialReason both ask the same
// service.DenialReasonForKind, so every error whose kind maps to a denial is
// folded into an in-body per-item TransactionResultItem and never returned;
// service.ExecuteTransaction cannot hand executeTxError a denial-kind error at
// all. This test is therefore a wire-shape pin on code no client reaches today,
// kept in-package (like the broker_error_detail_guard) against the protocol
// change that would make the branch live — a per-item exchange field on
// TransactionResultItem. When that lands, this contract transfers to the RPC
// surface unchanged.
func TestExecuteTxError_DenialDetailCarriesNoMetadata(t *testing.T) {
	t.Parallel() // pure error-mapping check — no shared DB.

	// A denial-map kind (INSUFFICIENT_BALANCE) that ALSO carries field metadata:
	// the strongest input for the absence assertion — the builder must not let
	// the metadata ride onto the typed-denial detail.
	src := exchange.Newf(exchange.KindBillingDenied, "billing denied").WithField("offer_id")
	if len(src.Metadata) == 0 {
		t.Fatal("test setup: source error must carry metadata for the absence check to bite")
	}

	err := executeTxError(src, testExchangeHost)

	detail := testutil.SingleErrorDetail(t, err)
	if got := detail.GetTransactionDenial().GetReason(); got != rampv1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Errorf("denial reason = %v, want DENIAL_REASON_INSUFFICIENT_BALANCE", got)
	}
	if got := detail.GetDomain(); got != exchangeServiceDomain {
		t.Errorf("ErrorDetail.Domain = %q, want %q", got, exchangeServiceDomain)
	}
	if detail.GetMessage() == "" {
		t.Error("ErrorDetail.Message must carry the non-authoritative developer message")
	}
	if md := detail.GetMetadata(); len(md) > 0 {
		t.Errorf("denial ErrorDetail must carry NO metadata (typed reason only), got %v", md)
	}
	if got := detail.GetTransactionDenial().GetExchange(); got != testExchangeHost {
		t.Errorf("TransactionDenial.exchange = %q, want %q — a client holding offers from "+
			"several Exchanges cannot tell which one refused unless the denial names it",
			got, testExchangeHost)
	}
}

// testExchangeHost stands in for the deployment's published identity, which
// production reads from ExchangeService.ExchangeDomain.
const testExchangeHost = "exchange.example"

// TestExecuteTxError_DenialNamesEachDistinctReason walks the denial reasons the
// execute path splits and checks that each keeps its own reason AND names this
// Exchange. Three today: an agent that never registered, a registered account the
// operator has not activated, and an agent far enough behind on usage reports.
// Each tells the agent to do something different — call Register, wait for the
// operator, file the missing reports — so a denial that collapsed any two of them
// would send those callers to the wrong remedy.
func TestExecuteTxError_DenialNamesEachDistinctReason(t *testing.T) {
	t.Parallel() // pure error-mapping check — no shared DB.

	cases := []struct {
		name string
		kind exchange.Kind
		want rampv1.DenialReason
	}{
		{
			"never registered",
			exchange.KindAccountNotRegistered,
			rampv1.DenialReason_DENIAL_REASON_ACCOUNT_NOT_REGISTERED,
		},
		{
			"registered but not activated",
			exchange.KindAccountInactive,
			rampv1.DenialReason_DENIAL_REASON_ACCOUNT_INACTIVE,
		},
		{
			// The reporting-overdue refusal is a denial like the account pair
			// above, and for the same reason: the agent is being told what to do
			// next, which here is to file the reports it owes. Before it carried
			// a reason it was an unclassifiable error, so a multi-item request
			// from a behind-on-reports agent lost every item instead of the
			// affected ones.
			"behind on usage reports",
			exchange.KindReportingOverdue,
			rampv1.DenialReason_DENIAL_REASON_REPORTING_OVERDUE,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := executeTxError(exchange.Newf(tc.kind, "refused"), testExchangeHost)

			denial := testutil.SingleErrorDetail(t, err).GetTransactionDenial()
			if got := denial.GetReason(); got != tc.want {
				t.Errorf("denial reason = %v, want %v", got, tc.want)
			}
			if got := denial.GetExchange(); got != testExchangeHost {
				t.Errorf("TransactionDenial.exchange = %q, want %q", got, testExchangeHost)
			}
		})
	}
}

// TestExecuteTxError_NonDenialRidesMetadata is the contrast leg: a NON-denial
// kind routes through the generic fault path, where the recorded field metadata
// MUST ride ErrorDetail.metadata (ADR-019 — the offending field identity travels
// machine-readably). Together with the denial leg above it pins the asymmetry
// the consolidation must preserve: generic path rides metadata, denial path
// never does.
func TestExecuteTxError_NonDenialRidesMetadata(t *testing.T) {
	t.Parallel() // pure error-mapping check — no shared DB.

	src := exchange.Newf(exchange.KindInvalidRequest, "idempotency_key required").WithField("idempotency_key")

	err := executeTxError(src, testExchangeHost)

	detail := testutil.SingleErrorDetail(t, err)
	if detail.GetTransactionDenial() != nil {
		t.Error("non-denial fault must not carry a TransactionDenial reason")
	}
	if got := detail.GetMetadata()["field"]; got != "idempotency_key" {
		t.Errorf("metadata[field] = %q, want idempotency_key (generic path rides metadata)", got)
	}
}
