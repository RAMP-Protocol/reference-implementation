package transport

import (
	"errors"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

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
// WHY THIS SEAM AND NOT THE PUBLIC RPC: after the items-only collapse a
// denial-map Kind always surfaces as an in-body per-item denial
// (service batchDenialResult); service.ExecuteTransaction never returns a
// denial-kind error, so executeTxError's typed-denial branch cannot be driven
// through the Connect surface. This function IS the outermost surface that owns
// the branch, so the wire-shape pin lives here (in-package, like the
// broker_error_detail_guard); if a future protocol change reintroduces
// envelope-level denials, this contract transfers to the RPC surface unchanged.
func TestExecuteTxError_DenialDetailCarriesNoMetadata(t *testing.T) {
	t.Parallel() // pure error-mapping check — no shared DB.

	// A denial-map kind (INSUFFICIENT_BALANCE) that ALSO carries field metadata:
	// the strongest input for the absence assertion — the builder must not let
	// the metadata ride onto the typed-denial detail.
	src := exchange.Newf(exchange.KindBillingDenied, "billing denied").WithField("offer_id")
	if len(src.Metadata) == 0 {
		t.Fatal("test setup: source error must carry metadata for the absence check to bite")
	}

	err := executeTxError(src)

	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("executeTxError returned %T, want *connect.Error", err)
	}
	detail := singleErrorDetail(t, ce)
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

	err := executeTxError(src)

	var ce *connect.Error
	if !errors.As(err, &ce) {
		t.Fatalf("executeTxError returned %T, want *connect.Error", err)
	}
	detail := singleErrorDetail(t, ce)
	if detail.GetTransactionDenial() != nil {
		t.Error("non-denial fault must not carry a TransactionDenial reason")
	}
	if got := detail.GetMetadata()["field"]; got != "idempotency_key" {
		t.Errorf("metadata[field] = %q, want idempotency_key (generic path rides metadata)", got)
	}
}

// singleErrorDetail decodes the exactly-one rampv1.ErrorDetail attached to ce.
func singleErrorDetail(t *testing.T, ce *connect.Error) *rampv1.ErrorDetail {
	t.Helper()
	var found *rampv1.ErrorDetail
	for _, d := range ce.Details() {
		msg, verr := d.Value()
		if verr != nil {
			continue
		}
		ed, ok := msg.(*rampv1.ErrorDetail)
		if !ok {
			continue
		}
		if found != nil {
			t.Fatal("more than one ErrorDetail attached; the envelope must be built exactly once")
		}
		found = ed
	}
	if found == nil {
		t.Fatalf("no rampv1.ErrorDetail attached to error: %v", ce)
	}
	return found
}
