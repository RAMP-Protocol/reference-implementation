package proto_test

// Structural guard for the items-only collapse:
// the canonical proto must define exactly ONE purchase shape — items[]-only.
//
// This is the documented structural-disease exception to the
// integration/E2E-by-default rule: C5 removes NON-behavioral wire fields from
// the canonical proto and re-pins the platform's go.mod, with NO runtime-
// observable behavior change (earlier slices already removed every consumer of these
// fields). The red artifact that pins the C5 outcome is therefore a structural
// guard over the GENERATED descriptors of the pinned proto module — pure
// protoreflect, no build tag, no infra.
//
// RED on HEAD: the platform pins github.com/RAMP-Protocol/protocol @ b51490b,
// whose TransactionRequest STILL declares offer=8 / agent_acceptance=9 and
// whose TransactionResponse STILL declares the single-mode top-level result
// fields. ByName therefore returns non-nil descriptors and the absence
// assertions FAIL. After C5 deletes those fields from the canonical proto,
// regenerates, and re-pins, ByName returns nil for each → GREEN.

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// removedTransactionRequestFields are the single-offer top-level fields that
// C5 deletes from TransactionRequest (the per-item shape now lives only in
// TransactionItem).
var removedTransactionRequestFields = []protoreflect.Name{
	"offer",
	"agent_acceptance",
}

// removedTransactionResponseFields are the single-mode top-level result fields
// that C5 deletes from TransactionResponse (the per-result data now lives only
// in TransactionResultItem).
var removedTransactionResponseFields = []protoreflect.Name{
	"transaction_id",
	"billing_id",
	"resource_title",
	"cost",
	"delivery_method",
	"reporting_obligation",
	"expires_at",
	"retrieval_endpoint",
	"subscription_id",
	"subscription_unit_value",
}

// keptTransactionRequestFields guard against over-deletion: the items-only
// purchase shape must still carry items[].
var keptTransactionRequestFields = []protoreflect.Name{
	"items",
}

// keptTransactionResponseFields guard against over-deletion: the shared header
// + items[] + aggregates must survive.
var keptTransactionResponseFields = []protoreflect.Name{
	"items",
	"agent_identity_hash",
	"total_cost",
}

func TestTransactionRequestHasNoSingleOfferFields(t *testing.T) {
	t.Parallel()

	fields := (&rampv1.TransactionRequest{}).ProtoReflect().Descriptor().Fields()
	for _, name := range removedTransactionRequestFields {
		if fd := fields.ByName(name); fd != nil {
			t.Errorf("TransactionRequest must NOT declare field %q (single-offer mode removed in C5), but it is still present (number %d)", name, fd.Number())
		}
	}
}

func TestTransactionResponseHasNoSingleModeResultFields(t *testing.T) {
	t.Parallel()

	fields := (&rampv1.TransactionResponse{}).ProtoReflect().Descriptor().Fields()
	for _, name := range removedTransactionResponseFields {
		if fd := fields.ByName(name); fd != nil {
			t.Errorf("TransactionResponse must NOT declare top-level field %q (single-mode result fields removed in C5; per-result data lives in TransactionResultItem), but it is still present (number %d)", name, fd.Number())
		}
	}
}

func TestItemsOnlyShapeRetainsKeptFields(t *testing.T) {
	t.Parallel()

	reqFields := (&rampv1.TransactionRequest{}).ProtoReflect().Descriptor().Fields()
	for _, name := range keptTransactionRequestFields {
		if fd := reqFields.ByName(name); fd == nil {
			t.Errorf("TransactionRequest must still declare field %q after the items-only collapse (over-deletion guard)", name)
		}
	}

	respFields := (&rampv1.TransactionResponse{}).ProtoReflect().Descriptor().Fields()
	for _, name := range keptTransactionResponseFields {
		if fd := respFields.ByName(name); fd == nil {
			t.Errorf("TransactionResponse must still declare field %q after the items-only collapse (over-deletion guard)", name)
		}
	}
}
