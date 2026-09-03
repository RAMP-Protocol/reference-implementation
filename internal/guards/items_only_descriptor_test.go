package guards

// Structural guard for the items-only collapse:
// the canonical proto must define exactly ONE purchase shape — items[]-only.
//
// This is the documented structural-disease exception to the
// integration/E2E-by-default rule: the single-offer fields were removed from the
// canonical proto with NO runtime-observable behavior change, because every
// consumer of them had already gone. There is no behavior left to drive a test
// through a public surface, so the artifact that pins the outcome is a
// structural guard over the GENERATED descriptors of the pinned proto module —
// pure protoreflect, no build tag, no infra.
//
// The guard is GREEN and has been since the pin that removed those fields: the
// proto module this repo pins declares neither offer=8 / agent_acceptance=9 on
// TransactionRequest nor the single-mode top-level result fields on
// TransactionResponse, so every ByName lookup below returns nil. It is a ratchet
// against their return, not a pending migration. Its counterpart is the
// over-deletion guard at the bottom of this file, which fails if items[] and the
// surviving aggregates are removed along with them.

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// removedTransactionRequestFields are the single-offer top-level fields the
// items-only collapse removed from TransactionRequest (the per-item shape now
// lives only in TransactionItem).
var removedTransactionRequestFields = []protoreflect.Name{
	"offer",
	"agent_acceptance",
}

// removedTransactionResponseFields are the single-mode top-level result fields
// the items-only collapse removed from TransactionResponse (the per-result data
// now lives only in TransactionResultItem).
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
			t.Errorf("TransactionRequest must NOT declare field %q (single-offer mode was removed by the items-only collapse), but it is still present (number %d)", name, fd.Number())
		}
	}
}

func TestTransactionResponseHasNoSingleModeResultFields(t *testing.T) {
	t.Parallel()

	fields := (&rampv1.TransactionResponse{}).ProtoReflect().Descriptor().Fields()
	for _, name := range removedTransactionResponseFields {
		if fd := fields.ByName(name); fd != nil {
			t.Errorf("TransactionResponse must NOT declare top-level field %q (single-mode result fields were removed by the items-only collapse; per-result data lives in TransactionResultItem), but it is still present (number %d)", name, fd.Number())
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
