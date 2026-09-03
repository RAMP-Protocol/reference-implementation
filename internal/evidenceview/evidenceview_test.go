package evidenceview_test

// Unit tests: this package is the parse/serialize boundary between the
// Exchange's evidence handler and the ramp-ledger renderer, which the testing
// doctrine admits as a unit-test category. Field drift is already a compile
// error because both sides share one declaration, so what is left to guard is
// what the compiler cannot see — the wire names, base64 on the byte fields,
// RFC 3339 on the timestamps, the optional fields actually disappearing when
// absent, and the decimal quantity surviving a fractional value.

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
)

func ptr[T any](v T) *T { return &v }

// createdAt and the other anchors carry no sub-second part, so the encoded form
// is plain RFC 3339 and the assertions can compare it as a literal string.
var (
	createdAt = time.Date(2026, 8, 16, 12, 34, 56, 0, time.UTC)
	expiry    = time.Date(2026, 8, 16, 13, 4, 56, 0, time.UTC)
	windowEnd = time.Date(2026, 8, 23, 12, 34, 56, 0, time.UTC)
	fulfilled = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)
	validated = time.Date(2026, 8, 17, 9, 0, 1, 0, time.UTC)
)

// full is a payload with every optional field present.
func full() *evidenceview.Response {
	return &evidenceview.Response{
		Evidence: &evidenceview.Evidence{
			TransactionID:                     "tx-1",
			TenantID:                          "tenant-1",
			OfferID:                           "offer-1",
			CreatedAt:                         createdAt,
			OfferSig:                          "a1b2",
			OfferSigAlgorithm:                 "ed25519",
			OfferCanonicalBytes:               []byte{0x01, 0x02, 0x03},
			ExchangeSigningPublicKey:          []byte{0x04, 0x05, 0x06},
			AgentAcceptanceSignature:          "c3d4",
			AgentAcceptanceSignatureAlgorithm: "ed25519",
			AgentAcceptanceCanonicalBytes:     []byte{0x07, 0x08, 0x09},
			AgentPublicKey:                    []byte{0x0a, 0x0b, 0x0c},
			RequesterID:                       "https://agents.example/agent",
			RequesterDomain:                   "agents.example",
			RequestIdempotencyKey:             "idem-1",
			RequestID:                         ptr("req-1"),
			RequestIDMinted:                   ptr(true),
		},
		TransactionState: &evidenceview.TransactionState{
			IdempotencyKey:  "idem-1:offer-1",
			SignedURLHash:   []byte{0x0d, 0x0e, 0x0f},
			SignedURLExpiry: &expiry,
		},
		ObligationState: &evidenceview.ObligationState{
			State:             "PENDING",
			ConsumedQuantity:  ptr("12.34500000"),
			WindowEnd:         windowEnd,
			FulfilledAt:       &fulfilled,
			CreatedAt:         createdAt,
			ValidationOutcome: ptr("REJECTED_FIELDS"),
			ValidatedAt:       &validated,
		},
	}
}

func TestRoundTripPreservesEveryField(t *testing.T) {
	t.Parallel()

	want := full()
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got evidenceview.Response
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate on a complete payload: %v", err)
	}
	if !reflect.DeepEqual(want, &got) {
		t.Errorf("round trip changed the value:\n got %+v\nwant %+v", got, *want)
	}
}

func TestEncodingIsBase64BytesAndRFC3339Timestamps(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(full())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := string(raw)

	// The byte fields are base64 of the exact bytes above, not hex and not a
	// JSON array of numbers.
	for field, want := range map[string]string{
		"offer_canonical_bytes":            `"AQID"`,
		"exchange_signing_public_key":      `"BAUG"`,
		"agent_acceptance_canonical_bytes": `"BwgJ"`,
		"agent_public_key":                 `"CgsM"`,
		"signed_url_hash":                  `"DQ4P"`,
	} {
		assertContains(t, encoded, `"`+field+`":`+want)
	}

	for field, want := range map[string]string{
		"created_at":        `"2026-08-16T12:34:56Z"`,
		"signed_url_expiry": `"2026-08-16T13:04:56Z"`,
		"window_end":        `"2026-08-23T12:34:56Z"`,
		"fulfilled_at":      `"2026-08-17T09:00:00Z"`,
		"validated_at":      `"2026-08-17T09:00:01Z"`,
	} {
		assertContains(t, encoded, `"`+field+`":`+want)
	}

	// The outcome crosses the wire as the persisted vocabulary verbatim, like
	// State: an operator settling a dispute reads the word the row holds.
	assertContains(t, encoded, `"validation_outcome":"REJECTED_FIELDS"`)
}

func TestConsumedQuantityKeepsItsFraction(t *testing.T) {
	t.Parallel()

	// The column is NUMERIC(20,8). A fractional value must arrive intact: an
	// integer conversion here would report 12 units consumed against a stored
	// 12.345, which is a wrong number on a surface used to settle disputes.
	raw, err := json.Marshal(full())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertContains(t, string(raw), `"consumed_quantity":"12.34500000"`)

	var got evidenceview.Response
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if q := got.ObligationState.ConsumedQuantity; q == nil || *q != "12.34500000" {
		t.Errorf("consumed_quantity = %v, want 12.34500000", q)
	}
}

func TestAbsentOptionalFieldsAreOmitted(t *testing.T) {
	t.Parallel()

	minimal := &evidenceview.Response{
		Evidence: &evidenceview.Evidence{
			TransactionID: "tx-1",
			CreatedAt:     createdAt,
		},
		TransactionState: &evidenceview.TransactionState{IdempotencyKey: "idem-1:offer-1"},
	}
	raw, err := json.Marshal(minimal)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	encoded := string(raw)

	// Absent means the key is gone, so a reader can tell "not recorded" from a
	// recorded zero, an empty digest or the year-one timestamp.
	for _, field := range []string{
		"obligation_state", "request_id", "request_id_minted",
		"signed_url_hash", "signed_url_expiry",
		"validation_outcome", "validated_at",
	} {
		if strings.Contains(encoded, `"`+field+`"`) {
			t.Errorf("expected %q to be omitted, got %s", field, encoded)
		}
	}

	var got evidenceview.Response
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("Validate on a payload with only the required objects: %v", err)
	}
	if got.ObligationState != nil {
		t.Errorf("obligation_state decoded to %+v, want nil", got.ObligationState)
	}
}

func TestValidateAcceptsAnAbsentObligation(t *testing.T) {
	t.Parallel()

	// A payload with everything populated except the obligation. The execute
	// path reaches this: a term whose pricing carries PRICING_METERING_NONE
	// mints no obligation, so a transaction against it omits the object. A
	// free-path transaction still mints one. A reader must accept the absence
	// instead of failing or inventing a duty.
	noObligation := full()
	noObligation.ObligationState = nil

	raw, err := json.Marshal(noObligation)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got evidenceview.Response
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("Validate on a complete payload with no obligation: %v", err)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	// The two required objects, with every field Validate looks at present.
	const (
		evidenceObj = `"evidence":{"transaction_id":"tx-1","created_at":"2026-08-16T12:34:56Z"}`
		txStateObj  = `"transaction_state":{"idempotency_key":"idem-1:offer-1"}`
	)

	cases := []struct {
		name    string
		payload string
		wantErr error
	}{
		{
			name:    "missing evidence is rejected",
			payload: `{` + txStateObj + `}`,
			wantErr: evidenceview.ErrMissingEvidence,
		},
		{
			name:    "missing transaction_state is rejected",
			payload: `{` + evidenceObj + `}`,
			wantErr: evidenceview.ErrMissingTransactionState,
		},
		{
			name:    "missing evidence created_at is rejected",
			payload: `{"evidence":{"transaction_id":"tx-1"},` + txStateObj + `}`,
			wantErr: evidenceview.ErrMissingEvidenceCreatedAt,
		},
		{
			name: "missing obligation window_end is rejected",
			payload: `{` + evidenceObj + `,` + txStateObj + `,` +
				`"obligation_state":{"state":"PENDING","created_at":"2026-08-16T12:34:56Z"}}`,
			wantErr: evidenceview.ErrMissingObligationWindowEnd,
		},
		{
			name: "missing obligation created_at is rejected",
			payload: `{` + evidenceObj + `,` + txStateObj + `,` +
				`"obligation_state":{"state":"PENDING","window_end":"2026-08-23T12:34:56Z"}}`,
			wantErr: evidenceview.ErrMissingObligationCreatedAt,
		},
		{
			name:    "missing obligation_state is accepted",
			payload: `{` + evidenceObj + `,` + txStateObj + `}`,
			wantErr: nil,
		},
		{
			name: "a complete obligation_state is accepted",
			payload: `{` + evidenceObj + `,` + txStateObj + `,` +
				`"obligation_state":{"state":"PENDING","window_end":"2026-08-23T12:34:56Z",` +
				`"created_at":"2026-08-16T12:34:56Z"}}`,
			wantErr: nil,
		},
		{
			// An outcome without an instant says a report was judged without
			// saying when.
			name:    "an outcome with no validated_at is rejected",
			payload: obligationPayload(`"validation_outcome":"REJECTED_FIELDS"`),
			wantErr: evidenceview.ErrPartialValidationOutcome,
		},
		{
			// An instant without an outcome names a moment without saying what
			// was decided at it.
			name:    "a validated_at with no outcome is rejected",
			payload: obligationPayload(`"validated_at":"2026-08-17T09:00:01Z"`),
			wantErr: evidenceview.ErrPartialValidationOutcome,
		},
		{
			// The zero time renders as year one and reads like a real instant,
			// which is the same defect the created_at check catches.
			name: "a set-but-zero validated_at is rejected",
			payload: obligationPayload(`"validation_outcome":"REJECTED_FIELDS",` +
				`"validated_at":"0001-01-01T00:00:00Z"`),
			wantErr: evidenceview.ErrMissingObligationValidatedAt,
		},
		{
			name: "both outcome fields present is accepted",
			payload: obligationPayload(`"validation_outcome":"VALIDATED",` +
				`"validated_at":"2026-08-17T09:00:01Z"`),
			wantErr: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got evidenceview.Response
			if err := json.Unmarshal([]byte(tc.payload), &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := got.Validate(); !errors.Is(err, tc.wantErr) {
				t.Errorf("Validate() = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// obligationPayload builds a Validate payload whose obligation carries the two
// required timestamps plus the extra members given, so each outcome case states
// only what it varies.
func obligationPayload(extra string) string {
	return `{"evidence":{"transaction_id":"tx-1","created_at":"2026-08-16T12:34:56Z"},` +
		`"transaction_state":{"idempotency_key":"idem-1:offer-1"},` +
		`"obligation_state":{"state":"PENDING","window_end":"2026-08-23T12:34:56Z",` +
		`"created_at":"2026-08-16T12:34:56Z",` + extra + `}}`
}

func assertContains(t *testing.T, encoded, want string) {
	t.Helper()
	if !strings.Contains(encoded, want) {
		t.Errorf("encoded payload is missing %s\ngot %s", want, encoded)
	}
}
