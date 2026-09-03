package service

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// TestRegistrationDataBounds_AcceptsAPayloadWithinEveryBound pins the pass-through
// case: a payload the SDK accepts produces no error at all, so nothing downstream
// has to distinguish "accepted" from "no verdict".
func TestRegistrationDataBounds_AcceptsAPayloadWithinEveryBound(t *testing.T) {
	t.Parallel()
	payload := map[string]any{
		"company_name":  "Stoa Press",
		"billing_email": "billing@publisher.example",
		"address":       map[string]any{"city": "Harmonia", "country": "XX"},
	}
	if err := registrationDataBounds(testutil.RegistrationStruct(t, payload)); err != nil {
		t.Fatalf("a payload within every bound was refused: %v", err)
	}
}

// TestRegistrationDataBounds_RefusesEachCrossedBound drives a real payload over
// each bound the SDK enforces and checks the refusal the Register gate produces.
//
// Every case asserts the same three things, because all three are contract:
// the refusal is KindInvalidRequest (a MALFORMED REQUEST, so it carries no
// RegistrationFailureReason — INVALID_REGISTRATION_DATA names non-conformance to
// a published schema instead), it names registration_data in structured
// metadata, and its message names the bound that was crossed together with the
// number the SDK enforces.
func TestRegistrationDataBounds_RefusesEachCrossedBound(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		payload map[string]any
		// wants is the number the message must carry, so a test failure says
		// which bound the message described rather than only that it differed.
		wants int
	}{
		{"too many top-level members", testutil.RegistrationOverMemberCap(), helpers.MaxRegistrationDataMembers},
		{"nested too deep", testutil.RegistrationOverDepthCap(), helpers.MaxRegistrationDataDepth},
		{"canonical form too large", testutil.RegistrationOverByteCap(), helpers.MaxRegistrationDataBytes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := registrationDataBounds(testutil.RegistrationStruct(t, tc.payload))
			if err == nil {
				t.Fatal("an over-bound payload was accepted")
			}
			var de *exchange.Error
			if !errors.As(err, &de) {
				t.Fatalf("refusal is not a domain error: %v", err)
			}
			if de.Kind != exchange.KindInvalidRequest {
				t.Errorf("kind is %v, want %v — a bounds violation is a malformed request, "+
					"not a schema failure", de.Kind, exchange.KindInvalidRequest)
			}
			if de.Metadata["field"] != "registration_data" {
				t.Errorf("metadata field is %q, want %q", de.Metadata["field"], "registration_data")
			}
			if !strings.Contains(err.Error(), strconv.Itoa(tc.wants)) {
				t.Errorf("message %q does not name the bound it enforces (%d)", err.Error(), tc.wants)
			}
		})
	}
}

// TestRegistrationDataBounds_RefusesAPayloadWithNoJSONForm drives the class the
// map-based check is blind to. Both values below cross the wire intact and have
// no JSON representation, so the payload has no canonical encoding and therefore
// no measurable size.
//
// The refusal must NOT say "too large". The byte bound is defined as the length
// of the canonical encoding, so for a payload that has no encoding there is no
// number to compare, and reporting one would state a measurement nobody took.
//
// This test is what fails if the check is ever moved back onto the converted map:
// AsMap renders the NaN as the string "NaN" and the untyped value as nil, and a
// map-based check accepts both.
func TestRegistrationDataBounds_RefusesAPayloadWithNoJSONForm(t *testing.T) {
	t.Parallel()
	cases := map[string]*structpb.Struct{
		"a non-finite number":      testutil.RegistrationNonFiniteStruct(),
		"a value with no type set": testutil.RegistrationUntypedValueStruct(),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := registrationDataBounds(payload)
			if err == nil {
				t.Fatal("a payload with no JSON form was accepted")
			}
			var de *exchange.Error
			if !errors.As(err, &de) {
				t.Fatalf("refusal is not a domain error: %v", err)
			}
			if de.Kind != exchange.KindInvalidRequest {
				t.Errorf("kind is %v, want %v — a payload with no JSON form is a "+
					"malformed request, not a schema failure", de.Kind, exchange.KindInvalidRequest)
			}
			if de.Metadata["field"] != "registration_data" {
				t.Errorf("metadata field is %q, want %q", de.Metadata["field"], "registration_data")
			}
			if got := err.Error(); !strings.Contains(got, "no JSON form") {
				t.Errorf("message %q does not name the class it refused", got)
			}
			if got := err.Error(); strings.Contains(got, strconv.Itoa(helpers.MaxRegistrationDataBytes)) {
				t.Errorf("message %q reports the byte cap for a payload that has no "+
					"canonical encoding to measure", got)
			}
		})
	}
}

// TestBoundsMessage_NamesADistinctBoundPerVerdict pins that no two rejecting
// verdicts render the same sentence. A shared message would leave a caller unable
// to tell which bound to shrink, which is the whole reason this mapping exists.
func TestBoundsMessage_NamesADistinctBoundPerVerdict(t *testing.T) {
	t.Parallel()
	verdicts := []helpers.RegistrationDataVerdict{
		helpers.RegistrationDataTooManyMembers,
		helpers.RegistrationDataTooDeep,
		helpers.RegistrationDataTooLarge,
		helpers.RegistrationDataUncanonicalizable,
	}
	seen := make(map[string]helpers.RegistrationDataVerdict, len(verdicts))
	for _, v := range verdicts {
		msg := boundsMessage(v, testutil.RegistrationNonFiniteStruct())
		if msg == "" {
			t.Errorf("verdict %v renders an empty message", v)
			continue
		}
		if prev, dup := seen[msg]; dup {
			t.Errorf("verdicts %v and %v render the same message %q", prev, v, msg)
			continue
		}
		seen[msg] = v
	}
}
