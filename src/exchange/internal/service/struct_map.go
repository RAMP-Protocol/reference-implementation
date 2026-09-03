package service

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"google.golang.org/protobuf/types/known/structpb"
)

// structToMap flattens a registration_data google.protobuf.Struct into the
// map[string]string the SoR adapter consumes (ADR-021 §5 decision 3). The
// conversion happens here at the service layer so the SoR interface stays
// map[string]string and its test set is untouched.
//
// Value handling, one rule per JSON kind:
//   - string  → kept verbatim.
//   - number  → decimal text, shortest form that round-trips, no trailing zeros
//     and no exponent (strconv 'f', precision -1). So 42 renders "42" and 1.5
//     renders "1.5". JSON has one numeric type, so an integer-valued field is
//     indistinguishable from its float form and both render without a decimal
//     point.
//   - bool    → "true" / "false".
//   - null    → omitted entirely (no empty-string sentinel).
//   - object/array → compact JSON text. Registration data is overwhelmingly flat
//     strings; a rare nested value is passed through opaquely rather than
//     deep-flattened, because the SoR maps only the known top-level string keys.
//
// A nil Struct yields an empty, non-nil map (never nil), so the SoR always
// receives a usable value.
func structToMap(s *structpb.Struct) map[string]string {
	fields := s.GetFields()
	out := make(map[string]string, len(fields))
	for k, v := range fields {
		if text, ok := valueToString(v); ok {
			out[k] = text
		}
	}
	return out
}

// valueToString renders one structpb.Value as text. The second return is false
// when the value carries nothing to store (a JSON null), so the caller omits the
// key entirely.
func valueToString(v *structpb.Value) (string, bool) {
	switch kind := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return "", false
	case *structpb.Value_StringValue:
		return kind.StringValue, true
	case *structpb.Value_NumberValue:
		return strconv.FormatFloat(kind.NumberValue, 'f', -1, 64), true
	case *structpb.Value_BoolValue:
		return strconv.FormatBool(kind.BoolValue), true
	case *structpb.Value_StructValue, *structpb.Value_ListValue:
		return nestedJSON(v)
	default:
		return "", false
	}
}

// nestedJSON encodes a nested object or array as compact JSON. It marshals the
// value's native Go form (AsInterface) with encoding/json rather than protojson:
// encoding/json emits compact output with map keys sorted, so the result is
// deterministic — protojson deliberately randomizes whitespace, which a stored
// value must not do. A marshal failure omits the key rather than aborting the
// whole registration.
func nestedJSON(v *structpb.Value) (string, bool) {
	raw, err := json.Marshal(v.AsInterface())
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// noJSONFormMember reports the first registration_data member holding a value
// with no JSON representation, as a dotted/indexed path ("ratio",
// "address.lat", "scores[2]"), or ok=false when it finds none.
//
// It DECIDES NOTHING. The verdict is the SDK's — helpers.CheckRegistrationDataStruct
// owns which payloads are refused and in what order — and this walk runs only
// after that verdict is Uncanonicalizable, to say WHERE. The SDK reports the
// class but not the member, and the member is the only part of the refusal that
// tells a caller which of its up-to-64 members to look at.
//
// Because it only describes, it is safe for it to find nothing: the caller falls
// back to naming the class. It must never do the reverse and claim a member the
// SDK accepted, which is why it is called on the refusal path alone.
//
// It reads the raw Struct for the reason the SDK's check does. AsMap renders a
// non-finite double as the Go string "NaN", "Infinity" or "-Infinity", and an
// unset kind as nil, so neither value is still visible after the conversion.
//
// Which member is named when a payload holds more than one is not fixed: Go
// randomizes map iteration, and the refusal identifies one offending member
// rather than listing them all.
func noJSONFormMember(s *structpb.Struct) (string, bool) {
	for k, v := range s.GetFields() {
		if rest, ok := noJSONFormValue(v); ok {
			return k + rest, true
		}
	}
	return "", false
}

// noJSONFormValue is noJSONFormMember's recursion. It returns the path SUFFIX
// below the value it was handed, so each caller prepends its own key or index.
// A leaf hit returns an empty suffix. Recursion depth is bounded by the
// protocol's nesting limit, which the SDK's verdict has already applied.
//
// The two leaf hits are the two members of the class. A non-finite double is one
// of them. The other is a Value with NO member of its kind oneof set, which the
// type switch sees as a nil kind — that arm is why the switch is written over
// the oneof wrapper rather than over v.GetKind()'s concrete types alone.
func noJSONFormValue(v *structpb.Value) (string, bool) {
	switch kind := v.GetKind().(type) {
	case nil:
		return "", true
	case *structpb.Value_NumberValue:
		n := kind.NumberValue
		return "", math.IsNaN(n) || math.IsInf(n, 0)
	case *structpb.Value_StructValue:
		for k, f := range kind.StructValue.GetFields() {
			if rest, ok := noJSONFormValue(f); ok {
				return "." + k + rest, true
			}
		}
	case *structpb.Value_ListValue:
		for i, e := range kind.ListValue.GetValues() {
			if rest, ok := noJSONFormValue(e); ok {
				return fmt.Sprintf("[%d]%s", i, rest), true
			}
		}
	}
	return "", false
}
