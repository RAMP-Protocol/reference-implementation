package service

import (
	"encoding/json"
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
