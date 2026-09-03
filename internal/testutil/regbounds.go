package testutil

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/structpb"
)

// The three registration_data payloads that cross exactly one of the protocol's
// bounds. Both the unit test of the Exchange's bounds check and the integration
// test that drives Register through the router build their cases from these, so
// the payload a bound is tested with is written once (Testing Doctrine point 7).
//
// Every builder reads the bound from the SDK rather than from a copied number,
// so a protocol revision that moves a bound moves these payloads with it.
//
// Each crosses ONE bound and stays inside the other two. A payload over two
// bounds at once would be refused whichever check ran first, so a test using it
// could not say which bound the refusal actually named.

// RegistrationOverMemberCap is one member past the top-level member cap. Every
// value is a single character, so the canonical form stays far inside the byte
// cap, and the object is flat, so it is one container deep.
func RegistrationOverMemberCap() map[string]any {
	out := make(map[string]any, helpers.MaxRegistrationDataMembers+1)
	for i := range helpers.MaxRegistrationDataMembers + 1 {
		out[fmt.Sprintf("k%d", i)] = "v"
	}
	return out
}

// RegistrationOverDepthCap is one container past the nesting cap. The payload
// object itself counts as the first container, matching the SDK's counting rule,
// so the nesting built below it stops one short of the cap and the whole document
// is one container over.
func RegistrationOverDepthCap() map[string]any {
	inner := map[string]any{"leaf": "v"}
	for range helpers.MaxRegistrationDataDepth {
		inner = map[string]any{"n": inner}
	}
	return inner
}

// RegistrationOverByteCap is a flat payload whose RFC 8785 canonical encoding is
// over the byte cap and over nothing else: it uses half the member cap, and a
// flat object is one container. Each member carries the cap divided by the
// member count, plus 64 bytes of slack, so the total clears the cap without
// depending on how many bytes the keys and the punctuation add.
func RegistrationOverByteCap() map[string]any {
	members := helpers.MaxRegistrationDataMembers / 2
	chunk := strings.Repeat("x", helpers.MaxRegistrationDataBytes/members+64)
	out := make(map[string]any, members)
	for i := range members {
		out[fmt.Sprintf("k%02d", i)] = chunk
	}
	return out
}

// The two registration_data payloads that have NO JSON REPRESENTATION at all.
// They exist only as a raw Struct: neither value survives a conversion to a Go
// map, which is the whole reason the Exchange checks the raw form. AsMap renders
// a non-finite double as the string "NaN", "Infinity" or "-Infinity", which a
// payload may legitimately carry, and renders a Value with no kind set as nil,
// which is what a real JSON null gives.
//
// Both stay inside every other bound — one flat container, two members, a few
// bytes — so a refusal can only be the no-JSON-form verdict.
//
// Neither can be built with structpb.NewStruct, which refuses a non-finite float
// and has no spelling for an unset kind, so both are assembled field by field.

// RegistrationNonFiniteStruct carries a NaN. Struct's number_value is an
// IEEE-754 double, so the value crosses the wire unchanged and the binary codec
// never objects; JSON can write none of NaN, Infinity or -Infinity.
func RegistrationNonFiniteStruct() *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"company_name": structpb.NewStringValue("Stoa Press"),
		"ratio":        {Kind: &structpb.Value_NumberValue{NumberValue: math.NaN()}},
	}}
}

// RegistrationUntypedValueStruct carries a Value with no member of its kind
// oneof set. A oneof with nothing set is well-formed on the wire, so the binary
// decoder accepts it, and proto-JSON refuses to render it — there is no JSON
// value it denotes.
func RegistrationUntypedValueStruct() *structpb.Struct {
	return &structpb.Struct{Fields: map[string]*structpb.Value{
		"company_name": structpb.NewStringValue("Stoa Press"),
		"untyped":      {},
	}}
}

// RegistrationStruct converts one of the map-shaped payloads above into the form
// RegisterRequest carries. It is the bridge between the three bound builders,
// which are naturally written as maps, and a check that reads the raw Struct.
func RegistrationStruct(tb testing.TB, payload map[string]any) *structpb.Struct {
	tb.Helper()
	s, err := structpb.NewStruct(payload)
	if err != nil {
		tb.Fatalf("build registration_data Struct: %v", err)
	}
	return s
}
