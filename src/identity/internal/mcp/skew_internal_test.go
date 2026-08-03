package mcp

import (
	"errors"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The protocol-skew guard cannot be driven through the MCP surface. Staging it
// needs a peer whose response carries a field this service's pinned protocol does
// not declare, and the peer doubles serialize with protojson, which cannot emit an
// unknown field at all — so an over-the-wire version of this test would assert
// nothing and would survive the guard's deletion. Same reasoning as
// caller_internal_test.go: the branch is unreachable from the integration suite,
// so it is driven directly here.
//
// unknownBytes is a wire-format field 511 (varint, value 1) — a tag no RAMP
// message declares, which is what a message from a newer peer looks like once it
// has been decoded against an older pin.
var unknownBytes = protoreflect.RawFields([]byte{0xf8, 0x1f, 0x01})

// The nested cases are the point. Before the walk, the guard called GetUnknown()
// on the top-level message only, so every one of these passed and the offer went
// to the agent with the nested field silently dropped — invalidating the signature
// that covers the whole message.
func TestCheckNoUnknownFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		// build returns the message to check, with any unknown field already set.
		build func() *rampv1.Offer
		// wantPath is the location the refusal must name; "" means the root.
		wantPath string
		wantErr  bool
	}{
		{
			name:    "clean offer passes",
			build:   func() *rampv1.Offer { return &rampv1.Offer{OfferId: "o1"} },
			wantErr: false,
		},
		{
			name: "unknown field on the offer itself",
			build: func() *rampv1.Offer {
				o := &rampv1.Offer{OfferId: "o1"}
				o.ProtoReflect().SetUnknown(unknownBytes)
				return o
			},
			wantErr: true,
		},
		{
			name: "unknown field on a nested singular message",
			build: func() *rampv1.Offer {
				o := &rampv1.Offer{OfferId: "o1", Pricing: &rampv1.Pricing{}}
				o.Pricing.ProtoReflect().SetUnknown(unknownBytes)
				return o
			},
			wantPath: ".pricing",
			wantErr:  true,
		},
		{
			name: "unknown field on a repeated nested message",
			build: func() *rampv1.Offer {
				o := &rampv1.Offer{
					OfferId: "o1",
					Terms:   []*rampv1.LicenseTerm{{}, {}},
				}
				o.Terms[1].ProtoReflect().SetUnknown(unknownBytes)
				return o
			},
			wantPath: ".terms[1]",
			wantErr:  true,
		},
		{
			name: "unknown field two levels down",
			build: func() *rampv1.Offer {
				o := &rampv1.Offer{
					OfferId:   "o1",
					Identity:  &rampv1.ResourceIdentity{},
					Pricing:   &rampv1.Pricing{},
					Previews:  []*rampv1.Preview{{}},
					DataAsOf:  nil,
					Signature: "sig",
				}
				o.Previews[0].ProtoReflect().SetUnknown(unknownBytes)
				return o
			},
			wantPath: ".previews[0]",
			wantErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkNoUnknownFields(tc.build())
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("checkNoUnknownFields: unexpected err %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("a message carrying an undeclared field was accepted")
			}
			// The sentinel must survive the wrap: rampError and the tool layer
			// branch on it to tell "upgrade the pin" from "the caller sent junk".
			if !errors.Is(err, errProtocolSkew) {
				t.Errorf("err %v does not match errProtocolSkew", err)
			}
			if !strings.Contains(err.Error(), "ramp.v1.Offer"+tc.wantPath) {
				t.Errorf("err %q does not locate the skew at %q", err, "ramp.v1.Offer"+tc.wantPath)
			}
		})
	}
}

// protoToMap is the surface the guard actually sits behind, so it gets its own
// check that a nested skew stops the render rather than being reported and then
// marshaled anyway.
func TestProtoToMap_RefusesNestedSkew(t *testing.T) {
	t.Parallel()
	o := &rampv1.Offer{OfferId: "o1", Pricing: &rampv1.Pricing{}}
	o.Pricing.ProtoReflect().SetUnknown(unknownBytes)

	obj, err := protoToMap(o)
	if err == nil {
		t.Fatal("protoToMap rendered an offer with a nested undeclared field")
	}
	if !errors.Is(err, errProtocolSkew) {
		t.Errorf("err %v does not match errProtocolSkew", err)
	}
	if obj != nil {
		t.Errorf("protoToMap returned %v alongside its error; a refusal renders nothing", obj)
	}
}
