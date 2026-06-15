// Package rampcanonical computes a deterministic, biscuit-carrier-
// independent hash of a RAMP protocol message. The hash is used by Gate F
// (ADR-005 Part 2) to bind the biscuit's per-request attenuation to the
// request body, independently of whether the biscuit rides the HTTP header
// (Tier 1), the RAMPRequest envelope (Tier 2), or a sub-message field
// (Tier 3).
//
// The canonicalization rule is:
//  1. Zero every entitlement_biscuit field reachable in the message tree,
//     regardless of its depth. This lets the hash commit to request
//     substance without pinning the biscuit's carrier.
//  2. Serialize with proto deterministic marshal (ascending field number,
//     sorted map entries).
//  3. sha256 of the resulting bytes.
//
// The set of biscuit-carrier field names is closed; adding a new carrier
// requires updating this file. That's intentional — the canonical form is
// a protocol invariant, not an open extension point.
package rampcanonical

import (
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// biscuitCarrierField is the proto field name ADR-005 assigns to every
// message that can carry the entitlement biscuit. The set is closed.
const biscuitCarrierField = "entitlement_biscuit"

// CanonicalHash returns sha256(canonical_form(msg)) per ADR-005 Part 2.
//
// Callers typically pass either a *rampv1.RAMPRequest (Tier 2 shape) or the
// concrete sub-message type when using Tier 3 carriage. Passing nil returns
// an error; passing a message with no biscuit-carrier fields returns the
// hash of the ordinary deterministic marshal.
func CanonicalHash(msg proto.Message) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("rampcanonical: nil message")
	}
	cloned := proto.Clone(msg)
	stripBiscuitCarriers(cloned.ProtoReflect())
	bytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("rampcanonical: deterministic marshal: %w", err)
	}
	sum := sha256.Sum256(bytes)
	return sum[:], nil
}

// stripBiscuitCarriers walks the proto message tree and zeroes every
// `entitlement_biscuit` field found on any descendant message. Repeated
// and map fields are traversed; oneof selected messages are traversed via
// the active field.
func stripBiscuitCarriers(m protoreflect.Message) {
	desc := m.Descriptor()
	if fd := desc.Fields().ByName(biscuitCarrierField); fd != nil {
		m.Clear(fd)
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(_ protoreflect.MapKey, vv protoreflect.Value) bool {
					stripBiscuitCarriers(vv.Message())
					return true
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind {
				list := v.List()
				for i := 0; i < list.Len(); i++ {
					stripBiscuitCarriers(list.Get(i).Message())
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			stripBiscuitCarriers(v.Message())
		}
		return true
	})
}
