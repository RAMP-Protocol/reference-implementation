package testutil

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// reporter is the slice of testing.TB this file needs. It exists so the
// assertion below can be driven by a recorder in its own tests: an assertion
// nothing ever watches fail is one that can be turned off by accident, and
// changing its Errorf to a Logf used to leave every call site quiet and green.
type reporter interface {
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Helper()
}

// AssertCanonicalWireNames fails tb when raw carries any field under its
// camelCase json_name alias instead of its snake_case proto name.
//
// The RAMP wire is snake_case proto-JSON. protojson writes the alias unless
// UseProtoNames is set, and a Go peer reads both spellings, so a producer that
// emits the alias looks correct from Go and is invisible to a status-code
// assertion. It is not invisible to a reader built from the generated Pydantic
// and Zod schemas: those declare proto names only and drop what they do not
// know, so an aliased answer parses into a message with the aliased fields
// missing and reports nothing wrong.
//
// Two further failures, because the walk is only meaningful once both hold.
// Bytes that are not JSON are fatal: there is nothing to walk. Bytes that do not
// decode as msg are reported, because the walk would otherwise describe the
// wrong message — see decodesAs for what that looks like.
//
// raw is the exact bytes on the wire; msg names the message they encode. Its own
// fields are never read: the descriptor drives the walk, and the decode check
// runs against a fresh instance.
func AssertCanonicalWireNames(tb testing.TB, raw []byte, msg proto.Message) {
	tb.Helper()
	assertCanonicalWireNames(tb, raw, msg)
}

// assertCanonicalWireNames is the body of the assertion above, over the narrow
// reporter so a test can watch it fail.
func assertCanonicalWireNames(r reporter, raw []byte, msg proto.Message) {
	r.Helper()
	var body any
	if err := json.Unmarshal(raw, &body); err != nil {
		r.Fatalf("body is not JSON: %v\n%s", err, truncate(raw))
		return
	}
	if err := decodesAs(raw, msg); err != nil {
		// Without this the walk below reports on what it RECOGNISES, and a body
		// belonging to another message recognises nothing: every key misses, each
		// one is taken for a field a newer peer added, and zero hits reads exactly
		// like a clean answer. Measured — a camelCase PushResourcesResponse walked
		// against a ResourceResponse descriptor came back with no findings at all.
		r.Errorf("body does not decode as %s, so the walk below would report on the "+
			"wrong message: %v\n%s", msg.ProtoReflect().Descriptor().FullName(), err, truncate(raw))
		return
	}
	hits := aliasedNames(msg.ProtoReflect().Descriptor(), body, "")
	// Map iteration is unordered, so a failure has to be sorted to read the same
	// way twice.
	sort.Strings(hits)
	for _, hit := range hits {
		r.Errorf("%s is the camelCase json_name alias; the wire is snake_case proto-JSON", hit)
	}
}

// AssertWireCarries fails tb unless raw carries each of names on the wire.
//
// A name is a DESCRIPTOR PATH: a field name, dotted to descend into a
// submessage and indexed to pick a repeated element — "idempotency_key",
// "items[0].agent_acceptance". Every segment is resolved against msg's
// descriptor before the body is read, so a name this build does not declare
// fails as a fault in the test rather than as a field missing from the wire.
//
// This replaces a substring search over the raw bytes at three call sites, and
// it is stricter in three ways that each mattered at one of them. A substring
// also matches the same text inside a string VALUE. It cannot tell a top-level
// key from a nested one, so a check for a per-item field passed against a body
// that carried it at the top level — the exact shape the wire contract forbids.
// And it never checks the name is a real field, so renaming one in the contract
// failed with a message about the codec, pointing the reader at the wrong cause.
func AssertWireCarries(tb testing.TB, raw []byte, msg proto.Message, names ...string) {
	tb.Helper()
	assertWireCarries(tb, raw, msg, names...)
}

// assertWireCarries is the body of the assertion above, over the narrow reporter
// so a test can watch it fail.
func assertWireCarries(r reporter, raw []byte, msg proto.Message, names ...string) {
	r.Helper()
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		r.Fatalf("body is not a JSON object: %v\n%s", err, truncate(raw))
		return
	}
	md := msg.ProtoReflect().Descriptor()
	for _, name := range names {
		steps, err := wirePath(md, name)
		if err != nil {
			// The test asked for something the contract does not have. Fatal,
			// because every later assertion in it is reading the wrong shape.
			r.Fatalf("%v", err)
			return
		}
		if missing, ok := walkTo(body, steps); !ok {
			r.Errorf("the wire carries no %s (looked for %s)\n%s", name, missing, truncate(raw))
		}
	}
}

// wireStep is one segment of a descriptor path: the field it names, and the
// repeated element to descend into (-1 where the segment names none).
type wireStep struct {
	field protoreflect.FieldDescriptor
	index int
}

// wirePath resolves a dotted path against md, one step per segment.
func wirePath(md protoreflect.MessageDescriptor, path string) ([]wireStep, error) {
	steps := make([]wireStep, 0, strings.Count(path, ".")+1)
	for _, segment := range strings.Split(path, ".") {
		if md == nil {
			return nil, fmt.Errorf("%s: %q descends into something that is not a message", path, segment)
		}
		name, index := splitIndex(segment)
		field := md.Fields().ByName(protoreflect.Name(name))
		if field == nil {
			return nil, fmt.Errorf("%s: %s declares no field %q — the path names a field "+
				"this build does not have, so nothing on the wire could satisfy it",
				path, md.FullName(), name)
		}
		steps = append(steps, wireStep{field: field, index: index})
		md = descend(field)
	}
	return steps, nil
}

// splitIndex reads "offers[2]" as ("offers", 2) and "offers" as ("offers", -1).
// A malformed index is left in the name, where wirePath reports it as a field
// the message does not declare.
func splitIndex(segment string) (string, int) {
	open := strings.IndexByte(segment, '[')
	if open < 0 || !strings.HasSuffix(segment, "]") {
		return segment, -1
	}
	index, err := strconv.Atoi(segment[open+1 : len(segment)-1])
	if err != nil || index < 0 {
		return segment, -1
	}
	return segment[:open], index
}

// walkTo follows steps through the decoded body. It reports the path prefix that
// stopped it, and whether every step was present.
func walkTo(body map[string]any, steps []wireStep) (string, bool) {
	node := any(body)
	seen := ""
	for _, step := range steps {
		name := string(step.field.Name())
		seen = strings.TrimPrefix(seen+"."+name, ".")
		obj, isObject := node.(map[string]any)
		if !isObject {
			return seen, false
		}
		value, present := obj[name]
		if !present {
			return seen, false
		}
		node = value
		if step.index >= 0 {
			seen = fmt.Sprintf("%s[%d]", seen, step.index)
			elems, isList := node.([]any)
			if !isList || step.index >= len(elems) {
				return seen, false
			}
			node = elems[step.index]
		}
	}
	return seen, true
}

// decodesAs reports whether raw is a body of msg's own message type.
//
// protojson refuses an unknown field unless DiscardUnknown is set, which is what
// makes this a mismatch check. It does NOT refuse the case under test: protojson
// reads both the proto name and the json_name alias, so an aliased body of the
// RIGHT message still decodes and still reaches the walk.
//
// Strict on purpose. This asserts on the answer of a server built from the same
// pinned contract, so a field it does not know is a mismatched body rather than a
// newer peer. A caller that genuinely needs to read a newer peer would have to
// relax this, and would lose the mismatch check with it.
func decodesAs(raw []byte, msg proto.Message) error {
	fresh := msg.ProtoReflect().New().Interface()
	return protojson.Unmarshal(raw, fresh)
}

// aliasedNames walks node against md and returns the dotted path of every key
// that is a field's json_name alias rather than its proto name. A nil md means
// the value is not field-keyed and the walk stops there — see descend.
func aliasedNames(md protoreflect.MessageDescriptor, node any, path string) []string {
	if md == nil {
		return nil
	}
	switch shaped := node.(type) {
	case []any:
		var hits []string
		for i, elem := range shaped {
			hits = append(hits, aliasedNames(md, elem, fmt.Sprintf("%s[%d]", path, i))...)
		}
		return hits
	case map[string]any:
		return aliasedKeys(md, shaped, path)
	default:
		return nil
	}
}

// aliasedKeys is aliasedNames' object case: one pass over the keys of a single
// JSON object, recursing into whatever each declared field holds. A key that IS
// an alias is reported and not descended into: the outermost wrong spelling is
// the finding, and every field under it would be reported too.
//
// A key matching neither a proto name nor an alias is left alone HERE, and does
// not reach here at all through AssertCanonicalWireNames: decodesAs runs first
// and refuses an undeclared field outright, for the reason it gives. So the
// tolerance below is reachable only from this walk's own tests, and is not a
// promise the exported assertion makes — a caller who needs to read a peer on a
// newer protocol would have to relax the decode, not this.
func aliasedKeys(md protoreflect.MessageDescriptor, obj map[string]any, path string) []string {
	var hits []string
	fields := md.Fields()
	for key, value := range obj {
		here := strings.TrimPrefix(path+"."+key, ".")
		field := fields.ByName(protoreflect.Name(key))
		if field == nil {
			// ByJSONName resolves the json_name index only, so reaching a field
			// here means key is that field's ALIAS. It cannot also be its proto
			// name: ByName would then have returned it and this branch would not
			// have run. A guard comparing the two reads like a live
			// discriminator and can never be false — measured against the
			// descriptors, where ByJSONName("offer_groups") is nil while
			// ByJSONName("offerGroups") resolves.
			if fields.ByJSONName(key) != nil {
				hits = append(hits, here)
			}
			continue
		}
		hits = append(hits, aliasedNames(descend(field), value, here)...)
	}
	return hits
}

// descend returns the descriptor to read field's JSON value against, or nil
// where that value is not keyed by field name:
//
//   - a scalar or an enum, which is not an object at all;
//   - a map, whose JSON keys are the map's own keys — reading them against a
//     message's fields would report a caller-chosen key as a field name. The
//     contract carries exactly one map field, ErrorDetail.metadata, and its
//     values are strings; a message-valued map would need this walk extended to
//     descend into the values;
//   - a well-known type, which protojson renders with its own custom JSON. This
//     is what keeps the walk off an open extension: Offer.ext is a
//     google.protobuf.Struct, so its members are data, never field names.
func descend(field protoreflect.FieldDescriptor) protoreflect.MessageDescriptor {
	if field.IsMap() {
		return nil
	}
	if field.Kind() != protoreflect.MessageKind && field.Kind() != protoreflect.GroupKind {
		return nil
	}
	md := field.Message()
	if strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return nil
	}
	return md
}

// truncate bounds a body quoted in a failure message.
func truncate(raw []byte) string {
	const max = 512
	if len(raw) <= max {
		return string(raw)
	}
	return string(raw[:max]) + "…"
}
