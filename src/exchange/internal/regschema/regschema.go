// Package regschema owns the Exchange's optional registration JSON Schema: the
// one operator-configured document published in /.well-known/ramp.json as
// account_registration.data_schema, and the same document checked against every
// incoming registration_data at the Register gate.
//
// The protocol makes publishing the schema the enforcement switch. An Exchange
// that publishes one has committed to validating registration_data against it
// and refusing a payload that does not conform; one that publishes none lets
// the payload reach the system of record uninspected, exactly as every
// deployment behaved before the field existed.
//
// One document drives both jobs, so Load produces both forms at once, and it
// builds the validator from the bytes it is about to publish rather than from
// the bytes the operator wrote. Document is what the manifest publishes,
// Validator is what the Register gate checks payloads with. Neither reader
// can derive its own form from the other's — a Struct cannot validate, and a
// compiled schema cannot be published — so handing out only one would force the
// second reader to compile again, from bytes that have been through a round
// trip. Producing both here, from one set of bytes, is what makes "the
// published schema and the enforced schema are the same schema" structural
// rather than a convention.
//
// The safety rules the document must satisfy — self-contained references, draft
// 2020-12 only, and the size, depth, evaluation-cost and reference-chain caps —
// are NOT restated here. They live in the SDK, which is where the agent
// pre-checking a payload reads them from too. A limit chosen privately by one
// side would refuse payloads the other accepts, and the whole point of a
// published schema is that both ends reach the same verdict.
package regschema

import (
	"fmt"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// Schema is an operator-configured registration schema that passed every rule
// the protocol states for a published one, in both the forms its two readers
// need.
//
// A nil *Schema is the "no schema configured" state and every method is safe on
// it, so neither the manifest builder nor the Register gate branches on whether
// an operator supplied one.
type Schema struct {
	doc      *structpb.Struct
	compiled *helpers.RegistrationSchema
}

// Load checks the configured schema and returns it ready to publish and to
// validate with.
//
// raw is the document as the operator wrote it. A blank value returns
// (nil, nil): nothing is configured, so nothing is published and nothing is
// enforced. Any other refusal is returned as an error for the composition root
// to fail the boot on.
//
// Failing to boot is the honest response to a schema this Exchange cannot use.
// Serving a manifest that advertises a schema the Exchange could never enforce
// is the one outcome it must not reach: every conformant agent applies these
// same rules, so it would refuse the document, check nothing locally, and send
// payloads against a requirement it could not read.
//
// The operator's bytes and the served bytes are not always the same document.
// The served form is a structpb.Struct marshaled back out by protojson, which
// carries every JSON number as a float64, so a literal needing more than 53
// bits of mantissa is rounded on the way to the wire while the operator's text
// still holds the exact value. The validator is compiled from the SERVED bytes
// for exactly that reason. An agent pre-checks its payload against the document
// it read, so a validator built from any other bytes can reach a verdict the
// agent cannot reproduce — accepting what the agent expected to be refused, or
// refusing what it expected to pass.
//
// Which bytes a rule is measured over follows the same reasoning. Every rule
// about the DOCUMENT — its dialect, its references, how deeply it nests, what
// its patterns cost — describes something the round trip leaves alone, so it is
// answered on the operator's own text, where the error arrives earlier and
// names what they wrote. The size cap is the one rule about the BYTES, and the
// protocol measures it over the bytes served in ramp.json. It is therefore
// answered on the served form alone: a schema that exceeds the cap only through
// its own indentation is one every agent reading the manifest accepts, and
// refusing it here would be a measurement none of them can reproduce.
func Load(raw string) (*Schema, error) {
	// The SDK decides what "no schema" means, down to which bytes count as
	// blank. That decision turns enforcement off, so it is exactly the one that
	// must not be re-answered per language or per service. This first pass is
	// the gate on the operator's own bytes; its compiled result is deliberately
	// discarded, because it was built from bytes nobody will read.
	//
	// SchemaTooLarge is the single verdict this pass does not act on, for the
	// reason the package comment gives: the cap is measured over the served
	// bytes, which the pass below holds. Every other refusal is a property of
	// the document and reads the same on either form, so it is answered here.
	if _, verdict := helpers.CompileRegistrationSchema([]byte(raw)); verdict != helpers.SchemaAccepted {
		switch verdict {
		case helpers.SchemaNotPublished:
			return nil, nil
		case helpers.SchemaTooLarge:
			// Deliberately not a refusal here. The served pass measures it.
		default:
			return nil, fmt.Errorf("registration schema refused: %s", verdict)
		}
	}
	doc := &structpb.Struct{}
	if err := protojson.Unmarshal([]byte(raw), doc); err != nil {
		return nil, fmt.Errorf("registration schema: %w", err)
	}
	// UseProtoNames changes nothing here and is set anyway. doc is a
	// structpb.Struct, which protojson renders with its own custom JSON — the
	// members are the schema author's keys, not proto field names, so the option
	// has nothing to rename and the bytes are identical either way (measured).
	// Every proto-JSON producer in this repository pins the naming, and setting
	// it on the one site where it is a no-op is what lets that rule be stated
	// without an exception.
	served, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("registration schema: re-encode for publication: %w", err)
	}
	// The cap lands here, on the bytes an agent will read. In practice this is
	// the only verdict this pass can still reach: the document rules were all
	// answered above, on a form the round trip does not change.
	compiled, verdict := helpers.CompileRegistrationSchema(served)
	if verdict != helpers.SchemaAccepted {
		return nil, fmt.Errorf("registration schema refused: %s", verdict)
	}
	return &Schema{doc: doc, compiled: compiled}, nil
}

// Document returns the schema to publish as account_registration.data_schema,
// or nil when no schema is configured — which leaves the whole block absent.
//
// The returned Struct is a copy. The manifest handler keeps whatever it is
// given for the life of the process and re-marshals it on every rebuild, so
// handing out the loader's own pointer would let a holder change what the next
// rebuild publishes while leaving the compiled validator — what the Register
// gate enforces — untouched. That is the one divergence this package exists to
// make impossible, and a shared pointer would leave it resting on nobody
// writing through it.
func (s *Schema) Document() *structpb.Struct {
	if s == nil || s.doc == nil {
		return nil
	}
	return proto.Clone(s.doc).(*structpb.Struct)
}

// Validator returns the compiled schema the Register gate checks an incoming
// registration_data against, or nil when no schema is configured — which is the
// pass-through case, where the payload is stored uninspected. A nil receiver
// reports no failures, so the gate needs no branch for it.
//
// It is compiled from the bytes Document publishes, so a payload the Exchange
// refuses is a payload that fails the document an agent could read.
func (s *Schema) Validator() *helpers.RegistrationSchema {
	if s == nil {
		return nil
	}
	return s.compiled
}
