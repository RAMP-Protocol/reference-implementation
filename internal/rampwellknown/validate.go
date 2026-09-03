package rampwellknown

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

//go:embed schema/ramp-well-known.json
var manifestSchemaSource []byte

//go:embed schema/ramp-wba-directory.json
var wbaSchemaSource []byte

//go:embed schema/ramp-key-revocation.json
var revocationSchemaSource []byte

// Compiled once at package init. The embedded schemas are developer-controlled
// build assets, so a compile failure is a build-time invariant violation, not
// a runtime condition — panicking surfaces it at the first import in tests.
var (
	manifestSchema   = mustCompileSchema("ramp-well-known.json", manifestSchemaSource)
	wbaSchema        = mustCompileSchema("ramp-wba-directory.json", wbaSchemaSource)
	revocationSchema = mustCompileSchema("ramp-key-revocation.json", revocationSchemaSource)
)

func mustCompileSchema(name string, source []byte) *jsonschema.Schema {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(source))
	if err != nil {
		panic(fmt.Sprintf("rampwellknown: parse embedded schema %s: %v", name, err))
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		panic(fmt.Sprintf("rampwellknown: add embedded schema %s: %v", name, err))
	}
	sch, err := c.Compile(name)
	if err != nil {
		panic(fmt.Sprintf("rampwellknown: compile embedded schema %s: %v", name, err))
	}
	return sch
}

// ValidateManifest checks raw against the WellKnownManifest JSON Schema. It
// returns ErrSchemaInvalid (wrapping the detailed violation) on any failure.
func ValidateManifest(raw []byte) error {
	return validateAgainst(manifestSchema, raw)
}

// ValidateWBA checks raw against the WBAFile (WBA directory) JSON Schema.
func ValidateWBA(raw []byte) error {
	return validateAgainst(wbaSchema, raw)
}

// ValidateRevocation checks raw against the KeyRevocationList JSON Schema.
func ValidateRevocation(raw []byte) error {
	return validateAgainst(revocationSchema, raw)
}

func validateAgainst(sch *jsonschema.Schema, raw []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: not JSON: %w", ErrSchemaInvalid, err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaInvalid, err)
	}
	return nil
}

// decodeValidated runs validate over raw, then protojson-decodes it into msg
// (ignoring unknown fields). A schema or decode failure is wrapped as
// ErrSchemaInvalid. The caller passes the schema validator so the manifest and
// revocation-list decode paths share one validate-then-unmarshal sequence
// without sharing a schema.
func decodeValidated[T proto.Message](raw []byte, msg T, validate func([]byte) error) error {
	if err := validate(raw); err != nil {
		return err
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, msg); err != nil {
		return fmt.Errorf("%w: protojson: %w", ErrSchemaInvalid, err)
	}
	// The embedded schema checks the WIRE SHAPE — which members exist, what JSON
	// type each carries, which enum names are spelled. The protocol's own field
	// and cross-field rules live in the proto as protovalidate constraints, and
	// running them here is what keeps this package from restating them in a
	// second language. A rule written twice drifts, and these two drift
	// invisibly: a producer that only ever emits the valid combination would
	// pass every behavioral test in this repo while the copy disagreed with the
	// protocol about the rest.
	if err := helpers.Validate(msg); err != nil {
		return fmt.Errorf("%w: %w", ErrSchemaInvalid, err)
	}
	return nil
}
