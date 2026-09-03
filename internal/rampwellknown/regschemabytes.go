package rampwellknown

import (
	"encoding/json"
	"fmt"
)

// registrationBlock and dataSchemaMember are the manifest members that carry an
// Exchange's registration schema. Spelled here as JSON names because this file
// reads the SERVED document rather than the decoded message, and the protojson
// name is what appears in the bytes.
const (
	registrationBlock = "account_registration"
	dataSchemaMember  = "data_schema"
)

// RegistrationSchemaBytes returns account_registration.data_schema exactly as
// this document was served, and whether the member is present at all.
//
// Read out of the raw body rather than re-marshalled from the decoded Struct,
// and the difference is not cosmetic. The protocol measures the schema's size
// cap over the bytes the origin sent; protojson re-encodes with its own
// spacing, and carries every JSON number as a float64. A validator compiled
// from a re-encoding would therefore be a different length and could round a
// literal, so this adapter and the publishing Exchange could reach different
// verdicts on the same document — the exact divergence the shared cap exists to
// prevent.
//
// json.RawMessage is what preserves the member: it holds the bytes the decoder
// walked past, interior spacing included.
//
// Absent (false, nil error) covers both a document with no registration block
// and a block with no schema member. Both mean the Exchange asks for nothing in
// particular, which is a normal state with its own contract — registration_data
// is passed through uninspected — and never a refusal. A body that is not JSON
// is an error, because ParseDocument already accepted it as a manifest and a
// document that decodes as a message but not as JSON is a contradiction worth
// reporting rather than reading as silence.
func (d *Document) RegistrationSchemaBytes() ([]byte, bool, error) {
	if d == nil || len(d.Raw) == 0 {
		return nil, false, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(d.Raw, &top); err != nil {
		return nil, false, fmt.Errorf("%w: read %s: %w", ErrSchemaInvalid, registrationBlock, err)
	}
	block, ok := top[registrationBlock]
	if !ok {
		return nil, false, nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(block, &members); err != nil {
		return nil, false, fmt.Errorf("%w: read %s.%s: %w",
			ErrSchemaInvalid, registrationBlock, dataSchemaMember, err)
	}
	schema, ok := members[dataSchemaMember]
	if !ok {
		return nil, false, nil
	}
	return schema, true, nil
}
