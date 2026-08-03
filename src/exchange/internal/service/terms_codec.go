package service

import (
	"encoding/json"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// marshalTerms serializes the repeated LicenseTerm into the JSONB array stored
// in catalog.terms. Terms are normalized (licenseterm.Normalize) and validated
// by the handler before this runs, so the persisted document is canonical. Each
// element is rendered with protojson snake_case so it round-trips back into a
// rampv1.LicenseTerm via unmarshalTerms without surprise.
func marshalTerms(terms []*rampv1.LicenseTerm) ([]byte, error) {
	if len(terms) == 0 {
		return []byte(`[]`), nil
	}
	mo := protojson.MarshalOptions{UseProtoNames: true}
	out := make([]byte, 0, len(terms)*64)
	out = append(out, '[')
	for i, t := range terms {
		if i > 0 {
			out = append(out, ',')
		}
		elem, err := mo.Marshal(t)
		if err != nil {
			return nil, fmt.Errorf("marshal term %d: %w", i, err)
		}
		out = append(out, elem...)
	}
	out = append(out, ']')
	return out, nil
}

// unmarshalTerms decodes the catalog.terms JSONB array (produced by
// marshalTerms) back into a slice of LicenseTerm. It is the read-side inverse
// used by discovery to project persisted terms onto Offer.terms — the public
// surface through which canonicalized tokens become observable.
func unmarshalTerms(raw []byte) ([]*rampv1.LicenseTerm, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, fmt.Errorf("decode terms array: %w", err)
	}
	out := make([]*rampv1.LicenseTerm, 0, len(elems))
	for i, e := range elems {
		var term rampv1.LicenseTerm
		if err := protojson.Unmarshal(e, &term); err != nil {
			return nil, fmt.Errorf("decode term %d: %w", i, err)
		}
		out = append(out, &term)
	}
	return out, nil
}
