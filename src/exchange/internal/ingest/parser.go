// Package ingest is the RAMP JSON-L ingestion core: it reads a
// JSON-Lines feed (one resource per line) into typed records, maps
// each record to a proto-exact ramp.v1.ResourceEntry (terms[] that pass
// licenseterm.Validate), then signs and pushes them to the Exchange via the
// CatalogService.PushResources RPC. The cmd/ramp-ingest binary is a thin
// flag-parsing wrapper over Run.
//
// This file is the parse layer: a faithful, typed transport DTO for the JSON-L
// line schema THIS repository fixes — a feed does not get to extend it, since
// unknown fields are rejected rather than ignored (see Record below). It performs
// no proto mapping and no licence-term validation — those are owned by the
// mapper slice and the licenseterm package respectively.
package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Record is one resource line of the JSON-L feed. Fields are typed
// (no map[string]any): the schema is fixed and any unknown field is a malformed
// line, not silently ignored data.
//
// The metadata fields (content_id … attestations) are the resource
// extension surface. They are accepted here as a faithful transport DTO only:
// ext and attestation claims are kept as raw JSON (json.RawMessage), and the
// provenance timestamp / source enum stay as strings. Structural and value
// validation (RFC3339 parse, IngestionSource enum lookup, structpb conversion)
// is owned by the mapper slice — the parser performs none of it. Every metadata
// field is optional, so a legacy line carrying none of them parses unchanged.
type Record struct {
	Domain  string   `json:"domain"`
	Path    string   `json:"path"`
	Title   string   `json:"title,omitempty"`
	License *License `json:"license,omitempty"`
	Terms   []Term   `json:"terms"`

	// Resource extension metadata, all optional.
	ContentID           string          `json:"content_id,omitempty"`
	WordCount           *int32          `json:"word_count,omitempty"`
	EstimatedQuantity   *int32          `json:"estimated_quantity,omitempty"`
	ContentHash         string          `json:"content_hash,omitempty"`
	HashMethod          string          `json:"hash_method,omitempty"`
	Source              string          `json:"source,omitempty"`
	ProvenanceSource    string          `json:"provenance_source,omitempty"`
	ProvenanceTimestamp string          `json:"provenance_timestamp,omitempty"`
	ResourceMutability  string          `json:"resource_mutability,omitempty"`
	Ext                 json.RawMessage `json:"ext,omitempty"`
	ExtCritical         []string        `json:"ext_critical,omitempty"`
	Attestations        []Attestation   `json:"attestations,omitempty"`
}

// Attestation is a third-party (or self-) attestation about a resource,
// mirroring proto ramp.v1.ResourceAttestation. Claims is kept as raw JSON; the
// mapper converts it to a *structpb.Struct (and rejects non-object claims).
type Attestation struct {
	Verifier   string          `json:"verifier,omitempty"`
	Kid        string          `json:"kid,omitempty"`
	AttestedAt string          `json:"attested_at,omitempty"`
	URI        string          `json:"uri,omitempty"`
	Claims     json.RawMessage `json:"claims,omitempty"`
	Signature  string          `json:"signature,omitempty"`
}

// License is the governing licence document for a record's terms.
// A REFERENCE_ONLY term requires a non-empty Uri (enforced downstream by
// licenseterm.Validate).
type License struct {
	ID        string `json:"id,omitempty"`
	URI       string `json:"uri,omitempty"`
	URIDigest string `json:"uri_digest,omitempty"`
	Name      string `json:"name,omitempty"`
}

// Term is one declared licensing offer. It maps 1:1 to a
// ramp.v1.LicenseTerm in the mapper slice.
type Term struct {
	Semantics           string       `json:"semantics"`
	Functions           []string     `json:"functions,omitempty"`
	ProhibitedFunctions []string     `json:"prohibited_functions,omitempty"`
	UserTypes           []string     `json:"user_types,omitempty"`
	Geos                []string     `json:"geos,omitempty"`
	Pricing             *Pricing     `json:"pricing,omitempty"`
	Quotas              []Quota      `json:"quotas,omitempty"`
	Obligations         []Obligation `json:"obligations,omitempty"`
	Scopes              []string     `json:"scopes,omitempty"`
}

// Pricing is the term's charging declaration. Model is one of
// "free" | "per_unit" | "flat" (the closed proto PricingModel set). Unit is a
// registered metering token, required for per_unit and absent for flat/free.
// Rate is a decimal STRING, matching proto ramp.v1.Pricing.rate — a JSON
// number fails the line at parse time (money is never a float on any
// surface). The mapper validates and canonicalizes the value.
type Pricing struct {
	Model    string `json:"model"`
	Unit     string `json:"unit,omitempty"`
	Rate     string `json:"rate"`
	Currency string `json:"currency,omitempty"`
}

// Quota is a usage cap. Window is one of "hourly" | "daily" |
// "monthly" | "total".
type Quota struct {
	Metric string `json:"metric"`
	Limit  int64  `json:"limit"`
	Window string `json:"window"`
}

// Obligation is a post-use behavioural requirement (e.g. attribution,
// contribution). Kind/Trigger are the lowercase source spellings of the proto
// ObligationKind / ObligationTrigger enums.
type Obligation struct {
	Kind         string `json:"kind"`
	Trigger      string `json:"trigger,omitempty"`
	ScopeLicense string `json:"scope_license,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

// ParseJSONL reads a JSON-Lines stream into typed Records. Each
// non-blank line must be a single well-formed JSON object matching the record
// schema; unknown fields are rejected (DisallowUnknownFields) so a malformed
// line fails loudly. Errors are wrapped with the 1-based line number.
func ParseJSONL(r io.Reader) ([]Record, error) {
	scanner := bufio.NewScanner(r)
	// Allow long lines (a resource with many terms can exceed the 64KB default).
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var records []Record
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue // skip blank lines
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("parse line %d: %w", lineNo, err)
		}
		// A line must be exactly one JSON object — reject trailing garbage.
		if dec.More() {
			return nil, fmt.Errorf("parse line %d: unexpected trailing content after JSON object", lineNo)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read line %d: %w", lineNo, err)
	}
	return records, nil
}
