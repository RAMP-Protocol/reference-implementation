// Package comptest is the CoMP V1 conformance oracle. It validates a
// rendered ext.comp Package (the supply-side CoMP document an Offer projects)
// against the canonical CoMP V1 supply schema, so "would a real CoMP parser
// accept this?" is a test, not a belief.
//
// CoMP V1 ships as a Markdown spec only — there is no upstream proto, JSON
// Schema, or reference parser (see deploy/fixtures/comp/canonical/README.md).
// The oracle therefore encodes the canonical supply-side object schema derived
// from the spec's attribute tables (commit 08c0181a): the known key set + types
// per object, plus required fields. Validate enforces three properties:
//
//   - no foreign keys at canonical CoMP paths — RAMP extras live ONLY under a
//     nested ext object (which is opaque and unvalidated);
//   - field types match the canonical declaration (int/float/string/object,
//     scalar or typed array);
//   - required fields are present (Package.id).
//
// The render slices call Validate in their GREEN step. When the
// RAMP-authored CoMP V1 JSON Schema (.18) lands it drops in behind this same
// Validate interface as a machine-checked gate.
package comptest

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"

	"google.golang.org/protobuf/types/known/structpb"
)

// kind is the canonical JSON type of a CoMP field.
type kind int

const (
	kInt kind = iota
	kFloat
	kString
	kObject
)

// field describes one canonical attribute: its type, whether it is an array,
// whether it is required, and (for object fields) the named sub-schema.
type field struct {
	k     kind
	array bool
	// scalarOrArray accepts a scalar OR an array of k — a documented CoMP
	// spec/example inconsistency (e.g. media title).
	scalarOrArray bool
	required      bool
	obj           string
}

// schema maps an object's canonical attribute names to their specs. The ext
// attribute is intentionally absent: ext is allowed on every object and is
// opaque (RAMP extras live there), so Validate special-cases it.
type schema map[string]field

// schemas is the canonical CoMP V1 supply-side object set (spec attribute
// tables, commit 08c0181a). Media schemas are built by mediaSchema to avoid
// four near-identical literals.
var schemas = map[string]schema{
	"Package": {
		"id":         {k: kString, required: true},
		"title":      {k: kString},
		"seller":     {k: kString},
		"packager":   {k: kString},
		"licenseurl": {k: kString},
		"citation":   {k: kInt},
		"reporturl":  {k: kString},
		"scope":      {k: kObject, obj: "Scope"},
		"retrieval":  {k: kObject, obj: "Retrieval"},
	},
	"Scope": {
		"scope":      {k: kInt},
		"ause":       {k: kInt},
		"pricetype":  {k: kInt},
		"pricetier":  {k: kInt},
		"unitprice":  {k: kFloat},
		"cur":        {k: kString},
		"country":    {k: kInt, array: true},
		"licensedur": {k: kInt},
		"max":        {k: kInt},
		"ctype":      {k: kInt, array: true},
		"text":       {k: kObject, array: true, obj: "Text"},
		"video":      {k: kObject, array: true, obj: "Video"},
		"image":      {k: kObject, array: true, obj: "Image"},
		"audio":      {k: kObject, array: true, obj: "Audio"},
	},
	"Retrieval": {
		"auth":     {k: kInt},
		"endpoint": {k: kString},
		"type":     {k: kInt, array: true},
	},
	"Text":  mediaSchema("wordcount"),
	"Video": mediaSchema("dur", "clip", "wordcount", "transcript"),
	"Image": mediaSchema(),
	"Audio": mediaSchema("dur", "wordcount", "transcript"),
}

// mediaSchema returns the fields shared by Text/Video/Image/Audio plus the
// per-media extras named in extra. wordcount/dur are int arrays; clip and
// transcript are scalar ints.
func mediaSchema(extra ...string) schema {
	s := schema{
		// title is "string, array" per the spec table, but several canonical
		// examples (ex2/ex8 text) carry it as a bare string — accept both.
		"title":      {k: kString, scalarOrArray: true},
		"cattax":     {k: kInt},
		"cat":        {k: kInt, array: true},
		"language":   {k: kInt, array: true},
		"pubdate":    {k: kString},
		"published":  {k: kInt},
		"update":     {k: kString},
		"author":     {k: kString, array: true},
		"sourcetype": {k: kInt},
		"provenance": {k: kInt},
		"provent":    {k: kString},
	}
	for _, e := range extra {
		switch e {
		case "wordcount", "dur":
			s[e] = field{k: kInt, array: true}
		case "clip", "transcript":
			s[e] = field{k: kInt}
		}
	}
	return s
}

// Validate checks that pkg is a conformant canonical CoMP V1 Package. A leading
// {"package": {...}} wrapper (the shape of the canonical examples) is unwrapped;
// a bare package object (the shape RAMP emits under ext.comp) is accepted
// directly. It returns nil when conformant, else an error joining every
// violation found.
func Validate(pkg *structpb.Struct) error {
	if pkg == nil {
		return errors.New("comp conformance: nil package")
	}
	obj := pkg.AsMap()
	if inner, ok := unwrap(obj); ok {
		obj = inner
	}
	if v := validateObject("Package", obj, "package"); len(v) > 0 {
		sort.Strings(v)
		return fmt.Errorf("comp conformance: %s", strings.Join(v, "; "))
	}
	return nil
}

// unwrap returns the inner package object when obj is exactly {"package": {…}}.
func unwrap(obj map[string]any) (map[string]any, bool) {
	if len(obj) != 1 {
		return nil, false
	}
	inner, ok := obj["package"].(map[string]any)
	return inner, ok
}

// validateObject checks obj against the named schema, returning all violations.
func validateObject(name string, obj map[string]any, path string) []string {
	sch, ok := schemas[name]
	if !ok {
		return []string{fmt.Sprintf("%s: unknown schema %q", path, name)}
	}
	var errs []string
	for key, val := range obj {
		if key == "ext" {
			continue // opaque: RAMP extras live here
		}
		f, known := sch[key]
		if !known {
			errs = append(errs, fmt.Sprintf("%s.%s: foreign key not in canonical CoMP %s", path, key, name))
			continue
		}
		errs = append(errs, checkType(f, val, path+"."+key)...)
	}
	for fname, f := range sch {
		if f.required {
			if _, present := obj[fname]; !present {
				errs = append(errs, fmt.Sprintf("%s.%s: missing required field", path, fname))
			}
		}
	}
	return errs
}

// checkType validates val against f, descending into arrays and object schemas.
func checkType(f field, val any, path string) []string {
	if f.scalarOrArray {
		if arr, ok := val.([]any); ok {
			return checkArray(f, arr, path)
		}
		return checkScalarOrObj(f, val, path)
	}
	if !f.array {
		return checkScalarOrObj(f, val, path)
	}
	arr, ok := val.([]any)
	if !ok {
		return []string{fmt.Sprintf("%s: expected array", path)}
	}
	return checkArray(f, arr, path)
}

// checkArray validates every element of arr against f's element kind.
func checkArray(f field, arr []any, path string) []string {
	errs := make([]string, 0, len(arr))
	for i, e := range arr {
		errs = append(errs, checkScalarOrObj(f, e, fmt.Sprintf("%s[%d]", path, i))...)
	}
	return errs
}

// checkScalarOrObj validates one (non-array) value against f's kind.
func checkScalarOrObj(f field, val any, path string) []string {
	switch f.k {
	case kInt:
		if n, ok := val.(float64); !ok || n != math.Trunc(n) || math.IsInf(n, 0) {
			return []string{fmt.Sprintf("%s: expected int", path)}
		}
	case kFloat:
		if _, ok := val.(float64); !ok {
			return []string{fmt.Sprintf("%s: expected number", path)}
		}
	case kString:
		if _, ok := val.(string); !ok {
			return []string{fmt.Sprintf("%s: expected string", path)}
		}
	case kObject:
		mm, ok := val.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: expected object", path)}
		}
		return validateObject(f.obj, mm, path)
	}
	return nil
}
