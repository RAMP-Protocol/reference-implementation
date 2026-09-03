// Guard on the division of labour between the two things that check a manifest.
//
// The embedded schema/ramp-well-known.json owns the WIRE SHAPE: which members
// exist, what JSON type each carries, which enum names are spelled. The
// protocol's own rules — field patterns, cross-field CEL — live in ramp.proto
// as protovalidate constraints and are run against the decoded message, on the
// produce path in server.Build and on the consume path in ParseManifest.
//
// This file keeps the first from growing into the second. A protocol rule
// restated as JSON Schema drifts from the proto, and it drifts invisibly: the
// manifest builder only ever emits the valid combination, so a copy that
// disagreed with the protocol about every other input would pass every
// behavioral test in this repo. It also refuses documents third parties are
// entitled to serve, since the embedded schema validates what this repo fetches
// as well as what it builds.
//
// semanticKeywords below lists every keyword a protocol rule gets written with
// when someone copies it here: a value pattern, a numeric or cardinality bound,
// or a branch relating one member to another. const and enum are deliberately
// absent, because for ver and role they ARE the wire shape.
//
// A handful of bounds in the embedded schema are this repo's own rather than a
// copy of anything, and repoOwnBounds names each one exactly. Every entry there
// is a field the proto leaves unconstrained, which is a claim under test:
// TestRepoOwnBoundsCoverOnlyUnconstrainedFields feeds each field an empty value
// and fails if protovalidate turns out to refuse it, so an entry cannot outlive
// the protocol pin that justified it.
package rampwellknown_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// semanticKeywords are the JSON Schema keywords that express a rule about a
// VALUE rather than about the document's shape. Each is how one of the proto's
// protovalidate constraints would be spelled if someone copied it here.
var semanticKeywords = []string{
	"pattern", "format",
	"minLength", "maxLength",
	"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf",
	"minItems", "maxItems", "uniqueItems", "minProperties", "maxProperties",
	"allOf", "anyOf", "oneOf", "not", "if", "then", "else",
	"dependentRequired", "dependentSchemas",
}

// repoOwnBounds are the exact sites where the embedded schema states a bound of
// its own rather than a copy of a protocol rule. Each is a field the pinned
// proto leaves unconstrained, so nothing in ramp.proto says what these say and
// deleting them here would lose the check rather than deduplicate it.
//
// The list is exact — a JSON pointer per site, not a keyword waved through
// everywhere — so a bound added to a different field has to be argued for here
// instead of arriving under an existing exemption. It may shrink; every entry
// disappears the day the proto states the rule, and the test below is what
// reports that day.
var repoOwnBounds = []string{
	"/properties/domain/minLength",
	"/properties/max_intermediary_hops/minimum",
	"/$defs/authorizedExchange/properties/endpoint/minLength",
	"/$defs/catalogContributor/properties/domain/minLength",
	"/$defs/catalogContributor/properties/relationship/minLength",
}

// manifestSchemaDoc reads the embedded manifest schema off disk as generic
// JSON. The compiled schema does not expose its keywords, and the source is
// what a reader of this repo edits.
func manifestSchemaDoc(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("schema", "ramp-well-known.json"))
	if err != nil {
		t.Fatalf("read embedded manifest schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse embedded manifest schema: %v", err)
	}
	return doc
}

// findSemanticKeywords walks node and appends the JSON pointer of every
// semantic keyword it carries.
func findSemanticKeywords(node any, at string, found *[]string) {
	switch n := node.(type) {
	case map[string]any:
		for _, kw := range semanticKeywords {
			if _, ok := n[kw]; ok {
				*found = append(*found, at+"/"+kw)
			}
		}
		for k, v := range n {
			findSemanticKeywords(v, at+"/"+k, found)
		}
	case []any:
		for i, v := range n {
			findSemanticKeywords(v, at+"/"+strconv.Itoa(i), found)
		}
	}
}

// TestManifestSchemaStatesNoProtocolRules fails when the embedded schema grows
// a keyword that restates a protocol rule. The rule belongs in ramp.proto,
// where protovalidate runs it on both paths this package owns; a copy here is a
// second statement of one rule, in a language the proto cannot be compared
// against.
func TestManifestSchemaStatesNoProtocolRules(t *testing.T) {
	t.Parallel()
	var found []string
	findSemanticKeywords(manifestSchemaDoc(t), "", &found)
	for _, at := range found {
		if slices.Contains(repoOwnBounds, at) {
			continue
		}
		t.Errorf("schema/ramp-well-known.json carries %s — that is a rule about a value, and every rule about a value is stated once, in ramp.proto, and run by protovalidate on the decoded message. Delete it here.", at)
	}
}

// TestMeta_SemanticKeywordDetectorFindsANestedCopy proves the walk reaches
// past the top level: the rules this guard is about were written inside allOf
// and inside properties, not at the document root.
func TestMeta_SemanticKeywordDetectorFindsANestedCopy(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"properties": map[string]any{
			"terms_digest": map[string]any{"type": "string", "pattern": "^sha256:"},
		},
	}
	var found []string
	findSemanticKeywords(doc, "", &found)
	if len(found) != 1 || found[0] != "/properties/terms_digest/pattern" {
		t.Fatalf("detector found %v, want exactly [/properties/terms_digest/pattern]", found)
	}
}

// TestMeta_SemanticKeywordDetectorFindsACopyInsideAnArray proves the walk
// descends through arrays, which is where an allOf branch's if/then sits.
func TestMeta_SemanticKeywordDetectorFindsACopyInsideAnArray(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"allOf": []any{
			map[string]any{"if": map[string]any{"required": []any{"terms_digest"}}},
		},
	}
	var found []string
	findSemanticKeywords(doc, "", &found)
	for _, want := range []string{"/allOf", "/allOf/0/if"} {
		if !slices.Contains(found, want) {
			t.Errorf("detector found %v, want it to include %s", found, want)
		}
	}
}

// TestMeta_SemanticKeywordDetectorPassesAWireShapeSchema is the negative
// meta-test: the shape checks the embedded schema is FOR must not trip it.
func TestMeta_SemanticKeywordDetectorPassesAWireShapeSchema(t *testing.T) {
	t.Parallel()
	doc := map[string]any{
		"type":     "object",
		"required": []any{"ver", "role", "domain"},
		"properties": map[string]any{
			"ver":       map[string]any{"const": "1.0"},
			"role":      map[string]any{"enum": []any{"ROLE_EXCHANGE"}},
			"domain":    map[string]any{"type": "string"},
			"exchanges": map[string]any{"type": "array", "items": map[string]any{"$ref": "#/$defs/x"}},
		},
	}
	var found []string
	findSemanticKeywords(doc, "", &found)
	if len(found) != 0 {
		t.Fatalf("detector flagged %v in a pure wire-shape schema", found)
	}
}

// TestRepoOwnBoundsCoverOnlyUnconstrainedFields turns the justification for
// repoOwnBounds into a measurement the suite repeats.
//
// Each entry claims the pinned proto says nothing about that field, which is
// why a bound stated here is this repo's own rather than a second copy. The
// claim was previously a sentence recording a one-time manual check, and it was
// wrong: authorizedExchange.domain carries a protovalidate pattern that no
// empty string can match, so its "minLength": 1 was a weaker restatement of a
// proto rule sitting inside the very file that forbids them.
//
// This drives each field empty through protovalidate and fails when the
// protocol turns out to refuse it. A pin bump that constrains one of these
// fields therefore breaks the build on the entry it retires, rather than
// leaving the exemption standing on a justification that has quietly expired.
func TestRepoOwnBoundsCoverOnlyUnconstrainedFields(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		bound string
		build func(m *rampwellknown.Manifest)
	}{
		{"/properties/domain/minLength", func(m *rampwellknown.Manifest) { m.Domain = "" }},
		{"/properties/max_intermediary_hops/minimum", func(m *rampwellknown.Manifest) {
			m.MaxIntermediaryHops = proto.Int32(0)
		}},
		{"/$defs/authorizedExchange/properties/endpoint/minLength", func(m *rampwellknown.Manifest) {
			m.Exchanges = []*rampv1.AuthorizedExchange{{
				Domain:       "x.example",
				Endpoint:     "",
				Relationship: rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT,
			}}
		}},
		{"/$defs/catalogContributor/properties/domain/minLength", func(m *rampwellknown.Manifest) {
			m.CatalogContributors = []*rampv1.CatalogContributor{{Domain: "", Relationship: "direct"}}
		}},
		{"/$defs/catalogContributor/properties/relationship/minLength", func(m *rampwellknown.Manifest) {
			m.CatalogContributors = []*rampv1.CatalogContributor{{Domain: "c.example", Relationship: ""}}
		}},
	} {
		t.Run(tc.bound, func(t *testing.T) {
			t.Parallel()
			if !slices.Contains(repoOwnBounds, tc.bound) {
				t.Fatalf("%s is not in repoOwnBounds — the two lists have drifted apart", tc.bound)
			}
			m := &rampwellknown.Manifest{
				Ver:    rampwellknown.Version,
				Role:   rampv1.Role_ROLE_EXCHANGE,
				Domain: "x.example",
			}
			tc.build(m)
			if err := helpers.Validate(m); err != nil {
				t.Errorf("protovalidate refuses the empty value at %s (%v) — the proto now states this rule, "+
					"so the entry in repoOwnBounds is a second copy of it. Delete the keyword from the schema "+
					"and the entry from the list.", tc.bound, err)
			}
		})
	}
}

// TestEveryRepoOwnBoundIsLive fails when repoOwnBounds names a site the schema
// no longer carries. An exemption for a keyword that has already been deleted
// reads as a live exception and is the shape an exclusion list grows by.
func TestEveryRepoOwnBoundIsLive(t *testing.T) {
	t.Parallel()
	var found []string
	findSemanticKeywords(manifestSchemaDoc(t), "", &found)
	for _, bound := range repoOwnBounds {
		if !slices.Contains(found, bound) {
			t.Errorf("repoOwnBounds names %s, which schema/ramp-well-known.json does not carry — delete the entry", bound)
		}
	}
}
