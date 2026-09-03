package ingest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// The demo catalog feeds and the totals the manifest beside them states.
//
// These feeds have no other automated consumer. The e2e suite used to ingest
// them and now owns its own copy, so nothing else would notice a demo feed that
// stopped parsing, mapped to a malformed entry, or grew a term the registered
// vocab does not know. The failure would first appear at the next deployment,
// as a rejected push against a live Exchange.
//
// The manifest in that directory states that all 22 records and 26 terms map and
// validate with zero warnings and zero hard rejects. That is a claim about this
// data, so it is checked here rather than left as prose.
//
// This is a parser-and-mapper test on committed input: no Exchange, no database,
// no RPC. It asserts what the ingest binary would compute before it signs
// anything, which is exactly the stage that decides whether a deployment push
// succeeds.
const (
	demoFeedRecords = 22
	demoFeedTerms   = 26
)

func demoFeedNames() []string {
	return []string{"philosophy.jsonl", "music.jsonl", "sfx.jsonl"}
}

func demoFeedPath(name string) string {
	return filepath.Join("..", "..", "..", "..", "deploy", "fixtures", "demo", name)
}

// parseDemoFeed parses one demo feed, failing the test with the feed's name so a
// breakage points at the file that changed rather than at a total.
func parseDemoFeed(t *testing.T, name string) []Record {
	t.Helper()
	f, err := os.Open(demoFeedPath(name))
	if err != nil {
		t.Fatalf("open demo feed %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	records, err := ParseJSONL(f)
	if err != nil {
		t.Fatalf("parse demo feed %s: %v", name, err)
	}
	if len(records) == 0 {
		t.Fatalf("demo feed %s parsed to zero records", name)
	}
	return records
}

// TestDemoFeedsMapAndValidateCleanly drives every demo feed through ParseJSONL,
// then MapRecords (mapRecord per record, which canonicalizes each term through
// the SDK helper), then helpers.ValidateLicenseTerm per term — the ingest-tier
// check the Exchange runs on a pushed entry. A hard reject fails; so does a
// warning, because the manifest claims there are none and a warning is how an
// unregistered vocab token announces itself.
func TestDemoFeedsMapAndValidateCleanly(t *testing.T) {
	t.Parallel()

	var totalRecords, totalTerms int
	for _, name := range demoFeedNames() {
		records := parseDemoFeed(t, name)
		totalRecords += len(records)

		entries, err := MapRecords(records)
		if err != nil {
			t.Fatalf("map demo feed %s: %v", name, err)
		}
		for _, entry := range entries {
			for _, term := range entry.GetTerms() {
				totalTerms++
				helpers.NormalizeLicenseTerm(term) // idempotent: mapRecord already ran it
				warnings, err := helpers.ValidateLicenseTerm(term)
				if err != nil {
					t.Errorf("%s: %s: term rejected: %v", name, entry.GetPath(), err)
				}
				for _, w := range warnings {
					t.Errorf("%s: %s: term warning: %s", name, entry.GetPath(), w.Message)
				}
			}
		}
	}

	if totalRecords != demoFeedRecords {
		t.Errorf("demo feeds hold %d records, manifest states %d", totalRecords, demoFeedRecords)
	}
	if totalTerms != demoFeedTerms {
		t.Errorf("demo feeds hold %d terms, manifest states %d", totalTerms, demoFeedTerms)
	}
}
