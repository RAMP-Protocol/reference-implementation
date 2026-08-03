//go:build integration

package transport_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// metadataCorpusPath resolves a fixture in the shared resource-metadata corpus
// (deploy/fixtures/publisher/metadata/) relative to this test file at the repo
// root.
func metadataCorpusPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", "deploy", "fixtures", "publisher", "metadata", name)
}

// parseCorpusFile parses one corpus fixture through the production ParseJSONL.
func parseCorpusFile(t *testing.T, name string) []ingest.Record {
	t.Helper()
	f, err := os.Open(metadataCorpusPath(t, name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer func() { _ = f.Close() }()
	records, err := ingest.ParseJSONL(f)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return records
}

// TestIngestMetadata_ExtensionLineAccepted drives an extension-bearing feed
// line from the shared corpus through the PRODUCTION ingest path —
// ParseJSONL + MapRecords + PushEntries (RFC 9421-signed Connect RPC, no SQL) —
// against a real Exchange + testcontainers Postgres, and asserts PushResources
// accepts it. The line carries ext (resource_mutability + previews),
// content_hash/hash_method, word_count, estimated_quantity, source,
// provenance_*, and one priced term. Persistence and Offer emission of the
// metadata are a later slice; this proves the proto round-trips THROUGH
// PushResources (accepted), discharging the ingest-side obligation of .7/.8.
func TestIngestMetadata_ExtensionLineAccepted(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)

	records := parseCorpusFile(t, "valid_full.jsonl")
	if len(records) != 1 {
		t.Fatalf("valid_full.jsonl: expected 1 record, got %d", len(records))
	}
	entries, err := ingest.MapRecords(records)
	if err != nil {
		t.Fatalf("map extension line: %v", err)
	}

	report, err := ingest.PushEntries(h.ctx, h.server.URL, publisherTenant, kid, mustSigningClient(t, kid, priv), entries)
	if err != nil {
		t.Fatalf("push extension line: %v", err)
	}
	if report.Accepted != 1 || report.Rejected != 0 {
		t.Fatalf("push report = accepted %d / rejected %d, want 1 / 0 (warnings: %v)",
			report.Accepted, report.Rejected, report.Warnings)
	}
}

// TestIngestMetadata_UnknownKeyRejectedAtParse proves the resource extension
// fields do NOT relax DisallowUnknownFields: the corpus reject_parse fixture
// carries a genuinely-unknown top-level key, and ParseJSONL fails loudly at the
// parse layer (before any push) with a line-numbered error.
func TestIngestMetadata_UnknownKeyRejectedAtParse(t *testing.T) {
	f, err := os.Open(metadataCorpusPath(t, "reject_parse.jsonl"))
	if err != nil {
		t.Fatalf("open reject_parse.jsonl: %v", err)
	}
	defer func() { _ = f.Close() }()

	_, err = ingest.ParseJSONL(f)
	if err == nil {
		t.Fatal("expected ParseJSONL to reject the corpus parse-reject fixture, got nil")
	}
	if !strings.Contains(err.Error(), "line") {
		t.Errorf("parse error should reference the offending line, got: %v", err)
	}
}

// TestIngestMetadata_MutabilityMapperRejected proves an explicit UNSPECIFIED and
// an unknown resource_mutability spelling PARSE cleanly but are rejected at the
// mapper (MapRecords) — the negative path for the typed-field promotion, driven
// through the production ParseJSONL + MapRecords surface. Nothing reaches push.
func TestIngestMetadata_MutabilityMapperRejected(t *testing.T) {
	records := parseCorpusFile(t, "reject_map_mutability.jsonl")
	if len(records) < 2 {
		t.Fatalf("reject_map_mutability.jsonl: expected >=2 records (UNSPECIFIED + unknown), got %d", len(records))
	}
	// MapRecords short-circuits on the first bad record, so assert each line is
	// rejected in isolation — proving BOTH the UNSPECIFIED sentinel and the unknown
	// name fail at the mapper, then that a batch containing either is voided whole.
	for i := range records {
		_, err := ingest.MapRecords(records[i : i+1])
		if err == nil {
			t.Errorf("record %d (%s%s): expected MapRecords to reject mutability, got nil",
				i, records[i].Domain, records[i].Path)
			continue
		}
		if !strings.Contains(err.Error(), "resource mutability") {
			t.Errorf("record %d (%s%s): rejection must name the mutability reason, got: %v",
				i, records[i].Domain, records[i].Path, err)
		}
	}
	_, err := ingest.MapRecords(records)
	if err == nil {
		t.Fatal("expected MapRecords to reject the batch, got nil (nothing should reach push)")
	}
	if !strings.Contains(err.Error(), "resource mutability") {
		t.Fatalf("batch rejection must name the mutability reason, got: %v", err)
	}
}
