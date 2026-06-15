package service

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestCatalogURIScheme covers the EXCHANGE_CATALOG_URI_SCHEME override knob.
// Production leaves the scheme at its https default; the e2e compose stack
// flips it to http so catalog URIs route through the in-network edge worker.
// Both entryFromProto and uriFromEntry must honor the override, otherwise
// the radix-trie longest-prefix lookup at discovery time will silently miss
// every http-backed row.
func TestCatalogURIScheme(t *testing.T) {
	entry := &rampv1.ResourceEntry{
		Domain:    rampv1.ResourceEntry{}.Domain, //nolint:staticcheck // placeholder, overwritten below
		Path:      "/premium/article-42.html",
		ContentId: proto("res-e2e-1"),
	}
	entry.Domain = "edge:8787"

	t.Run("default is https", func(t *testing.T) {
		SetCatalogURIScheme("")
		t.Cleanup(func() { SetCatalogURIScheme("") })
		got, err := entryFromProto("tenant-x", entry)
		if err != nil {
			t.Fatalf("entryFromProto: %v", err)
		}
		const want = "https://edge:8787/premium/article-42.html"
		if got.URI != want {
			t.Fatalf("URI = %q, want %q", got.URI, want)
		}
		if u := uriFromEntry(entry); u != want {
			t.Fatalf("uriFromEntry = %q, want %q", u, want)
		}
	})

	t.Run("override applies to entryFromProto", func(t *testing.T) {
		SetCatalogURIScheme("http")
		t.Cleanup(func() { SetCatalogURIScheme("") })
		got, err := entryFromProto("tenant-x", entry)
		if err != nil {
			t.Fatalf("entryFromProto: %v", err)
		}
		const want = "http://edge:8787/premium/article-42.html"
		if got.URI != want {
			t.Fatalf("URI = %q, want %q", got.URI, want)
		}
		if got.URIPrefix != want {
			t.Fatalf("URIPrefix = %q, want %q", got.URIPrefix, want)
		}
	})

	t.Run("override applies to uriFromEntry", func(t *testing.T) {
		SetCatalogURIScheme("http")
		t.Cleanup(func() { SetCatalogURIScheme("") })
		if u := uriFromEntry(entry); u != "http://edge:8787/premium/article-42.html" {
			t.Fatalf("uriFromEntry = %q, want http://edge:8787/...", u)
		}
	})

	t.Run("empty override resets to default", func(t *testing.T) {
		SetCatalogURIScheme("http")
		SetCatalogURIScheme("")
		t.Cleanup(func() { SetCatalogURIScheme("") })
		got, err := entryFromProto("tenant-x", entry)
		if err != nil {
			t.Fatalf("entryFromProto: %v", err)
		}
		if got.URI[:5] != "https" {
			t.Fatalf("URI = %q, want https:// prefix after empty reset", got.URI)
		}
	})
}

func proto[T any](v T) *T { return &v }
