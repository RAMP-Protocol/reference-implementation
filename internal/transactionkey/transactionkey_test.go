package transactionkey_test

import (
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/transactionkey"
)

// The expected values below are LITERALS on purpose. A test that builds the
// expectation by calling DerivedItemKey would change with the function and
// assert nothing: the point of a pinned vector is that editing the formula
// fails a test rather than propagating to every caller silently. Rows written by
// an already-deployed Exchange carry these exact strings, so the vector is what
// stands in for them.
func TestDerivedItemKeyPinnedVectors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		requestKey string
		offerID    string
		want       string
	}{
		{
			name:       "request key and offer id",
			requestKey: "tx-2f6c1a9e",
			offerID:    "tenant-demo:https://publisher.example/a.txt",
			want:       "tx-2f6c1a9e:tenant-demo:https://publisher.example/a.txt",
		},
		{
			// The offer id contains colons of its own, so the separator does
			// not survive as a delimiter anything could split back apart. That
			// is intended: the key is compared whole, never parsed.
			name:       "the separator is not a parseable delimiter",
			requestKey: "a:b",
			offerID:    "c:d",
			want:       "a:b:c:d",
		},
		{
			name:       "empty offer id still separates",
			requestKey: "tx-1",
			offerID:    "",
			want:       "tx-1:",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := transactionkey.DerivedItemKey(tc.requestKey, tc.offerID); got != tc.want {
				t.Fatalf("DerivedItemKey(%q, %q) = %q, want %q",
					tc.requestKey, tc.offerID, got, tc.want)
			}
		})
	}
}

// Distinct offer ids must give distinct keys. This is the property the derived
// key exists for: without it the idempotency_key UNIQUE constraint and the
// billing dedup collapse every item of one multi-item request into one row.
func TestDerivedItemKeySeparatesItemsOfOneRequest(t *testing.T) {
	t.Parallel()

	const requestKey = "tx-2f6c1a9e"
	first := transactionkey.DerivedItemKey(requestKey, "offer-1")
	second := transactionkey.DerivedItemKey(requestKey, "offer-2")

	if first == second {
		t.Fatalf("two offers of one request derived the same key: %q", first)
	}
}
