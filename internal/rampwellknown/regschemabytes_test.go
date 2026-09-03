package rampwellknown_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// The schema a test Exchange publishes. Written with interior spacing that a
// re-encoding would normalise away, which is what makes the served-bytes
// assertions below able to tell the two apart.
const spacedSchema = `{ "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [ "company_name" ],
  "properties": { "company_name": { "type": "string" } } }`

// TestFetchDocument_ReturnsTheBodyTheOriginServed pins the property the whole
// Document type exists for: Raw is what came off the wire, not a re-encoding of
// the decoded message.
//
// The served body is deliberately INDENTED, and that is what gives the test
// teeth. A fixture built the way production builds one is protojson output, and
// re-marshalling protojson output inside a single process reproduces it byte
// for byte — so a Raw quietly rebuilt from the message would compare equal and
// this test would pass while the guarantee was gone. Indentation is a shape no
// protojson marshal emits, so only the actual wire body can match it. The
// decoder does not care: JSON spacing carries no meaning, which is exactly why
// the size cap has to be measured on the bytes rather than on the message.
func TestFetchDocument_ReturnsTheBodyTheOriginServed(t *testing.T) {
	t.Parallel()
	served := indented(t, testutil.ExchangeManifestWithRegistration(
		"exchange.example", "https://exchange.example",
		testutil.Registration{DataSchemaJSON: spacedSchema}))
	origin := testutil.NewOrigin(served)
	defer origin.Close()

	doc, err := rampwellknown.FetchDocument(context.Background(), origin.URL, rampwellknown.FetchOptions{
		Client:     testutil.Client(),
		ExpectRole: rampwellknown.RoleExchange,
	})
	if err != nil {
		t.Fatalf("FetchDocument: %v", err)
	}
	if !bytes.Equal(doc.Raw, served) {
		t.Fatalf("Raw is not the served body:\n got %s\nwant %s", doc.Raw, served)
	}
	if doc.Manifest.GetDomain() != "exchange.example" {
		t.Fatalf("decoded the wrong document: domain=%s", doc.Manifest.GetDomain())
	}
}

// TestRegistrationSchemaBytes_PreservesTheServedMember is the cap's measurement
// under test. The member is returned with the origin's own spacing, so its
// length is what the publishing Exchange measured — a re-encoding would be
// shorter and the two ends could disagree on a document near the limit.
func TestRegistrationSchemaBytes_PreservesTheServedMember(t *testing.T) {
	t.Parallel()
	served := indented(t, testutil.ExchangeManifestWithRegistration(
		"exchange.example", "https://exchange.example",
		testutil.Registration{DataSchemaJSON: spacedSchema}))
	doc, err := rampwellknown.ParseDocument(served, rampwellknown.RoleExchange)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	raw, ok, err := doc.RegistrationSchemaBytes()
	if err != nil || !ok {
		t.Fatalf("RegistrationSchemaBytes: ok=%t err=%v", ok, err)
	}
	// The member is a slice of the served body, so finding it there byte for
	// byte is the whole claim.
	if !bytes.Contains(served, raw) {
		t.Fatalf("returned bytes are not a slice of the served document: %s", raw)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("returned bytes are not a JSON object: %v", err)
	}
	if got["type"] != "object" {
		t.Fatalf("wrong member returned: %s", raw)
	}
}

// TestRegistrationSchemaBytes_AbsentIsNotARefusal covers both shapes of "this
// Exchange asks for nothing in particular": no registration block at all, and a
// block carrying no schema. Both are normal states with their own contract —
// registration_data passes through uninspected — so neither is an error.
func TestRegistrationSchemaBytes_AbsentIsNotARefusal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		doc  []byte
	}{
		{
			name: "no registration block",
			doc:  testutil.ExchangeManifest("exchange.example", "https://exchange.example"),
		},
		{
			name: "block with no schema member",
			doc:  withEmptyRegistrationBlock(t),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := &rampwellknown.Document{Raw: tc.doc}
			raw, ok, err := doc.RegistrationSchemaBytes()
			if err != nil {
				t.Fatalf("RegistrationSchemaBytes: %v", err)
			}
			if ok || raw != nil {
				t.Fatalf("want absent, got ok=%t raw=%s", ok, raw)
			}
		})
	}
}

// withEmptyRegistrationBlock renders a manifest carrying account_registration
// with no data_schema inside it — a shape the proto admits and the fixture
// builder cannot produce, since it omits the block when there is no schema.
//
// Built by editing the decoded document and re-encoding, then asserted, rather
// than by splicing a string: a splice that missed its anchor would silently
// hand this test the SAME document as the case above, and both would pass.
func withEmptyRegistrationBlock(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(
		testutil.ExchangeManifest("exchange.example", "https://exchange.example"), &doc,
	); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	doc["account_registration"] = map[string]any{}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	if !bytes.Contains(raw, []byte(`"account_registration"`)) {
		t.Fatal("fixture does not carry the registration block it is named for")
	}
	return raw
}

// TestRegistrationSchemaBytes_UnreadableBodyIsReported pins that a body which
// is not JSON is an error rather than silence. Silence would read as "this
// Exchange publishes no schema", which turns a broken document into a decision
// to skip validation.
func TestRegistrationSchemaBytes_UnreadableBodyIsReported(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`not json`, `[1,2,3]`, `{"account_registration": 7}`} {
		doc := &rampwellknown.Document{Raw: []byte(raw)}
		_, ok, err := doc.RegistrationSchemaBytes()
		if !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
			t.Fatalf("%s: want ErrSchemaInvalid, got %v", raw, err)
		}
		if ok {
			t.Fatalf("%s: reported present despite failing", raw)
		}
	}
}

// TestRegistrationSchemaBytes_NoDocumentIsAbsent pins the zero value. A caller
// holding no document has read no schema, which is the absent answer and not a
// nil dereference.
func TestRegistrationSchemaBytes_NoDocumentIsAbsent(t *testing.T) {
	t.Parallel()
	for _, doc := range []*rampwellknown.Document{nil, {}} {
		raw, ok, err := doc.RegistrationSchemaBytes()
		if err != nil || ok || raw != nil {
			t.Fatalf("want absent, got ok=%t raw=%s err=%v", ok, raw, err)
		}
	}
}

// TestFetch_StillReturnsTheMessage pins that the old face is unchanged for the
// readers that never wanted the body: both now run through one fetch-and-parse
// path, and this is what says that path did not shift under them.
func TestFetch_StillReturnsTheMessage(t *testing.T) {
	t.Parallel()
	origin := testutil.NewOrigin(testutil.ExchangeManifest("exchange.example", "https://exchange.example"))
	defer origin.Close()

	m, err := rampwellknown.Fetch(context.Background(), origin.URL, rampwellknown.FetchOptions{
		Client:     testutil.Client(),
		ExpectRole: rampwellknown.RoleExchange,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if m.GetEndpoint() != "https://exchange.example" {
		t.Fatalf("unexpected endpoint %q", m.GetEndpoint())
	}
	if _, err = rampwellknown.Fetch(context.Background(), origin.URL, rampwellknown.FetchOptions{
		Client:     testutil.Client(),
		ExpectRole: rampwellknown.RoleAgent,
	}); !errors.Is(err, rampwellknown.ErrRoleMismatch) {
		t.Fatalf("want ErrRoleMismatch, got %v", err)
	}
	if strings.Contains(m.String(), "account_registration") {
		t.Fatal("fixture unexpectedly carries a registration block")
	}
}

// indented re-renders raw with two-space indentation, so the result is a
// well-formed document that no protojson marshal in this process would produce.
// See TestFetchDocument_ReturnsTheBodyTheOriginServed for why that matters.
func indented(t *testing.T, raw []byte) []byte {
	t.Helper()
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return out
}
