package testutil

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// Fixtures for the registration half of a RAMP manifest, the one way to read a
// served manifest back over HTTP, and the assertions every reader makes about
// what came back.
//
// Four packages read the same served document — the Exchange's loader, its
// discovery handler, its composition root, and the Broker's transport suite —
// and rampwellknown drives the same refusal values through its parser. Written
// per package, the copies drift: the same schema appeared under three names
// split across different line breaks, so a grep for one found none of the
// others, and two refusal tables disagreed about what to call the same case.
//
// Anything asserted in more than one of those packages belongs here rather than
// in whichever file the author opened. That covers the fixtures, the fetch, and
// the assertions themselves — a comparison written twice is the same drift one
// step later, and the served-schema comparison had already reordered its
// statements between the two copies before it was moved here.

// RegistrationSchemaJSON is the shape an operator configures: the business
// details a publisher wants before it opens an account. Written compactly and
// on one logical document so a test comparing served bytes against it does not
// have to normalize whitespace first.
const RegistrationSchemaJSON = `{"$schema":"https://json-schema.org/draft/2020-12/schema",` +
	`"type":"object",` +
	`"required":["company_name","billing_email"],` +
	`"properties":{` +
	`"company_name":{"type":"string","minLength":1},` +
	`"billing_email":{"type":"string","pattern":"^[^@]+@[^@]+$"},` +
	`"vat_id":{"type":"string"}}}`

// TermsURI and TermsDigest are the terms pair a configured Exchange publishes.
// The digest is the SHA-256 of the string "test", a real digest of a real input
// rather than a hand-typed run of hex, so a reader who doubts it can check it
// with `printf 'test' | shasum -a 256`.
//
// Nothing derives it: it is a literal, and every consumer reads this one
// constant rather than hashing "test" again. A wrong value here would therefore
// be wrong everywhere at once, which is the property worth having — the copies
// cannot disagree — and it is a reader running that command, not the suite,
// that would catch it.
const (
	TermsURI    = "https://exchange.example/terms/2026-04"
	TermsDigest = "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

// RevisedTermsDigest is a well-formed digest of a DIFFERENT terms revision: the
// SHA-256 of the single byte "b". It is what a test needs when it has to send or
// publish terms that are not the ones TermsDigest names — a stale digest at the
// Register gate, a manifest that changed under a reader that cached it.
//
// Derived here rather than written out, because unlike TermsDigest it had gone
// on to exist in three unconnected spellings: hashed in one test, typed as hex
// in another, and typed again in the e2e compose file. The two Go copies are now
// this one value. The compose file cannot import Go, so its literal stays and
// names the same preimage beside it.
var RevisedTermsDigest = revisedTermsDigest()

func revisedTermsDigest() string {
	sum := sha256.Sum256([]byte("b"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FullRegistration is the account_registration block a fully-published Exchange
// serves: this package's schema, its terms URI and the digest of that revision,
// together.
//
// A named value rather than the same three-field literal per test. Add a fourth
// member every published Exchange should carry and it is one edit here, not one
// per copy — and jscpd cannot help, because its minimum is twenty lines and each
// copy is five.
//
// A value rather than a function of a peer: it is these three constants whatever
// peer serves them, and taking a peer as an argument made call sites read as
// though the document were built from that peer. Someone staging two peers with
// different schemas would have passed the second and got this same document
// back, with nothing to say so.
//
// Tests that need a DIFFERENT document build their own literal rather than
// copying this one and editing a field — a revised terms digest and a
// schema-only manifest both say what they are by being written out.
var FullRegistration = rwtestutil.Registration{
	DataSchemaJSON: RegistrationSchemaJSON,
	TermsURI:       TermsURI,
	TermsDigest:    TermsDigest,
}

// RegistrationManifestMembers are the manifest members the three registration
// settings write. A deployment that configures none of them publishes none of
// these, which is the property "upgrading changes nothing" is asserted as.
var RegistrationManifestMembers = []string{"account_registration", "terms_uri", "terms_digest"}

// UnusableSchema is one way a configured registration schema can be one this
// Exchange could never enforce, with the verdict the SDK names it by.
//
// The type is NAMED, not anonymous, because a consumer that holds a row rather
// than only ranging over the table has to write the element type out — and three
// of them had. Anonymous struct types match structurally, so a fourth consumer
// declaring a narrower one would compile and silently drop a field.
type UnusableSchema struct {
	Name    string
	Raw     string
	Verdict string
}

// UnusableSchemas is the shared table. Every consumer of the loader drives it,
// so a sixth refusal is added once rather than in whichever copy the author
// happened to open.
var UnusableSchemas = []UnusableSchema{
	{"not JSON", "company_name is required", "malformed"},
	{"a JSON array rather than an object", `["company_name"]`, "malformed"},
	{"a reference leaving the document", `{"$ref":"https://attacker.example/schema.json"}`, "remote_ref"},
	{"an older dialect", `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`, "wrong_dialect"},
	{"over the size cap", oversizeSchema, "too_large"},
}

// oversizeSchema is a well-formed schema padded past the protocol's 16KB cap
// through its title, so the only rule it breaks is the size one.
var oversizeSchema = `{"type":"object","title":"` + strings.Repeat("x", 16<<10) + `"}`

// MalformedTermsDigest is one way a configured terms pair can be one the
// protocol refuses. Every consumer drives the shared table below, so a sixth
// refusal is added once rather than in whichever copy the author happened to
// open.
//
// The no-method case is derived from TermsDigest rather than written out again:
// spelled as its own hex literal it denotes the same value while a grep for
// either finds only one of the two, and re-pointing TermsDigest at another hash
// method would silently turn it into a different case.
type MalformedTermsDigest struct {
	Name   string
	URI    string
	Digest string
}

// MalformedTermsDigests is the shared table. Named element type for the same
// reason UnusableSchema is.
var MalformedTermsDigests = []MalformedTermsDigest{
	{"a digest with no URI", "", TermsDigest},
	{"a digest with no method", TermsURI, strings.TrimPrefix(TermsDigest, "sha256:")},
	{"a digest that is not hex", TermsURI, "sha256:not-hex"},
	{"a truncated digest", TermsURI, "sha256:9f86d081"},
	{"an unlisted hash method", TermsURI, "md5:9f86d081884c7d659a2feaa0c55ad015"},
}

// FetchManifest GETs the manifest served at baseURL and returns it parsed for
// role alongside the raw bytes, so a caller can assert on the published value
// AND on what the wire actually carried. It fails the test on any status other
// than 200 or on a document the protocol schema refuses, because a test that
// went on to assert against an unparsed body would report a missing member
// rather than a broken document.
func FetchManifest(tb testing.TB, baseURL string, role rampwellknown.Role) (*rampwellknown.Manifest, []byte) {
	tb.Helper()
	body := fetchOK(tb, baseURL+rampwellknown.Path)
	m, err := rampwellknown.ParseManifest(body, role)
	if err != nil {
		tb.Fatalf("served manifest invalid: %v", err)
	}
	return m, body
}

// fetchOK GETs url, drains and closes the body, and returns it, failing the
// test on a transport error or a non-200 status.
func fetchOK(tb testing.TB, url string) []byte {
	tb.Helper()
	ctx := tb.Context()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		tb.Fatalf("new request %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("get %s: %v", url, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			tb.Errorf("close body: %v", cerr)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		tb.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
	}
	return body
}

// AssertServedDataSchema compares the schema served in
// account_registration.data_schema against the JSON an operator configured.
// Both sides are decoded before they are compared, because the served form has
// been through protojson and the two texts differ in member order and spacing
// while naming the same document.
func AssertServedDataSchema(tb testing.TB, served *structpb.Struct, wantJSON string) {
	tb.Helper()
	if served == nil {
		tb.Fatal("account_registration.data_schema absent, want the configured schema")
	}
	got, err := served.MarshalJSON()
	if err != nil {
		tb.Fatalf("marshal the served schema: %v", err)
	}
	var gotDoc, want any
	if err := json.Unmarshal(got, &gotDoc); err != nil {
		tb.Fatalf("unmarshal the served schema: %v", err)
	}
	if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
		tb.Fatalf("unmarshal the configured schema: %v", err)
	}
	if !reflect.DeepEqual(gotDoc, want) {
		tb.Errorf("served data_schema = %s,\nwant %s", got, wantJSON)
	}
}

// AssertRegistrationMembersAbsent checks that a manifest built with none of the
// three registration settings publishes none of the members they write. This is
// the property "upgrading changes nothing for a deployment that configures
// nothing" is asserted as, so it reads the decoded wire document rather than
// the parsed message: a member present with a zero value would satisfy the
// getters and still change what an agent sees.
func AssertRegistrationMembersAbsent(tb testing.TB, doc map[string]any) {
	tb.Helper()
	for _, member := range RegistrationManifestMembers {
		if got, ok := doc[member]; ok {
			tb.Errorf("%s = %v in the served manifest, want absent", member, got)
		}
	}
}
