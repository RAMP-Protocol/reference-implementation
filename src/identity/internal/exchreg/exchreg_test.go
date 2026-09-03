package exchreg_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchreg"
)

func newReader(t *testing.T) *exchreg.Reader {
	t.Helper()
	r, err := exchreg.New(exchreg.Config{Fetch: rwtestutil.Client(), Scheme: "http"})
	if err != nil {
		t.Fatalf("exchreg.New: %v", err)
	}
	return r
}

// exchangeServing starts an origin publishing an Exchange manifest with reg.
func exchangeServing(t *testing.T, reg rwtestutil.Registration) *rwtestutil.Origin {
	t.Helper()
	origin := rwtestutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	origin.SetManifest(rwtestutil.ExchangeManifestWithRegistration(
		"exchange.example", origin.URL, reg))
	return origin
}

// TestRequirements_ReadsThePublishedSchemaAndTerms is the happy path: what the
// Exchange published is what the adapter will hold the payload to, and the
// digest it will echo.
func TestRequirements_ReadsThePublishedSchemaAndTerms(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, testutil.FullRegistration)

	reqs, err := newReader(t).Requirements(context.Background(), origin.Host())
	if err != nil {
		t.Fatalf("Requirements: %v", err)
	}
	if reqs.Verdict != helpers.SchemaAccepted || reqs.Schema == nil {
		t.Fatalf("verdict=%s schema=%v", reqs.Verdict, reqs.Schema)
	}
	if reqs.TermsDigest == nil || *reqs.TermsDigest != testutil.TermsDigest {
		t.Fatalf("terms digest = %v, want %q", reqs.TermsDigest, testutil.TermsDigest)
	}
	// The compiled validator is the published one, not a permissive stand-in:
	// a payload missing a required member is reported, naming that member.
	failures := reqs.Schema.Validate(map[string]any{"vat_id": "DE1"})
	if len(failures) == 0 {
		t.Fatal("the compiled schema accepted a payload missing every required member")
	}
	// Both halves are searched, because which one names the member depends on
	// the keyword: a `required` violation is reported against the containing
	// object with the member in the constraint text, while a `pattern` violation
	// is reported at the member's own pointer.
	reported := make([]string, 0, len(failures))
	for _, f := range failures {
		reported = append(reported, f.GetPath()+" "+f.GetError())
	}
	joined := strings.Join(reported, " | ")
	for _, want := range []string{"company_name", "billing_email"} {
		if !strings.Contains(joined, want) {
			t.Errorf("failures %q do not name %q", joined, want)
		}
	}
}

// TestRequirements_NoSchemaIsTheNormalPassThroughState pins that an Exchange
// publishing nothing is not an error and not a refusal. It is the state every
// Exchange was in before the block existed, and the contract for it is that
// registration_data passes through uninspected.
func TestRequirements_NoSchemaIsTheNormalPassThroughState(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, rwtestutil.Registration{})

	reqs, err := newReader(t).Requirements(context.Background(), origin.Host())
	if err != nil {
		t.Fatalf("Requirements: %v", err)
	}
	if reqs.Verdict != helpers.SchemaNotPublished {
		t.Fatalf("verdict = %s, want not_published", reqs.Verdict)
	}
	if reqs.Schema != nil || reqs.SchemaRefused() {
		t.Fatalf("schema=%v refused=%t, want neither", reqs.Schema, reqs.SchemaRefused())
	}
	if reqs.TermsDigest != nil {
		t.Fatalf("terms digest = %v, want absent", *reqs.TermsDigest)
	}
	// The nil validator is what the caller will run, so it is the thing under
	// test: it must report no failures rather than panic or refuse. That is what
	// lets the register path stay branch-free.
	if failures := reqs.Schema.Validate(map[string]any{"anything": "at all"}); len(failures) != 0 {
		t.Fatalf("an unpublished schema reported %d failures", len(failures))
	}
}

// TestRequirements_AnUnusableSchemaIsNotALocalVeto is the rule that matters most
// here. A schema this adapter cannot compile is reported with its verdict and
// leaves a nil validator, so the registration still goes to the Exchange. An
// adapter that refused instead would block a registration the Exchange would
// have accepted, and the agent would have no way past it.
//
// It drives the shared refusal table, minus the rows a manifest cannot carry —
// see servableSchemas for which and why.
func TestRequirements_AnUnusableSchemaIsNotALocalVeto(t *testing.T) {
	t.Parallel()
	for _, tc := range servableSchemas(t) {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			origin := exchangeServing(t, rwtestutil.Registration{DataSchemaJSON: tc.Raw})

			reqs, err := newReader(t).Requirements(context.Background(), origin.Host())
			if err != nil {
				t.Fatalf("Requirements: %v", err)
			}
			if reqs.Verdict.String() != tc.Verdict {
				t.Fatalf("verdict = %s, want %s", reqs.Verdict, tc.Verdict)
			}
			if reqs.Schema != nil {
				t.Fatal("a refused schema left a usable validator")
			}
			if !reqs.SchemaRefused() {
				t.Fatal("a refused schema does not report as refused, so nothing would log it")
			}
			if failures := reqs.Schema.Validate(map[string]any{"x": 1}); len(failures) != 0 {
				t.Fatalf("a refused schema vetoed a payload locally (%d failures)", len(failures))
			}
		})
	}
}

// TestRequirements_ReadsTheOriginEveryTime is the protocol's freshness rule
// under test: a registering client reads the terms digest from a freshly fetched
// manifest, never from a cache. A cached digest cannot be checked for staleness
// locally, so a warm cache would make the agent echo a refused value and retry
// the same refusal until the cache expired.
func TestRequirements_ReadsTheOriginEveryTime(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, testutil.FullRegistration)
	reader := newReader(t)
	ctx := context.Background()

	if _, err := reader.Requirements(ctx, origin.Host()); err != nil {
		t.Fatalf("first Requirements: %v", err)
	}
	if got := origin.Hits(); got != 1 {
		t.Fatalf("first read made %d origin fetches, want 1", got)
	}

	// The Exchange revises its terms. Nothing tells the adapter, which is the
	// whole reason the read is not cached.
	// The shared revised-terms fixture: a real digest of a different input from
	// the one testutil.TermsDigest names, so this reads as a genuine new revision
	// rather than an edited copy of the old one.
	revised := testutil.RevisedTermsDigest
	origin.SetManifest(rwtestutil.ExchangeManifestWithRegistration("exchange.example", origin.URL,
		rwtestutil.Registration{
			DataSchemaJSON: testutil.RegistrationSchemaJSON,
			TermsURI:       testutil.TermsURI,
			TermsDigest:    revised,
		}))

	reqs, err := reader.Requirements(ctx, origin.Host())
	if err != nil {
		t.Fatalf("second Requirements: %v", err)
	}
	if got := origin.Hits(); got != 2 {
		t.Fatalf("second read made %d origin fetches in total, want 2", got)
	}
	if reqs.TermsDigest == nil || *reqs.TermsDigest != revised {
		t.Fatalf("terms digest = %v, want the revised %q", reqs.TermsDigest, revised)
	}
}

// TestRequirements_CompilesOneDocumentOnce pins the memo. The fetch repeats
// because the protocol requires it; the compile does not, because the key is
// the document's own bytes — a hit means the schema has not changed, not that
// nobody looked.
func TestRequirements_CompilesOneDocumentOnce(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, rwtestutil.Registration{DataSchemaJSON: testutil.RegistrationSchemaJSON})
	reader := newReader(t)
	ctx := context.Background()

	first, err := reader.Requirements(ctx, origin.Host())
	if err != nil {
		t.Fatalf("first Requirements: %v", err)
	}
	second, err := reader.Requirements(ctx, origin.Host())
	if err != nil {
		t.Fatalf("second Requirements: %v", err)
	}
	if origin.Hits() != 2 {
		t.Fatalf("made %d origin fetches, want 2 — the fetch is never memoized", origin.Hits())
	}
	// Same pointer means the same compiled value was handed back, which is the
	// only externally visible evidence that the compile did not run twice.
	if first.Schema != second.Schema {
		t.Fatal("the same served schema was compiled twice")
	}
}

// TestRequirements_RefusesADocumentThatIsNotAnExchange pins the role assertion.
// An agent naming a publisher's domain would otherwise have that publisher's
// manifest read for members it has no business publishing.
func TestRequirements_RefusesADocumentThatIsNotAnExchange(t *testing.T) {
	t.Parallel()
	origin := rwtestutil.NewOrigin(rwtestutil.MarshalManifest(
		rwtestutil.Manifest(rampwellknown.RolePublisher, "publisher.example")))
	defer origin.Close()

	_, err := newReader(t).Requirements(context.Background(), origin.Host())
	if !errors.Is(err, rampwellknown.ErrRoleMismatch) {
		t.Fatalf("want ErrRoleMismatch, got %v", err)
	}
}

// TestRequirements_AnAbsentManifestIsReported pins that an Exchange serving no
// manifest fails the read rather than reading as "asks for nothing". Without a
// manifest there is no terms digest to echo, and a registration that states no
// terms revision is one no later dispute can resolve.
func TestRequirements_AnAbsentManifestIsReported(t *testing.T) {
	t.Parallel()
	origin := rwtestutil.NewOrigin(nil)
	defer origin.Close()
	origin.SetManifestStatus(404)

	_, err := newReader(t).Requirements(context.Background(), origin.Host())
	if !errors.Is(err, rampwellknown.ErrNoDocument) {
		t.Fatalf("want ErrNoDocument, got %v", err)
	}
}

// TestNew_RequiresAnInjectedClient pins the fail-loud. The SSRF-guarded client
// is built once at the composition root; a package-level default here would be
// a second reading of the SSRF environment, and a nil one would dial a
// caller-named host unguarded.
func TestNew_RequiresAnInjectedClient(t *testing.T) {
	t.Parallel()
	if _, err := exchreg.New(exchreg.Config{}); err == nil {
		t.Fatal("New accepted a nil Client")
	}
	if _, err := exchreg.New(exchreg.Config{
		Fetch: rwtestutil.Client(), CacheSize: -1,
	}); err == nil {
		t.Fatal("New accepted a negative CacheSize")
	}
}

// servableSchemas is the shared refusal table narrowed to the rows a MANIFEST
// can actually carry.
//
// The table describes what an operator can configure on the Exchange, which is
// a raw string. What reaches this adapter has already been through the wire:
// data_schema is a google.protobuf.Struct, so a served document always holds a
// JSON object there. The two "malformed" rows — bytes that are not JSON, and a
// JSON array — describe a configuration mistake that can never appear in a
// manifest, so exercising them here would assert against input this code path
// cannot receive.
//
// The excluded set is named rather than filtered silently: a row added to the
// shared table that IS servable must reach this test, and a filter that only
// said "skip what does not parse" would swallow it.
func servableSchemas(t *testing.T) []testutil.UnusableSchema {
	t.Helper()
	unservable := map[string]bool{
		"not JSON":                           true,
		"a JSON array rather than an object": true,
	}
	var out []testutil.UnusableSchema
	for _, tc := range testutil.UnusableSchemas {
		if !unservable[tc.Name] {
			out = append(out, tc)
			continue
		}
		// The exclusion is a claim about the row, so it is checked rather than
		// trusted: a row named here that a Struct WOULD accept is one this test
		// is skipping for a reason that stopped being true.
		var obj map[string]any
		if err := json.Unmarshal([]byte(tc.Raw), &obj); err == nil {
			t.Fatalf("%q is excluded as unservable but decodes as a JSON object, so a manifest can carry it", tc.Name)
		}
		delete(unservable, tc.Name)
	}
	for name := range unservable {
		t.Fatalf("%q is excluded as unservable but is no longer in the shared table", name)
	}
	return out
}

// TestRequirements_RefusesADomainThePolicyExcludes pins the policy where it is
// structural rather than where it is readable.
//
// This is the one Exchange-facing leg that dials without going through an
// endpoint resolver, so the resolver's overlay — which the composition root
// relies on to make the deployment's Exchange policy unavoidable — never sees
// it. The tool layer checks the same thing before calling here, and that check
// is what gives an agent a sentence naming the policy; this is what makes the
// rule hold for a caller that does not run it.
//
// Asserted on the origin's hit count as well as the error: refusing after the
// fetch would already have dialled the excluded host, which is the whole thing
// the policy exists to prevent.
func TestRequirements_RefusesADomainThePolicyExcludes(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, testutil.FullRegistration)
	reader, err := exchreg.New(exchreg.Config{
		Fetch:  rwtestutil.Client(),
		Scheme: "http",
		Allow:  func(string) bool { return false },
	})
	if err != nil {
		t.Fatalf("exchreg.New: %v", err)
	}

	if _, err = reader.Requirements(context.Background(), origin.Host()); err == nil {
		t.Fatal("an excluded domain's requirements were read")
	}
	if !errors.Is(err, account.ErrNotPermitted) {
		t.Errorf("err = %v, want ErrNotPermitted so a caller can tell a policy refusal from an outage", err)
	}
	if got := origin.Hits(); got != 0 {
		t.Errorf("the excluded origin was fetched %d times; the refusal must precede the dial", got)
	}
}

// TestRequirements_RefusesAValueThatIsNotABareDomain drives the shape rule at
// the layer that owns it, rather than at the tool that also states it.
//
// This is the one outbound leg with no endpoint resolver under it, so the shape
// rule is the only thing standing between a caller's value and a URL built by
// concatenation.
//
// TWO ASSERTIONS, and they cover different halves of the table. Nine of its
// fifteen cases decorate the host the fixture is really serving, so a refusal
// there cannot be mistaken for "nothing was listening" and the hit count is what
// proves the refusal came BEFORE the dial rather than after it. The other six
// carry their own literal and ignore the host they are given, so nothing they
// name is the fixture and its counter cannot move either way — for those the
// count proves nothing, and the sentinel is the whole assertion.
//
// Both are run over every case rather than split, because which half a case
// falls in is a property of the shared table and would go stale here the moment
// an entry changed shape.
func TestRequirements_RefusesAValueThatIsNotABareDomain(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, testutil.FullRegistration)
	reader := newReader(t)

	for _, tc := range testutil.NonBareDomains {
		t.Run(tc.Name, func(t *testing.T) {
			before := origin.Hits()
			_, err := reader.Requirements(context.Background(), tc.Of(origin.Host()))
			if err == nil {
				t.Fatalf("%q was read as an Exchange domain", tc.Of(origin.Host()))
			}
			if !errors.Is(err, account.ErrNotBareDomain) {
				t.Errorf("err = %v, want ErrNotBareDomain so a caller can tell a refused "+
					"argument from a peer that would not answer", err)
			}
			if got := origin.Hits(); got != before {
				t.Errorf("the origin was fetched %d times; the refusal must precede the dial",
					got-before)
			}
		})
	}
}

// TestRequirements_ANilPolicyPermitsEveryDomain pins the unset case, which is
// what CONFIGURATION documents as normal. A nil Allow must read like an
// allowlist nobody set, not like one that excludes everything.
func TestRequirements_ANilPolicyPermitsEveryDomain(t *testing.T) {
	t.Parallel()
	origin := exchangeServing(t, testutil.FullRegistration)

	if _, err := newReader(t).Requirements(context.Background(), origin.Host()); err != nil {
		t.Fatalf("an unset policy refused %s: %v", origin.Host(), err)
	}
}
