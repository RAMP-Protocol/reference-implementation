//go:build integration

package transport_test

// The shared license-term corpus, replayed through the Exchange.
//
// testdata/licenseterm-vectors.json is a verbatim copy of the SDK's own
// sdk/go/helpers/testdata/licenseterm-vectors.json (module
// github.com/RAMP-Protocol/protocol); internal/guards/licenseterm_vectors_test.go
// keeps the copy honest against the pinned module. The corpus records the
// verdict the SDK's client-side checks reach for every vector. This file proves
// the Exchange reaches the same verdict, observed only through the public RPCs:
//
//	write leg  PushResources RPC → validate interceptor (wire tier) → handler →
//	           CatalogService (SDK normalization, then the SDK ingest tier and
//	           the Exchange-owned gates) → repository → database
//	read leg   DiscoverResources RPC → catalog snapshot → offer count / Offer.terms
//
// Warnings and error details are read off the write leg's response; persistence
// — one offer for a stored entry, zero for a refused one — off the read leg. A
// protocol round-trip on both legs, with no database, repository or service
// access. The negative paths are the corpus's own refused vectors, each with
// the side effect's absence.
//
// Which column is compared, at which strength, per list:
//
//   - entry (all vectors, mandatory). ok → the push succeeds with accepted == 1,
//     PushResourcesResponse.warnings equals warnings[].message exactly and in
//     order, and the URI resolves to one offer when the entry has terms. ok=false
//     → InvalidArgument, zero offers, and WHICH tier refused: a vector recorded
//     with a structural or a cross-field column was refused at the wire, so its
//     buf.validate.Violations detail is classified with the descriptor's CEL id
//     set exactly as the corpus emitter classified the SDK's violations (the CEL
//     ids must equal cross_field_rules as a set; structural must equal "at least
//     one non-CEL id"); a vector recorded with only term_rules was refused at
//     the ingest tier, so it carries NO Violations detail and its message quotes
//     the SDK's violation message verbatim behind the invalid_license_terms
//     reason. The rule id itself is not wire-visible: the reason travels as a
//     string, so the id is asserted on the server's log line instead.
//   - normalize (all vectors), through push → discover on the harness's
//     default publisher: the discovered term must equal the recorded normalized
//     term (proto.Equal). Five vectors carry tokens the wire tier refuses
//     (padding, non-ASCII, a term without pricing); normalizeWireRefused names
//     each with the violation it must draw, and they assert the refusal instead.
//   - validate (all vectors), each wrapped in an entry on the default
//     publisher: violation present → InvalidArgument with its message verbatim
//     and no offer; else success with the warnings equal and in order, and one
//     offer. The vectors the wire tier takes first are named in
//     validateWireRefused, and one carries a token that is not canonical
//     (validateFoldedTokens).
//   - fold, known: not replayed here. No RPC exposes CanonicalRestrictionToken
//     or KnownRestrictionToken as such; their behaviour reaches the wire only as
//     the normalize list (the fold) and as warnings (membership), and the guard
//     replays both lists through the module.
//
// Every hand-written map in this file is checked against the corpus's vector names,
// so a renamed or deleted vector fails the test instead of leaving a stale
// expectation that silently stops applying. Nothing is skipped, and the test
// never calls the SDK to compute its own oracle.
//
// One fresh harness per vector, serial: the entry vectors share one URI, so an
// absolute zero-offer assertion after an accepted vector would still see the
// earlier row (re-push of a URI is an idempotent upsert). The harness hosts
// publisher.example as its default publisher and edge:8787 as a second hosted
// publisher, both real tenants with manifests; vector domains are never
// rewritten, since three vectors are about the domain.

import (
	"slices"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// licenseTermCorpusPath is the repo-root copy, relative to this package.
const licenseTermCorpusPath = "../../../../testdata/licenseterm-vectors.json"

// The two domains the corpus's accepted entries name, hosted as real tenants.
const (
	corpusPublisherDomain = "publisher.example"
	corpusEdgeDomain      = "edge:8787"
)

// aliasResolvedVector is the entry vector whose accepted term carries a
// FUNCTION alias ("Generative-AI"); its read leg proves the alias was resolved
// to the registered token before persistence.
const aliasResolvedVector = "alias_resolved_before_membership_no_warning"

// corpusHarness is a pushHarness hosting both corpus domains, with one admitted
// contributor signing every push.
type corpusHarness struct {
	*pushHarness
	callerID string
	client   rampconnect.CatalogServiceClient
	// tenants maps each hosted domain to its tenant id.
	tenants map[string]string
}

func newCorpusHarness(t *testing.T) *corpusHarness {
	t.Helper()
	h := newPushHarnessWith(t, pushHarnessOptions{publisherDomain: corpusPublisherDomain})
	const callerID = "caller.example"
	client := setupTermContributor(t, h, callerID)
	edge := h.addPublisher(t, corpusEdgeDomain, callerID)
	return &corpusHarness{
		pushHarness: h, callerID: callerID, client: client,
		tenants: map[string]string{corpusPublisherDomain: h.tenantID, corpusEdgeDomain: edge.tenantID},
	}
}

// push sends one entry under the tenant its domain resolves to. A vector whose
// domain is not a hosted tenant — the two structural-domain negatives — goes
// under the default publisher's tenant, so the envelope itself is valid and
// every violation on the wire is the entry's own.
func (c *corpusHarness) push(entry *rampv1.ResourceEntry) (*connect.Response[rampv1.PushResourcesResponse], error) {
	tenantID, ok := c.tenants[entry.GetDomain()]
	if !ok {
		tenantID = c.tenantID
	}
	req := newPushRequest(tenantID, c.callerID, []*rampv1.ResourceEntry{entry})
	return c.client.PushResources(c.ctx, connect.NewRequest(req))
}

// corpusURI is the catalog URI the Exchange materializes for an entry — the
// harness's scheme, the domain and the path — and so the URI the read leg
// probes. For a refused entry it is the URI that must resolve to no offer.
func corpusURI(entry *rampv1.ResourceEntry) string {
	return "https://" + entry.GetDomain() + entry.GetPath()
}

func decodeCorpusEntry(t *testing.T, name string, raw []byte) *rampv1.ResourceEntry {
	t.Helper()
	var entry rampv1.ResourceEntry
	if err := protojson.Unmarshal(raw, &entry); err != nil {
		t.Fatalf("%s: decode entry: %v", name, err)
	}
	return &entry
}

func decodeCorpusTerm(t *testing.T, name string, raw []byte) *rampv1.LicenseTerm {
	t.Helper()
	var term rampv1.LicenseTerm
	if err := protojson.Unmarshal(raw, &term); err != nil {
		t.Fatalf("%s: decode term: %v", name, err)
	}
	return &term
}

// termEntry wraps a term-list vector into an entry on the default publisher, at
// a path unique to the list and the vector.
func termEntry(list, name string, term *rampv1.LicenseTerm) *rampv1.ResourceEntry {
	return &rampv1.ResourceEntry{
		Domain: corpusPublisherDomain,
		Path:   "/corpus/" + list + "/" + name,
		Terms:  []*rampv1.LicenseTerm{term},
	}
}

// messagesOf projects findings onto the strings the RPC answers in warnings[].
func messagesOf(findings []testutil.LicenseTermFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Message)
	}
	return out
}

// vectorNames collects a list's vector names so hand-written expectations can
// be checked against them.
func vectorNames[T any](vectors []T, name func(T) string) map[string]bool {
	names := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		names[name(v)] = true
	}
	return names
}

// requireKeysNameVectors fails when a hand-written map names a vector the
// corpus does not have, so a renamed or deleted vector cannot leave behind an
// expectation that silently stops applying.
func requireKeysNameVectors[V any](t *testing.T, label string, m map[string]V, names map[string]bool) {
	t.Helper()
	for key := range m {
		if !names[key] {
			t.Fatalf("%s names vector %q, which the corpus does not have", label, key)
		}
	}
}

// acceptedPush checks the write leg of an accepting verdict — no error, one
// accepted entry — and returns the warnings the RPC answered.
func acceptedPush(t *testing.T, resp *connect.Response[rampv1.PushResourcesResponse], err error) []string {
	t.Helper()
	if err != nil {
		t.Fatalf("push refused, want accepted: %v", err)
	}
	if resp.Msg.GetAccepted() != 1 {
		t.Fatalf("accepted = %d, want 1", resp.Msg.GetAccepted())
	}
	return resp.Msg.GetWarnings()
}

// assertNoIngestReason checks that a refusal did not come from the ingest tier:
// the Exchange stops at the first tier that fails, so a wire-tier refusal never
// carries the ingest tier's reason.
func assertNoIngestReason(t *testing.T, err error) {
	t.Helper()
	if strings.Contains(err.Error(), service.RejectionReasonInvalidTerms) {
		t.Fatalf("a wire-tier refusal carries the ingest-tier reason %q, so the ingest tier ran: %v",
			service.RejectionReasonInvalidTerms, err)
	}
}

// wireRefusal names why the wire tier refuses a term-list vector and one
// violation the validate interceptor must attach for it — the field path as
// testutil.ViolationFieldPath renders it and protovalidate's rule id — so the
// test proves WHICH tier refused, not only that something did.
type wireRefusal struct {
	field, rule, why string
}

// assertWireRefusal checks a wire-tier refusal through the RPC: InvalidArgument,
// the named violation in the Violations detail, no ingest-tier reason in the
// message, and no offer for the URI.
func assertWireRefusal(t *testing.T, c *corpusHarness, uri string, err error, want wireRefusal) {
	t.Helper()
	t.Logf("wire tier refuses this vector: %s", want.why)
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertWireViolation(t, err, want.field, want.rule)
	assertNoIngestReason(t, err)
	assertOfferCount(t, c.pushHarness, uri, 0)
}

// assertIngestTierRefusal checks an ingest-tier refusal through the RPC: no
// Violations detail (the wire tier admitted the request), InvalidArgument with
// the SDK's message behind the invalid_license_terms reason for the entry's URI
// and the server's Warn line naming rule, entry-relative path and token
// (assertIngestRefusal), and no offer. want.Path is entry-relative.
func assertIngestTierRefusal(
	t *testing.T, c *corpusHarness, entry *rampv1.ResourceEntry, err error, want testutil.LicenseTermFinding,
) {
	t.Helper()
	if entry.GetDomain() != c.publisherDom {
		t.Fatalf("ingest-tier vector on %q; the log assertion keys on the default publisher %q",
			entry.GetDomain(), c.publisherDom)
	}
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if violations := testutil.ValidationViolations(t, err); len(violations) != 0 {
		t.Fatalf("the wire tier attached %d violation(s) to what the corpus records as an ingest-tier refusal: %v",
			len(violations), err)
	}
	assertIngestRefusal(t, c.pushHarness, entry.GetPath(), err,
		ingestRefusal{rule: want.Rule, path: want.Path, token: want.Token, detail: want.Message})
	assertOfferCount(t, c.pushHarness, corpusURI(entry), 0)
}

// TestPushResources_CorpusEntry replays the entry list: the composed verdict,
// both tiers in the Exchange's order.
func TestPushResources_CorpusEntry(t *testing.T) {
	corpus := testutil.LoadLicenseTermCorpus(t, licenseTermCorpusPath)
	names := vectorNames(corpus.Entry, func(v testutil.LicenseTermEntryVector) string { return v.Name })
	if !names[aliasResolvedVector] {
		t.Fatalf("the corpus has no entry vector %q; the alias-resolution read leg would never run", aliasResolvedVector)
	}
	for _, v := range corpus.Entry {
		t.Run(v.Name, func(t *testing.T) {
			c := newCorpusHarness(t)
			entry := decodeCorpusEntry(t, v.Name, v.Entry)
			resp, err := c.push(entry)
			if !v.OK {
				assertEntryRefused(t, c, entry, err, v)
				return
			}
			assertStrs(t, "warnings", acceptedPush(t, resp, err), messagesOf(v.Warnings))
			assertEntryStored(t, c, entry, v.Name)
		})
	}
}

// assertEntryStored is the read leg for an accepted entry vector. A term-less
// entry (no_terms_accepted) has no public read surface: DiscoverResources
// projects an offer only from a priced term, so a stored row without terms and
// a row that was never stored both resolve to zero offers. The RPC verdict is
// the whole observable there. That absence is a design signal, not something
// this test papers over by reading past the RPC.
func assertEntryStored(t *testing.T, c *corpusHarness, entry *rampv1.ResourceEntry, name string) {
	t.Helper()
	if len(entry.GetTerms()) == 0 {
		return
	}
	uri := corpusURI(entry)
	assertOfferCount(t, c.pushHarness, uri, 1)
	if name != aliasResolvedVector {
		return
	}
	// "Generative-AI" is a FUNCTION alias of the registered token "ai-input"
	// (the corpus's normalize list records the same resolution for the
	// lower-case spelling). The persisted, discoverable term must carry the
	// registered token, which is also why the vector records no warning.
	terms := discoverTerms(t, c.pushHarness, uri)
	if len(terms) != 1 || len(terms[0].GetRestrictions()) != 1 {
		t.Fatalf("discovered terms = %v, want the one term with its one restriction", terms)
	}
	assertStrs(t, "canonical tokens", terms[0].GetRestrictions()[0].GetPermitted(), []string{"ai-input"})
}

// assertEntryRefused checks a refused entry vector: InvalidArgument, zero
// offers, and the tier the corpus recorded. A vector with a structural or a
// cross-field column set was refused at the wire (assertEntryWireTier); a
// vector with only term_rules was refused at the ingest tier.
//
// The Exchange stops at the first tier that fails, so a vector recorded with
// both a wire violation and a term rule proves only the wire tier here; the
// SDK's entry face reports both so a publisher fixes both in one round. Two
// vectors are that shape. structural_and_term_reject_both_reported carries a
// wire fault and a term reject on unrelated fields. In
// cross_field_restriction_permitted_prohibited_overlap the two findings are the
// same collision read twice: one token written identically in both lists fails
// the wire rule, which compares the tokens as received, and the ingest tier's
// rule, which compares what the fold produced. For
// the same reason the warnings a refused vector records
// (term_reject_drops_that_terms_warnings) are not wire-observable: a refused
// push answers an error, never warnings.
func assertEntryRefused(
	t *testing.T, c *corpusHarness, entry *rampv1.ResourceEntry, err error, v testutil.LicenseTermEntryVector,
) {
	t.Helper()
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if v.Structural || len(v.CrossFieldRules) > 0 {
		assertEntryWireTier(t, err, v)
	} else {
		if len(v.TermRules) == 0 {
			t.Fatalf("%s: refused with no structural, cross-field or term rule recorded", v.Name)
		}
		// The Exchange reports the first hard violation per entry, in term
		// order — the order the SDK's entry face records them in.
		assertIngestTierRefusal(t, c, entry, err, v.TermRules[0])
	}
	assertOfferCount(t, c.pushHarness, corpusURI(entry), 0)
}

// assertEntryWireTier attributes a refusal to the wire tier by classifying the
// Violations detail with the descriptor's CEL id set, exactly as the corpus
// emitter classified the SDK's violations: the CEL ids must equal
// cross_field_rules as a set, and structural must equal "at least one non-CEL
// id". The message must not carry the ingest-tier reason.
//
// Reading the detail is what makes the attribution real. Every tier answers
// InvalidArgument with zero offers, so without it a cross-field rule that had
// dropped off the wire and been caught by a later gate — or never caught, with
// the entry stored — would read the same as the wire refusal.
func assertEntryWireTier(t *testing.T, err error, v testutil.LicenseTermEntryVector) {
	t.Helper()
	celIDs := testutil.CrossFieldRuleIDs(t)
	var gotCEL []string
	structural := false
	for _, viol := range testutil.ValidationViolations(t, err) {
		if celIDs[viol.GetRuleId()] {
			gotCEL = append(gotCEL, viol.GetRuleId())
		} else {
			structural = true
		}
	}
	slices.Sort(gotCEL)
	wantCEL := slices.Clone(v.CrossFieldRules)
	slices.Sort(wantCEL)
	if !slices.Equal(gotCEL, wantCEL) {
		t.Errorf("%s: cross-field rule ids on the wire = %v, want %v (err=%v)", v.Name, gotCEL, wantCEL, err)
	}
	if structural != v.Structural {
		t.Errorf("%s: structural (a field-level wire violation) = %v, want %v (err=%v)", v.Name, structural, v.Structural, err)
	}
	assertNoIngestReason(t, err)
}

// normalizeWireRefused names the normalize vectors the wire tier refuses, and
// why. The corpus records what NormalizeLicenseTerm makes of them; through the
// RPC the validate interceptor refuses them first, because the restriction
// token pattern admits only clean ASCII and a term must carry pricing.
var normalizeWireRefused = map[string]wireRefusal{
	"function_mixed_case_padding": {
		field: "entries[0].terms[0].restrictions[0].permitted[0]", rule: "string.pattern",
		why: `"  Generative-AI " is padded; the token pattern refuses whitespace before the fold could trim it`,
	},
	"geography_upper": {
		field: "entries[0].terms[0].restrictions[0].permitted[1]", rule: "string.pattern",
		why: `" de " is padded; the three tokens beside it are wire-clean`,
	},
	"other_untouched": {
		field: "entries[0].terms[0].restrictions[0].permitted[1]", rule: "string.pattern",
		why: `"  Spaced  " is padded; an OTHER token is never trimmed, so it would have stayed padded anyway`,
	},
	"non_ascii_untouched": {
		field: "entries[0].terms[0].restrictions[0].permitted[0]", rule: "string.pattern",
		why: "the KELVIN SIGN is outside the ASCII token alphabet; the NBSP-padded second token is refused too",
	},
	"empty_term": {
		field: "entries[0].terms[0].pricing", rule: "required",
		why: "a term without pricing (and with unspecified semantics) never reaches the fold, which has nothing to touch in it",
	},
}

// TestPushResources_CorpusNormalize replays the normalize list through push →
// discover: the term DiscoverResources projects must equal the recorded
// normalized term. The requester holds the global scope so a scoped vector
// (three_axes_at_once) projects too. Warnings are not compared here: the
// normalize list records none, and a normalized term's warnings are the
// validate list's subject.
func TestPushResources_CorpusNormalize(t *testing.T) {
	corpus := testutil.LoadLicenseTermCorpus(t, licenseTermCorpusPath)
	names := vectorNames(corpus.Normalize, func(v testutil.LicenseTermNormalizeVector) string { return v.Name })
	requireKeysNameVectors(t, "normalizeWireRefused", normalizeWireRefused, names)
	for _, v := range corpus.Normalize {
		t.Run(v.Name, func(t *testing.T) {
			c := newCorpusHarness(t)
			entry := termEntry("normalize", v.Name, decodeCorpusTerm(t, v.Name, v.Term))
			resp, err := c.push(entry)
			if refusal, ok := normalizeWireRefused[v.Name]; ok {
				assertWireRefusal(t, c, corpusURI(entry), err, refusal)
				return
			}
			acceptedPush(t, resp, err)
			want := decodeCorpusTerm(t, v.Name, v.Normalized)
			got := discoverTermsAs(t, c.pushHarness, corpusURI(entry), requesterWithScopes("agent-discover", "*"))
			if len(got) != 1 || !proto.Equal(got[0], want) {
				t.Fatalf("discovered terms = %v, want the one normalized term %v", got, want)
			}
		})
	}
}

// validateWireRefused names the validate vectors the wire tier refuses, and why.
// The corpus records the per-term face's verdict, which checks only registry
// membership; through the RPC the validate interceptor runs first.
var validateWireRefused = map[string]wireRefusal{
	"pricing_unit_uppercase_rejected": {
		field: "entries[0].terms[0].pricing.unit", rule: "string.pattern",
		why: `"TOKENS" fails the bare-unit pattern, which admits lower case only; the membership check the corpus records never runs`,
	},
	"empty_term_accepted": {
		field: "entries[0].terms[0].pricing", rule: "required",
		why: "the per-term face accepts an empty term (nothing to membership-check); the wire requires pricing and a specified semantics",
	},
	"unregistered_token_without_kind_names_the_unset_enum": {
		field: "entries[0].terms[0].restrictions[0].kind", rule: "enum.not_in",
		why: "the restriction names no axis, so kind is the unspecified zero; the per-term face still membership-checks the token and warns, while the wire refuses an unset axis outright",
	},
	"restriction_padded_token_collides_after_trim_rejected": {
		field: "entries[0].terms[0].restrictions[0].permitted[0]", rule: "string.pattern",
		why: `" crawl " carries whitespace, which the restriction token pattern does not admit, so the wire refuses it before the fold could trim it into the collision the per-term face records`,
	},
	"restriction_other_axis_exact_duplicate_rejected": {
		field: "entries[0].terms[0].restrictions[0]", rule: "restriction.permitted_prohibited_disjoint",
		why: `"custom-use" is written identically in both lists, so the wire tier's own disjointness rule — which compares the tokens as received — catches it first; the per-term face records the same collision read on the canonical tokens`,
	},
}

// validateFoldedTokens names the validate vectors whose term is not already
// canonical, with the fold the Exchange applies before the membership check.
// The corpus's validate list records ValidateLicenseTerm over the term AS
// WRITTEN, so such a vector records the raw spelling in its warning, while the
// Exchange, which canonicalizes first, warns about the canonical one:
// warnings_in_report_order lists the GEOGRAPHY token "usa", which the fold
// upper-cases to "USA" (still unregistered — three letters is not an alpha-2
// code). warningsThroughExchange requires the raw spelling to be present in the
// corpus's warnings, so a corpus refresh that canonicalizes the vector fails
// the test and this entry is deleted with it.
var validateFoldedTokens = map[string]map[string]string{
	"warnings_in_report_order": {"usa": "USA"},
}

// warningsThroughExchange returns the warning strings the Exchange answers for
// an accepted validate vector: the corpus's messages, with a token
// validateFoldedTokens names rewritten to its canonical spelling.
func warningsThroughExchange(t *testing.T, v testutil.LicenseTermValidateVector) []string {
	t.Helper()
	want := messagesOf(v.Warnings)
	for raw, canonical := range validateFoldedTokens[v.Name] {
		rawQuoted, canonicalQuoted := `"`+raw+`"`, `"`+canonical+`"`
		replaced := false
		for i, msg := range want {
			if strings.Contains(msg, rawQuoted) {
				want[i] = strings.ReplaceAll(msg, rawQuoted, canonicalQuoted)
				replaced = true
			}
		}
		if !replaced {
			t.Fatalf("%s: validateFoldedTokens names %q, but no corpus warning quotes it; "+
				"the vector may have been canonicalized upstream, in which case the entry goes", v.Name, raw)
		}
	}
	return want
}

// TestPushResources_CorpusValidate replays the validate list, each term wrapped
// in an entry on the default publisher: the ingest-tier hard reject with its
// message verbatim, or the accepted term's warnings and its offer.
func TestPushResources_CorpusValidate(t *testing.T) {
	corpus := testutil.LoadLicenseTermCorpus(t, licenseTermCorpusPath)
	names := vectorNames(corpus.Validate, func(v testutil.LicenseTermValidateVector) string { return v.Name })
	requireKeysNameVectors(t, "validateWireRefused", validateWireRefused, names)
	requireKeysNameVectors(t, "validateFoldedTokens", validateFoldedTokens, names)
	for _, v := range corpus.Validate {
		t.Run(v.Name, func(t *testing.T) {
			c := newCorpusHarness(t)
			entry := termEntry("validate", v.Name, decodeCorpusTerm(t, v.Name, v.Term))
			resp, err := c.push(entry)
			if refusal, ok := validateWireRefused[v.Name]; ok {
				assertWireRefusal(t, c, corpusURI(entry), err, refusal)
				return
			}
			if v.Violation != nil {
				// The corpus path is term-relative; the server logs it
				// entry-relative, as the SDK's entry face reports it.
				want := *v.Violation
				want.Path = "terms[0]." + want.Path
				assertIngestTierRefusal(t, c, entry, err, want)
				return
			}
			assertStrs(t, "warnings", acceptedPush(t, resp, err), warningsThroughExchange(t, v))
			assertOfferCount(t, c.pushHarness, corpusURI(entry), 1)
		})
	}
}
