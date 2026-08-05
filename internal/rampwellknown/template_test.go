package rampwellknown_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// The two files under deploy/publisher-wellknown/ are the reference copies of
// the discovery documents the Edge Worker serves. The edge suite pins them to
// the PRODUCER — it drives template-env.json, the checked-in variable values that
// sit beside them, through parseEnv and buildDeps, requests both addresses
// through the Worker's own routes, and
// asserts each response body is deep-equal to the file on disk. This file pins
// the same templates to the CONSUMER, which is a different check: the Exchange
// does not run Ajv, it runs ParseManifest / ParseWBA, and those schema-validate
// AND protojson-decode into the proto messages. A template can satisfy the JSON
// Schema and still fail the decode the Exchange actually performs.
//
// The exchange domain the template's own exchanges[] entry names. The payee
// lookup matches on this string exactly, so a template that renamed it would
// hand operators an example whose payee the Exchange could never find.
const templateExchangeDomain = "exchange.example"

// The contributor the template authorizes, and the publisher that serves it.
const (
	templatePublisherDomain   = "www.publisher.example"
	templateContributorDomain = "catalog-contributor.example"
)

func readTemplate(tb testing.TB, name string) []byte {
	tb.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "publisher-wellknown", name))
	if err != nil {
		tb.Fatalf("read template %s: %v", name, err)
	}
	return raw
}

func TestTemplateManifestParsesThroughTheConsumerPath(t *testing.T) {
	t.Parallel()
	// ParseManifest is the whole consumer path in one call: schema validation,
	// protojson decode, and the role assertion. RolePublisher is passed because a
	// publisher template that decoded as any other role would be silently useless.
	m, err := rampwellknown.ParseManifest(readTemplate(t, "ramp.json.example"), rampwellknown.RolePublisher)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if got := m.GetDomain(); got != templatePublisherDomain {
		t.Errorf("domain = %q, want %q", got, templatePublisherDomain)
	}
	if got := m.GetVer(); got != rampwellknown.Version {
		t.Errorf("ver = %q, want %q", got, rampwellknown.Version)
	}
	if got := len(m.GetExchanges()); got != 1 {
		t.Fatalf("exchanges = %d, want 1", got)
	}
	if got := m.GetExchanges()[0].GetDomain(); got != templateExchangeDomain {
		t.Errorf("exchanges[0].domain = %q, want %q", got, templateExchangeDomain)
	}
}

func TestTemplateManifestAttestsAPayeeForItsExchange(t *testing.T) {
	t.Parallel()
	// Making ext.resource_owner_id visible before a deployment is the reason the
	// template exists. Without it every catalog push for the publisher is rejected
	// with missing_resource_owner_id, while the Worker looks healthy and serves the
	// document without complaint. ResourceOwnerID is the accessor the Exchange
	// calls, so the template is checked through it rather than by reading ext.
	m, err := rampwellknown.ParseManifest(readTemplate(t, "ramp.json.example"), rampwellknown.RolePublisher)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	owner, ok := rampwellknown.ResourceOwnerID(m, templateExchangeDomain)
	if !ok {
		t.Fatalf("ResourceOwnerID(%q) reports no attested payee", templateExchangeDomain)
	}
	// Non-empty is the ONLY thing the Exchange checks, which is exactly why the
	// template must not carry a value that reads like a real id. A wrong payee is
	// accepted, written to the catalog row, and used as the revenue payee at
	// settlement, so an operator who deploys a realistic-looking placeholder sells
	// content under an account the Exchange operator does not recognise. Keeping
	// the value visibly unfilled is what forces them to replace it.
	if !strings.HasPrefix(owner, "<") {
		t.Errorf("attested payee is %q; the template must carry a value no operator "+
			"could mistake for a real payee id, because the Exchange accepts any "+
			"non-empty string here and never validates it", owner)
	}
	// The lookup matches the exchange domain exactly, with no folding. A template
	// whose entry named a different host would pass the check above and still
	// leave a real deployment with no payee.
	if _, found := rampwellknown.ResourceOwnerID(m, "other-exchange.example"); found {
		t.Error("a payee was found for an exchange the template does not name")
	}
}

func TestTemplateManifestAuthorizesThePublisherAndItsContributor(t *testing.T) {
	t.Parallel()
	// The README tells operators that the publisher's own domain is authorized to
	// push its own catalog without appearing in catalog_contributors, and that the
	// list is for other parties. That is a claim about behaviour, so it is pinned
	// here against the template the README describes.
	//
	// agentid.FromDirectory is the rule the Exchange passes in production, so the
	// template's hosts are checked under the same folding an operator's deployment
	// will apply to them. A rule that folded nothing would reduce these three
	// assertions to string comparison and pass for a template value the Exchange
	// refuses — every push rejected as not_in_contributors while the Worker starts
	// cleanly and serves the document.
	m, err := rampwellknown.ParseManifest(readTemplate(t, "ramp.json.example"), rampwellknown.RolePublisher)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	for _, c := range m.GetCatalogContributors() {
		if c.GetDomain() == templatePublisherDomain {
			t.Fatalf("template lists the publisher %q as its own contributor; "+
				"the entry is redundant and contradicts the README", templatePublisherDomain)
		}
	}
	if !rampwellknown.AuthorizesContributor(m, templatePublisherDomain, agentid.FromDirectory) {
		t.Error("the publisher's own domain must authorize it without a contributor entry")
	}
	if !rampwellknown.AuthorizesContributor(m, templateContributorDomain, agentid.FromDirectory) {
		t.Errorf("the listed contributor %q must be authorized", templateContributorDomain)
	}
	if rampwellknown.AuthorizesContributor(m, "stranger.example", agentid.FromDirectory) {
		t.Error("an unlisted caller must not be authorized")
	}
}

func TestTemplateDirectoryParsesAndCarriesOneActiveKey(t *testing.T) {
	t.Parallel()
	f, err := rampwellknown.ParseWBA(readTemplate(t, "http-message-signatures-directory.example"))
	if err != nil {
		t.Fatalf("ParseWBA: %v", err)
	}
	if got := len(f.GetKeys()); got != 1 {
		t.Fatalf("keys = %d, want 1", got)
	}
	// The template's window is [2026-01-01, 2027-01-01). The three instants below
	// are fixed, so this says something about the template rather than about the
	// day the suite runs: active inside, inactive before, and inactive AT the
	// upper bound, which is excluded.
	inside := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	if got := len(rampwellknown.ActiveKeys(f, inside)); got != 1 {
		t.Errorf("active keys at %s = %d, want 1", inside, got)
	}
	before := time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC)
	if got := len(rampwellknown.ActiveKeys(f, before)); got != 0 {
		t.Errorf("active keys at %s = %d, want 0", before, got)
	}
	atUpperBound := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	if got := len(rampwellknown.ActiveKeys(f, atUpperBound)); got != 0 {
		t.Errorf("active keys at the excluded upper bound %s = %d, want 0", atUpperBound, got)
	}
}

func TestTemplateDirectoryKeyCannotBeSignedAgainst(t *testing.T) {
	t.Parallel()
	// The template's x is a placeholder an operator is meant to replace, and until
	// they do, it is published as this publisher's signing key. Nothing on the way
	// there rejects it: the Worker's schema checks the base64url alphabet and the
	// 43-character length, DecodeEd25519X checks the length again, and the SDK's
	// key selection checks that x decodes to 32 bytes. None of them asks whether
	// those 32 bytes are a point on the curve.
	//
	// That matters because some 32-byte strings ARE points, and one of them was
	// what this template used to ship: an all-zero x decodes to a point of order
	// exactly 4, and anyone can produce a signature ed25519.Verify accepts for it
	// without holding any private key. A publisher shipping that template
	// unchanged publishes, as its own signing key, one that any caller can sign
	// for — in the directory the Exchange reads to learn who may write to its
	// catalog.
	//
	// Which values are points is not something a reader can judge by looking. 43
	// underscores also decodes to a point, though a different kind: it is outside
	// the prime-order subgroup, so it is nobody's public key and nothing can sign
	// for it. Only a check decides.
	//
	// So the property this pins is not "x looks like a placeholder" but "no
	// signature can ever verify against x": its bytes are not on the curve, and
	// point decoding is where that is decided.
	f, err := rampwellknown.ParseWBA(readTemplate(t, "http-message-signatures-directory.example"))
	if err != nil {
		t.Fatalf("ParseWBA: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(f.GetKeys()[0].GetX())
	if err != nil {
		t.Fatalf("template x is not base64url: %v", err)
	}
	if _, err := new(edwards25519.Point).SetBytes(raw); err == nil {
		t.Fatal("the template's x decodes to a real Ed25519 curve point. Depending on " +
			"which point, either anyone can produce a signature that verifies against " +
			"it, or nobody holds the private half — either way a publisher deploying " +
			"the template unchanged publishes a key it does not control. Pick 43 " +
			"base64url characters whose 32 bytes are NOT a point — most " +
			"arbitrary-looking values are not, but some are, so re-run this test " +
			"rather than assuming")
	}
}

func TestTemplateDirectoryAdvertisesNoRevocationURL(t *testing.T) {
	t.Parallel()
	// The Worker serves four addresses and the revocation list is not one of them,
	// so a revocation_url here would send verifiers to an address that answers
	// nothing. The README explains that and names key rotation as the lever
	// instead.
	f, err := rampwellknown.ParseWBA(readTemplate(t, "http-message-signatures-directory.example"))
	if err != nil {
		t.Fatalf("ParseWBA: %v", err)
	}
	if got := f.GetRevocationUrl(); got != "" {
		t.Errorf("revocation_url = %q, want empty", got)
	}
}
