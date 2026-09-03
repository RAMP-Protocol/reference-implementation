//go:build integration

package transport_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// The two tests in this file prove the contract PushEntries states for a feed
// larger than the wire bound on one submission, through the PRODUCTION push
// path (the SDK catalog client) against a real Exchange + testcontainers
// Postgres. Write leg: PushEntries → SDK client → validate interceptor →
// Exchange handler → service → repository → DB. Read leg: DiscoverResources.
// Nothing reaches past a public surface; the offer count DiscoverResources
// yields is the persistence probe (one ⇒ stored, zero ⇒ not).

// entriesPerSubmission is the wire bound the CLI splits a feed at. The tests
// here do not take the read on trust:
// TestIngest_FeedOverTheWireBoundIsPushedInSubmissions proves the value is the
// Exchange's from both sides of it.
func entriesPerSubmission(t *testing.T) int {
	t.Helper()
	return wireBound(t, "PushResourcesRequest", "entries")
}

// bulkEntries builds n minimal valid entries under domain at prefix plus a
// zero-padded index, each with its own priced term, so the only thing that
// varies across a feed is its length.
func bulkEntries(domain, prefix string, n int) []*rampv1.ResourceEntry {
	out := make([]*rampv1.ResourceEntry, 0, n)
	for i := range n {
		out = append(out, &rampv1.ResourceEntry{
			Domain: domain,
			Path:   fmt.Sprintf("%s%04d", prefix, i),
			Terms:  []*rampv1.LicenseTerm{seedPricedTerm()},
		})
	}
	return out
}

// unregisteredUnitTerm is a priced term the Exchange's ingest tier refuses:
// its bare pricing unit is not a registered metering token. The unit passes
// the wire pattern on Pricing.unit, so the client's wire validation lets it
// through and the refusal is the Exchange's, after the request crossed the
// wire.
func unregisteredUnitTerm() *rampv1.LicenseTerm {
	term := seedPricedTerm()
	term.Pricing.Unit = proto.String("bogus-unit")
	return term
}

// discoverBatch is how many URIs one DiscoverResources query carries here:
// well under the wire bound on ResourceQuery.uris, and small enough that a
// feed of several submissions reads back in a handful of calls. The batching
// is load-bearing: the harness's signing helper advances each signature's
// timestamps by one second per call, so several hundred back-to-back calls
// would carry them past the verifier's tolerance for a signature dated in the
// future and the read leg would fail with 401 for a reason unrelated to the
// catalog.
const discoverBatch = 100

// assertEntriesOfferCount proves through DiscoverResources that every entry given
// resolves to want offers: one ⇒ it reached the catalog, zero ⇒ it did not.
// The Exchange answers one offer group per requested URI, so the entries are
// read back in batched queries and counted per group.
func assertEntriesOfferCount(t *testing.T, h *pushHarness, entries []*rampv1.ResourceEntry, want int) {
	t.Helper()
	for start := 0; start < len(entries); start += discoverBatch {
		batch := entries[start:min(start+discoverBatch, len(entries))]
		uris := make([]string, 0, len(batch))
		for _, e := range batch {
			uris = append(uris, "https://"+e.GetDomain()+e.GetPath())
		}
		query := newResourceQuery(requesterWithScopes("agent-discover").requester, uris)
		resp, err := h.exchange.DiscoverResources(h.ctx, connect.NewRequest(query))
		if err != nil {
			t.Fatalf("discover %d URIs from %s: %v", len(uris), uris[0], err)
		}
		got := make(map[string]int, len(uris))
		for _, g := range resp.Msg.GetOfferGroups() {
			got[g.GetUri()] = len(g.GetOffers())
		}
		for _, uri := range uris {
			if got[uri] != want {
				t.Fatalf("discover %s: %d offer(s), want %d", uri, got[uri], want)
			}
		}
	}
}

// assertSubmission pins one submission result's entry range and outcome.
func assertSubmission(t *testing.T, got ingest.SubmissionResult, first, last int, stored bool) {
	t.Helper()
	if got.First != first || got.Last != last || got.Stored() != stored {
		t.Fatalf("submission = entries %d-%d stored=%v (err: %v), want entries %d-%d stored=%v",
			got.First, got.Last, got.Stored(), got.Err, first, last, stored)
	}
}

// TestIngest_FeedOverTheWireBoundIsPushedInSubmissions proves the contract's
// success path: a feed one entry larger than the bound goes as two
// submissions in feed order — the first carrying exactly the bound, the second
// the remaining entry — both are stored, and every entry is discoverable.
//
// The bound the CLI reads off the descriptor has to be the Exchange's, and the
// test proves that from both sides rather than reading the descriptor a second
// time: the first submission, exactly the bound, is accepted at the wire
// (bound ≤ wire cap); one more than the bound sent as a single raw submission
// through the harness's own signed client is refused at the wire tier naming
// entries under repeated.max_items (bound + 1 > wire cap), with nothing
// stored. A CLI bound that drifted low would pass the first probe and fail the
// second; one that drifted high would fail the first.
func TestIngest_FeedOverTheWireBoundIsPushedInSubmissions(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)
	bound := entriesPerSubmission(t)

	entries := bulkEntries(publisherDomain, "/bulk/", bound+1)
	report, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, h.server.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	if err != nil {
		t.Fatalf("push %d entries: %v", len(entries), err)
	}
	if report.Planned != 2 || len(report.Submissions) != 2 || int(report.Accepted) != len(entries) {
		t.Fatalf("report = planned %d / sent %d / accepted %d, want 2 / 2 / %d",
			report.Planned, len(report.Submissions), report.Accepted, len(entries))
	}
	assertSubmission(t, report.Submissions[0], 0, bound-1, true)
	assertSubmission(t, report.Submissions[1], bound, bound, true)
	assertEntriesOfferCount(t, h, entries, 1)

	over := bulkEntries(publisherDomain, "/bulk-raw/", bound+1)
	_, err = h.signedCat(kid, priv).PushResources(h.ctx, connect.NewRequest(newPushRequest(publisherTenant, kid, over)))
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	assertWireViolation(t, err, "entries", "repeated.max_items")
	assertEntriesOfferCount(t, h, over, 0)
}

// TestIngest_RefusedSubmissionStopsTheRun proves the contract's failure path:
// a feed of three submissions whose SECOND carries an entry the Exchange's
// ingest tier refuses. The first submission is stored and every entry in it is
// discoverable; the second is refused whole — CodeInvalidArgument from the
// RPC, with no Violations detail, so the refusal is the ingest tier's after
// the request crossed the wire — and none of its entries is stored; the
// third, entirely valid, is never sent, and none of its entries is stored
// either. The returned error and the written report both name the refused
// submission, the range that was stored and the range that was not sent.
func TestIngest_RefusedSubmissionStopsTheRun(t *testing.T) {
	h := newPushHarness(t)
	const publisherDomain = "publisher.example"
	kid, priv := registerContributor(t, h, publisherDomain)
	publisherTenant := seedTenantForDomain(t, h, publisherDomain)
	bound := entriesPerSubmission(t)

	entries := bulkEntries(publisherDomain, "/stop/", 2*bound+1)
	entries[bound].Terms = []*rampv1.LicenseTerm{unregisteredUnitTerm()}

	report, err := ingest.PushEntries(h.ctx,
		mustCatalogClient(t, h.server.URL, kid, priv), pushTarget(publisherTenant, kid), entries)
	assertConnectCode(t, err, connect.CodeInvalidArgument)
	if violations := testutil.ValidationViolations(t, err); len(violations) != 0 {
		t.Fatalf("refusal carries %d wire violation(s); want none: the ingest tier refused, not the wire tier",
			len(violations))
	}
	for _, want := range []string{
		fmt.Sprintf("submission 2 of 3 (entries %d-%d) refused", bound, 2*bound-1),
		fmt.Sprintf("entries 0-%d were stored", bound-1),
		fmt.Sprintf("entries %d-%d were not sent", 2*bound, 2*bound),
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if report.Planned != 3 || len(report.Submissions) != 2 || int(report.Accepted) != bound {
		t.Fatalf("report = planned %d / sent %d / accepted %d, want 3 / 2 / %d",
			report.Planned, len(report.Submissions), report.Accepted, bound)
	}
	assertSubmission(t, report.Submissions[0], 0, bound-1, true)
	assertSubmission(t, report.Submissions[1], bound, 2*bound-1, false)

	var written bytes.Buffer
	ingest.WriteReport(&written, report)
	for _, want := range []string{
		fmt.Sprintf("push: accepted=%d warnings=0\n", bound),
		fmt.Sprintf("  submission 1 of 3 (entries 0-%d): stored, accepted=%d warnings=0\n", bound-1, bound),
		fmt.Sprintf("  submission 2 of 3 (entries %d-%d): REFUSED: ", bound, 2*bound-1),
		fmt.Sprintf("  entries %d-%d: not sent\n", 2*bound, 2*bound),
	} {
		if !strings.Contains(written.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, written.String())
		}
	}

	assertEntriesOfferCount(t, h, entries[:bound], 1)
	assertEntriesOfferCount(t, h, entries[bound:2*bound], 0)
	assertEntriesOfferCount(t, h, entries[2*bound:], 0)
}
