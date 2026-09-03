package ingest_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// TestRun_EmptyFeedIsRefusedBeforeDialling pins that a feed with no entries is
// refused locally, for the reason the wire refuses it (a push must carry at
// least one entry), and that nothing is signed or sent for it: the recording
// CatalogService sees no request.
func TestRun_EmptyFeedIsRefusedBeforeDialling(t *testing.T) {
	t.Parallel()
	rec, srv := newRecordingExchange(t)
	_, err := ingest.Run(context.Background(), ingest.Options{
		ExchangeURL: srv.URL,
		TenantID:    "tenant-empty",
		KeyPath:     writeContributorKey(t),
		Feed:        strings.NewReader("\n\n"),
		Clk:         clock.System{},
	})
	if !errors.Is(err, ingest.ErrEmptyFeed) {
		t.Fatalf("Run over an empty feed returned %v; want ErrEmptyFeed", err)
	}
	if rec.req != nil {
		t.Error("a push was sent for an empty feed; nothing must be dialled")
	}
}

// shortCatalog is a CatalogService that answers 2xx while reporting it accepted
// a different number of entries than it was sent — the one answer a conforming
// Exchange never gives, and the one nothing on the wire forbids.
type shortCatalog struct {
	rampconnect.UnimplementedCatalogServiceHandler
	accepted, rejected int32
	sent               int
}

func (c *shortCatalog) PushResources(
	_ context.Context, req *connect.Request[rampv1.PushResourcesRequest],
) (*connect.Response[rampv1.PushResourcesResponse], error) {
	c.sent = len(req.Msg.GetEntries())
	return connect.NewResponse(&rampv1.PushResourcesResponse{
		Ver: helpers.ProtocolVersion, Accepted: c.accepted, Rejected: c.rejected,
	}), nil
}

// newShortExchange starts a CatalogService answering every push with the given
// counts, through the codec the real Catalog mount serves.
func newShortExchange(t *testing.T, accepted, rejected int32) (*shortCatalog, *httptest.Server) {
	t.Helper()
	rec := &shortCatalog{accepted: accepted, rejected: rejected}
	path, handler := rampconnect.NewCatalogServiceHandler(rec,
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()))
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return rec, srv
}

// TestRun_ShortAcceptedCountStopsTheRunWithoutAVerdict pins the invariant the
// wire does not carry: PushResourcesResponse has no rule relating accepted to
// the number of entries the request held, so a recipient answering 200 with a
// short count would otherwise leave the run exiting 0 over a catalog it never
// stored. The CLI dials whatever Exchange an operator names, so this is the
// only place the contract is asserted rather than assumed.
//
// The run stops, and the submission it stopped at is UNCONFIRMED rather than
// refused: the Exchange answered success, so its entries may well be stored.
// The test asserts that label, because the outcome word is what an operator
// acts on and a run that stops is not the same fact as a range that is absent.
//
// The second case pins that stopping does not depend on rejected, which the
// reference Exchange never populates: accepted alone decides.
func TestRun_ShortAcceptedCountStopsTheRunWithoutAVerdict(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name               string
		accepted, rejected int32
	}{
		{"accepted none", 0, 0},
		{"accepted none, rejected reported", 0, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rec, srv := newShortExchange(t, tc.accepted, tc.rejected)
			report, err := ingest.Run(context.Background(), ingest.Options{
				ExchangeURL: srv.URL,
				TenantID:    "tenant-short",
				KeyPath:     writeContributorKey(t),
				Feed:        strings.NewReader(feedLine),
				Clk:         clock.System{},
			})
			if rec.sent != 1 {
				t.Fatalf("the Exchange was sent %d entries, want 1", rec.sent)
			}
			if err == nil {
				t.Fatal("Run returned nil for a 2xx that accepted fewer entries than it was sent; the CLI would exit 0")
			}
			for _, want := range []string{"accepted 0 of the 1 entries", "stored whole or refused whole"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not say %q", err, want)
				}
			}
			if report.Accepted != 0 {
				t.Errorf("report counted %d accepted entries for a submission that did not store, want 0", report.Accepted)
			}
			failed, stopped := report.StoppedAt()
			if !stopped || failed.First != 0 || failed.Last != 0 {
				t.Errorf("report names stopped submission %+v (stopped=%v), want entries 0-0", failed, stopped)
			}
			if !failed.Unconfirmed() {
				t.Error("a 2xx with a short count is printed as REFUSED; the Exchange answered success, " +
					"so whether the range is stored is unknown")
			}
		})
	}
}

// TestRun_FullAcceptedCountIsStored is the control: the same harness answering
// the count the submission carried is accepted, so the check above refuses a
// short count rather than every answer.
func TestRun_FullAcceptedCountIsStored(t *testing.T) {
	t.Parallel()
	_, srv := newShortExchange(t, 1, 0)
	report, err := ingest.Run(context.Background(), ingest.Options{
		ExchangeURL: srv.URL,
		TenantID:    "tenant-full",
		KeyPath:     writeContributorKey(t),
		Feed:        strings.NewReader(feedLine),
		Clk:         clock.System{},
	})
	if err != nil {
		t.Fatalf("Run over a fully accepted submission: %v", err)
	}
	if report.Accepted != 1 {
		t.Errorf("report.Accepted = %d, want 1", report.Accepted)
	}
}

// unansweredServer starts an HTTP server that never answers a request the way
// the given fault describes, and returns its URL.
//
// It is a NETWORK FAULT INJECTOR, not an Exchange double. It serves no
// CatalogService and speaks no RAMP: the whole point is that the request gets
// no verdict, which is a fault a conforming Exchange cannot produce on purpose.
// That is the same reasoning that admits shortExchange above — the Testing
// Doctrine forbids mocking the Exchange, and neither of these stands in for
// one.
func unansweredServer(t *testing.T, fault func(http.ResponseWriter, *http.Request)) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(fault))
	t.Cleanup(srv.Close)
	return srv.URL
}

// dropConnection hijacks the connection and closes it without writing a
// response, which the client reads as a reset peer.
func dropConnection(w http.ResponseWriter, _ *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	conn, _, err := hijacker.Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// TestPushEntries_UncontactedExchangeIsNotPrintedAsRefused drives the real SDK
// catalog client into the two failures the report's NOT CONFIRMED label exists
// for, and asserts the label reaches the operator's line.
//
// It has to go through PushEntries against a real server. The client wraps
// every transport failure in its own typed error, so a deadline and a dropped
// connection arrive as something no hand-built error matches: an error
// assembled in a test passes a predicate the real one fails, which is exactly
// how this defect shipped. Whatever classifies the outcome has to be fed what
// the client returns.
//
// The other side of the split — a submission the Exchange REFUSED — is driven
// against a real Exchange over a real over-cap rejection by the ingest
// submissions e2e in the transport package, which asserts the REFUSED word.
func TestPushEntries_UncontactedExchangeIsNotPrintedAsRefused(t *testing.T) {
	t.Parallel()
	entry := &rampv1.ResourceEntry{
		Domain: "publisher.example",
		Path:   "/unanswered",
		Terms: []*rampv1.LicenseTerm{{
			Semantics: rampv1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
			Pricing: &rampv1.Pricing{
				Model: rampv1.PricingModel_PRICING_MODEL_FREE, Rate: "0", Currency: "EUR",
			},
		}},
	}

	for _, tc := range []struct {
		name  string
		fault func(http.ResponseWriter, *http.Request)
		call  func(*testing.T, string) (ingest.PushReport, error)
	}{
		{
			name:  "the connection dropped before any answer",
			fault: dropConnection,
			call: func(t *testing.T, url string) (ingest.PushReport, error) {
				t.Helper()
				return pushOneEntry(t, context.Background(), url, entry)
			},
		},
		{
			name: "the deadline passed before any answer",
			// Outlast the client's deadline, then return. The bound matters:
			// httptest.Server.Close waits for outstanding handlers, and a
			// handler that waited only on the request context would hang the
			// suite — the client abandoning the call does not cancel the
			// server's context while the connection stays open. The select
			// still takes the early exit if it ever does.
			fault: func(_ http.ResponseWriter, r *http.Request) {
				select {
				case <-r.Context().Done():
				case <-time.After(pushDeadline * 4):
				}
			},
			call: func(t *testing.T, url string) (ingest.PushReport, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), pushDeadline)
				defer cancel()
				return pushOneEntry(t, ctx, url, entry)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			report, err := tc.call(t, unansweredServer(t, tc.fault))
			if err == nil {
				t.Fatal("PushEntries returned nil for a call that never got an answer")
			}
			stopped, ok := report.StoppedAt()
			if !ok {
				t.Fatal("the report names no submission the run stopped at")
			}
			if !stopped.Unconfirmed() {
				t.Errorf("a call that got no answer reads as a verdict from the Exchange: %v", stopped.Err)
			}
			// The operator's line, not just the predicate: REFUSED says the
			// entries are absent, and after a timeout the Exchange may hold them.
			var out bytes.Buffer
			ingest.WriteReport(&out, report)
			if !strings.Contains(out.String(), "NOT CONFIRMED (the range may or may not be stored)") {
				t.Errorf("the report does not say the range is unconfirmed:\n%s", out.String())
			}
			if strings.Contains(out.String(), "REFUSED") {
				t.Errorf("the report calls an unanswered call a refusal:\n%s", out.String())
			}
			if !strings.Contains(err.Error(), "not confirmed (its entries may or may not be stored)") {
				t.Errorf("the returned error calls an unanswered call a refusal: %v", err)
			}
		})
	}
}

// pushDeadline is short enough to keep the deadline case quick and long enough
// that a loaded machine still dials before it passes.
const pushDeadline = 150 * time.Millisecond

// pushOneEntry dials exchangeURL through the production client builder and
// pushes one entry, so the failure under test travels the path ingest.Run
// travels rather than a client assembled for the test.
func pushOneEntry(
	t *testing.T, ctx context.Context, exchangeURL string, entry *rampv1.ResourceEntry,
) (ingest.PushReport, error) {
	t.Helper()
	kid, priv, err := ingest.LoadContributorKey(writeContributorKey(t))
	if err != nil {
		t.Fatalf("load contributor key: %v", err)
	}
	client, err := ingest.NewCatalogClient(exchangeURL, kid, priv, clock.System{})
	if err != nil {
		t.Fatalf("build catalog client: %v", err)
	}
	target := ingest.PushTarget{Exchange: "exchange.example", TenantID: "tenant-unanswered", CallerID: kid}
	return ingest.PushEntries(ctx, client, target, []*rampv1.ResourceEntry{entry})
}
