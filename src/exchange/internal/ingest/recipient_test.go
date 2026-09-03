package ingest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// A single valid feed line. The push only has to reach the server for these
// cases; what the entries say is the parser's and the mapper's business.
const feedLine = `{"domain":"publisher.example","path":"/article/recipient","title":"T",` +
	`"terms":[{"semantics":"enumerated","functions":["ai-input"],"pricing":{"model":"free","rate":"0","currency":"USD"}}]}`

// TestRun_AddressesThePushToTheDialledHost pins the rule that replaced a second
// required flag: an Exchange is reached at its own identity, so the recipient a
// push names is the host of the URL it is sent to.
//
// It matters because getting it wrong is not a local error. The push is signed
// and sent, and the Exchange refuses it as addressed to somebody else — a
// failure that surfaces at the far end of the wire and names the operator's URL
// nowhere.
func TestRun_AddressesThePushToTheDialledHost(t *testing.T) {
	t.Parallel()
	got, url := runAgainstRecordingExchange(t, "")
	if want := strings.TrimPrefix(url, "http://"); got != want {
		t.Errorf("push addressed to %q, want the dialled host %q", got, want)
	}
}

// TestRun_ExchangeOverridesTheDialledHost covers the one shape the derivation
// cannot serve: a routing shim in front of the Exchange, where the dialled host
// is a port mapping that names no Exchange at all. The e2e harness is the only
// caller that needs it.
func TestRun_ExchangeOverridesTheDialledHost(t *testing.T) {
	t.Parallel()
	const override = "exchange.example:8081"
	got, url := runAgainstRecordingExchange(t, override)
	if got != override {
		t.Errorf("push addressed to %q, want the override %q", got, override)
	}
	if got == strings.TrimPrefix(url, "http://") {
		t.Error("the override was ignored in favour of the dialled host")
	}
}

// TestRun_RecipientTheWireWouldRefuseStopsTheLocalRun covers the refusals the
// two acceptance paths above do not reach. The push is signed before it is
// sent, so a recipient the field does not admit would otherwise surface as a
// rejection at the far end, naming the operator's URL nowhere. Refusing locally
// is what turns it into an error about the value the operator supplied.
//
// Both paths are driven, because the value can arrive two ways: an override is
// operator input that nothing else checks, and a derived host answers a weaker
// question than the protocol does — HostOf takes an underscored container alias
// that a recipient field rejects.
func TestRun_RecipientTheWireWouldRefuseStopsTheLocalRun(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ url, exchange string }{
		"override is not a bare domain": {"", "https://exchange.example/catalog"},
		"dialled host is an underscored alias": {
			"http://ex_change.internal:8081", "",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec, srv := newRecordingExchange(t)
			url := tc.url
			if url == "" {
				url = srv.URL
			}
			_, err := ingest.Run(context.Background(), ingest.Options{
				ExchangeURL: url,
				Exchange:    tc.exchange,
				TenantID:    "tenant-recipient",
				KeyPath:     writeContributorKey(t),
				Feed:        strings.NewReader(feedLine),
				Clk:         clock.System{},
			})
			if err == nil {
				t.Fatal("Run accepted a recipient the wire would refuse")
			}
			if !strings.Contains(err.Error(), "not a bare domain") {
				t.Errorf("error %q does not say the recipient is not a bare domain", err)
			}
			if rec.req != nil {
				t.Error("a push was sent; the run must stop before anything is signed and dialled")
			}
		})
	}
}

// newRecordingExchange starts a CatalogService that accepts any push and keeps
// the request it was given.
func newRecordingExchange(t *testing.T) (*recordingCatalog, *httptest.Server) {
	t.Helper()
	rec := &recordingCatalog{}
	// The codec the real Catalog mount serves through, so this double answers the
	// ingest client in the spelling production emits.
	path, handler := rampconnect.NewCatalogServiceHandler(rec,
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()))
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return rec, srv
}

// runAgainstRecordingExchange drives a full Run against a CatalogService that
// records the request, and returns the recipient the push named along with the
// URL it was sent to.
func runAgainstRecordingExchange(t *testing.T, exchange string) (recipient, url string) {
	t.Helper()
	rec, srv := newRecordingExchange(t)

	if _, err := ingest.Run(context.Background(), ingest.Options{
		ExchangeURL: srv.URL,
		Exchange:    exchange,
		TenantID:    "tenant-recipient",
		KeyPath:     writeContributorKey(t),
		Feed:        strings.NewReader(feedLine),
		Clk:         clock.System{},
	}); err != nil {
		t.Fatalf("ingest.Run: %v", err)
	}
	if rec.req == nil {
		t.Fatal("the Exchange received no push")
	}
	return rec.req.GetExchange(), srv.URL
}

// recordingCatalog accepts any push and keeps the request it was given.
type recordingCatalog struct {
	rampconnect.UnimplementedCatalogServiceHandler
	req *rampv1.PushResourcesRequest
}

func (c *recordingCatalog) PushResources(
	_ context.Context, req *connect.Request[rampv1.PushResourcesRequest],
) (*connect.Response[rampv1.PushResourcesResponse], error) {
	c.req = req.Msg
	return connect.NewResponse(&rampv1.PushResourcesResponse{
		Ver: helpers.ProtocolVersion, Accepted: int32(len(req.Msg.GetEntries())),
	}), nil
}

// writeContributorKey mints a throwaway contributor keypair on disk in the shape
// LoadContributorKey reads.
func writeContributorKey(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	doc := ingest.ContributorKey{
		KID:        "publisher.example",
		PrivateKey: base64.RawURLEncoding.EncodeToString(priv.Seed()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(pub),
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "contributor-key.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}
