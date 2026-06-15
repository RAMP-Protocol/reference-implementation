package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

var anchor = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

type fixedKeys struct{ keys []*rampwellknown.Key }

func (f fixedKeys) Keys() []*rampwellknown.Key { return f.keys }

func oneKey(kid string) server.KeySource {
	_, k := testutil.NewSigningKey(kid, anchor.Add(-time.Hour), anchor.Add(time.Hour))
	return fixedKeys{keys: []*rampwellknown.Key{k}}
}

func TestBuild_RolesRoundTrip(t *testing.T) {
	t.Parallel()
	hops := int32(4)
	cfgs := map[string]server.Config{
		"agent":  {Role: rampwellknown.RoleAgent, Domain: "a.example", Keys: oneKey("a")},
		"broker": {Role: rampwellknown.RoleBroker, Domain: "b.example", Keys: oneKey("b")},
		"exchange": {
			Role: rampwellknown.RoleExchange, Domain: "x.example", Keys: oneKey("x"),
			Endpoint: "https://x.example/ramp", BaseCurrency: "USD", MaxIntermediaryHops: &hops,
		},
		"publisher": {
			Role: rampwellknown.RolePublisher, Domain: "p.example",
			Exchanges: []*rampv1.AuthorizedExchange{
				testutil.PublisherExchange("x.example", "https://x.example/ramp",
					rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT),
			},
		},
	}
	want := map[string]rampwellknown.Role{
		"agent": rampwellknown.RoleAgent, "broker": rampwellknown.RoleBroker,
		"exchange": rampwellknown.RoleExchange, "publisher": rampwellknown.RolePublisher,
	}
	for name, cfg := range cfgs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw, err := server.Build(cfg)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			m, err := rampwellknown.ParseManifest(raw, want[name])
			if err != nil {
				t.Fatalf("ParseManifest: %v", err)
			}
			if m.GetDomain() != cfg.Domain {
				t.Fatalf("domain=%s want %s", m.GetDomain(), cfg.Domain)
			}
		})
	}
}

func TestBuild_AgentWithoutKeysIsRejected(t *testing.T) {
	t.Parallel()
	_, err := server.Build(server.Config{Role: rampwellknown.RoleAgent, Domain: "a.example"})
	if err == nil {
		t.Fatal("expected agent manifest without public_keys to fail schema validation")
	}
}

// mutableKeys is a KeySource whose key list can be rotated between Rebuilds, so
// the test can prove Rebuild actually re-reads the source.
type mutableKeys struct{ keys []*rampwellknown.Key }

func (m *mutableKeys) Keys() []*rampwellknown.Key { return m.keys }

func TestHandler_ServeAndRebuild(t *testing.T) {
	t.Parallel()
	_, b1 := testutil.NewSigningKey("b1", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	src := &mutableKeys{keys: []*rampwellknown.Key{b1}}
	h, err := server.NewHandler(server.Config{
		Role: rampwellknown.RoleBroker, Domain: "b.example", Keys: src,
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	// Serve through a mux mounted at the canonical path (exercises RegisterRoutes).
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Get(srv.URL + rampwellknown.Path) //nolint:noctx // test client
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	served, err := rampwellknown.ParseManifest(body, rampwellknown.RoleBroker)
	if err != nil {
		t.Fatalf("served manifest invalid: %v", err)
	}
	if _, ok := rampwellknown.KeyByKid(served, "b1"); !ok {
		t.Fatal("initial document missing kid b1")
	}

	// Rotate the KeySource, then Rebuild: the new kid must replace the old one,
	// proving Rebuild re-reads the source rather than serving a stale snapshot.
	_, b2 := testutil.NewSigningKey("b2", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	src.keys = []*rampwellknown.Key{b2}
	if err := h.Rebuild(); err != nil {
		t.Fatalf("Rebuild: %v", err)
	}
	rebuilt, err := rampwellknown.ParseManifest(h.Bytes(), rampwellknown.RoleBroker)
	if err != nil {
		t.Fatalf("manifest invalid after rebuild: %v", err)
	}
	if _, ok := rampwellknown.KeyByKid(rebuilt, "b2"); !ok {
		t.Fatal("Rebuild did not pick up the rotated-in kid b2")
	}
	if _, ok := rampwellknown.KeyByKid(rebuilt, "b1"); ok {
		t.Fatal("Rebuild still serves the old kid b1 after rotation")
	}
}
