//go:build integration

package transport_test

// Fixture ARRANGEMENT for the Exchange integration suite: seeding agents and
// tenants, and minting the signed clients that act as them. Split out of
// integration_helper_test.go to keep both files inside the 800-line test cap.
//
// Everything here arranges through the production repository surface
// (repo.AgentRepo / repo.TenantWriteRepo), never raw sqlc or SQL, so a fixture
// and the code under test agree on the encoding by construction.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/jackc/pgx/v5/pgtype"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// agentDirectoryURL mirrors the anchored WBA directory agentreg pins a key from
// (registry.RegisterFromDirectory resolves exactly this shape), so seeded agents
// carry the same key provenance production records rather than a NULL that would
// make provenance assertions vacuous.
func agentDirectoryURL(agentID string) string {
	return "https://" + agentID + "/.well-known/http-message-signatures-directory"
}

// seedAgent registers one agent row: its directory identity, its REAL public key
// (so a caller signing with the matching private key satisfies the identity↔key
// binding the Exchange enforces), its requester type, and the anchored directory
// the key is pinned from.
//
// One function rather than the block repeated at each fixture: the upsert
// overwrites discovery_url with whatever the caller passes, so a site that
// omitted it does not merely skip the column — it seeds NULL over a value an
// earlier seed established, turning key-provenance assertions vacuous.
func seedAgent(t *testing.T, ctx context.Context, q *sqlc.Queries, agentID string, pub ed25519.PublicKey) {
	t.Helper()
	seedAgentAs(t, ctx, q, agentID, pub, string(sqlc.RampRequesterTypeAGENT))
}

// seedAgentAs is seedAgent for a caller that must be registered as something
// other than an AGENT (a relaying BROKER). It arranges through repo.AgentRepo,
// the surface production writes agents through, so fixture and code under test
// agree on the encoding — including that an empty discovery URL becomes NULL.
func seedAgentAs(
	t *testing.T, ctx context.Context, q *sqlc.Queries,
	agentID string, pub ed25519.PublicKey, kind string,
) {
	t.Helper()
	if _, err := repo.NewAgentRepo(q).Upsert(ctx, repo.Agent{
		ID:            agentID,
		PublicKey:     pub,
		DiscoveryURL:  agentDirectoryURL(agentID),
		RequesterType: kind,
	}); err != nil {
		t.Fatalf("seed agent %q: %v", agentID, err)
	}
}

// addCallerWithKey is addCaller that also returns the freshly-generated Ed25519
// keypair, so a test can sign the new caller's OWN body offer-acceptance (not
// just its transport RFC 9421 envelope). Used by cross-caller replay tests that
// present a second agent's legitimately self-signed request.
func (h *testHarness) addCallerWithKey(
	t *testing.T, agentID, requesterType string,
) (rampconnect.ExchangeServiceClient, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("addCaller ed25519: %v", err)
	}
	// The httpsig resolver keys by RFC 9421 keyid (an RFC 7638 thumbprint after
	// the WBA split); the agents row keys by the directory identity (agentID).
	h.resolver.Put(rwtestutil.MustThumbprintPriv(priv), pub)
	seedAgentAs(t, h.ctx, h.queries, agentID, pub, requesterType)
	client := &http.Client{Transport: newSigningTransport(h.baseTransport, agentID, priv)}
	return rampconnect.NewExchangeServiceClient(client, h.server.URL, connect.WithGRPC()), pub, priv
}

// addTenant inserts a fresh tenant row + signing key, and registers a
// caller for it via addCaller. Returns the new tenant_id + the new caller's
// ExchangeService client. Used by cross-tenant tests.
func (h *testHarness) addTenant(t *testing.T, tenantSlug, agentID string) (tenantID string, client rampconnect.ExchangeServiceClient) {
	t.Helper()
	tenantID = "t_" + tenantSlug
	tenantDomain := tenantSlug + ".example"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("addTenant ed25519: %v", err)
	}
	keyRef := "secret://ed25519/" + tenantID
	h.keystore.PutEd25519(keyRef, pub, priv)
	if _, err := h.queries.InsertTenant(h.ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          tenantDomain,
		HmacSecretRef:   "unused",
		Ed25519KeyRef:   keyRef,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant %q: %v", tenantID, err)
	}
	client = h.addCaller(t, agentID, "AGENT")
	return tenantID, client
}

// enableBrokerRelay flips tenants.allow_broker_relay = true for the given
// tenant via the generated sqlc Querier.
func (h *testHarness) enableBrokerRelay(t *testing.T, tenantID string) {
	t.Helper()
	if err := h.queries.SetTenantAllowBrokerRelay(h.ctx, sqlc.SetTenantAllowBrokerRelayParams{
		TenantID:         tenantID,
		AllowBrokerRelay: true,
	}); err != nil {
		t.Fatalf("set allow_broker_relay: %v", err)
	}
}
