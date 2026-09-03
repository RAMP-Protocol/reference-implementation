//go:build integration

package transport_test

// Fixture ARRANGEMENT for the Exchange integration suite: seeding agents and
// tenants, and minting the signed clients that act as them. Split out of
// integration_helper_test.go to keep both files inside the 800-line test cap.
//
// Agents are seeded through the production repository surface (repo.AgentRepo),
// so the fixture and the code under test agree on their encoding by
// construction.
//
// Tenants are not, and this is the file that says so. Every tenant write here
// calls the generated sqlc querier directly, because the repository has no
// tenant-creation port: repo.TenantWriteRepo carries setters on a row that
// already exists and no way to make one. The Testing Doctrine's fallback tier
// is the repository interface; a raw querier is the tier below that, which it
// does not sanction at all. This is that tier, taken because the surface a test
// should reach does not exist. Adding the port and moving these arranges onto
// it is tracked as its own work — the sixteen call sites across this package
// predate this file.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/protobuf/reflect/protoreflect"

	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/signing"
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

// wireBound reads a repeated field's max_items rule off the pinned protocol
// descriptor, so a bound this package's cap tests drive is the wire's own and
// cannot drift from it.
//
// It is the one wrapper over that read for the whole package. There were two,
// added the same day the reader itself was unified one level down, and they had
// already diverged: only one refused a bound a list cannot be split at. The
// check is here so both callers get it.
//
// ingest.RepeatedMaxItems is the reader; the CLI chunks a feed with the same
// call. A cap a test drives that has gone from the wire is a finding, not a
// zero, and that judgement is made in one place for the CLI and the tests
// alike.
func wireBound(t *testing.T, message, field protoreflect.Name) int {
	t.Helper()
	bound, err := ingest.RepeatedMaxItems(message, field)
	if err != nil {
		t.Fatalf("read %s.%s off the pinned descriptor: %v", message, field, err)
	}
	if bound < 2 {
		t.Fatalf("%s.%s bound = %d; a list cannot be split at it", message, field, bound)
	}
	return bound
}

// insertTenantRow writes the tenants row for a publisher domain and returns its
// id. Catalog rows are owned by the tenant whose domain matches the entry's
// publisher domain (server-side derivation), so every test that pushes for a
// domain registers it here first.
//
// It is the writer for that path, not for every tenant this file seeds:
// addTenant above writes its own InsertTenantParams literal for the
// cross-tenant scenarios, which need a caller-chosen id and key ref rather than
// the generated pair this returns. Two literals, and a change to the tenants
// table has to reach both.
//
// It calls the InsertTenant query directly, for the reason the file header
// gives: there is no repository port that creates a tenant.
func insertTenantRow(t *testing.T, ctx context.Context, q *sqlc.Queries, domain string) (tenantID, keyRef string) {
	t.Helper()
	tenantID = "t_" + uuid.NewString()
	keyRef = "secret://ed25519/" + tenantID
	if _, err := q.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        tenantID,
		Domain:          domain,
		Ed25519KeyRef:   keyRef,
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant for %s: %v", domain, err)
	}
	return tenantID, keyRef
}

// seedPublisherTenant seeds a publisher the harness HOSTS: the tenant row, an
// Ed25519 offer-signing key in the keystore under that row's key ref, and
// broker relay allowed. That is the full shape, and every publisher the harness
// serves has it — the default one the constructor seeds and any a test adds
// through addPublisher — so both behave alike on every flow.
//
// It is the difference from seedTenantForDomain below, and the two exist rather
// than one function with a flag because the choice is not a switch a caller
// tunes: it is which of two roles the tenant plays.
func seedPublisherTenant(
	t *testing.T, ctx context.Context, queries *sqlc.Queries, keystore *signing.InMemoryKeyStore, domain string,
) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	tenantID, keyRef := insertTenantRow(t, ctx, queries, domain)
	if err := queries.SetTenantAllowBrokerRelay(ctx, sqlc.SetTenantAllowBrokerRelayParams{
		TenantID:         tenantID,
		AllowBrokerRelay: true,
	}); err != nil {
		t.Fatalf("enable broker relay for %s: %v", domain, err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("publisher ed25519: %v", err)
	}
	keystore.PutEd25519(keyRef, pub, priv)
	return tenantID, pub, priv
}

// seedTenantForDomain seeds a publisher the harness only has to RESOLVE: the
// tenant row and nothing else. It is what a test needs when the domain must
// exist so a push can be attributed to it — a second publisher a feed names, or
// a victim tenant in an isolation test — and the harness never serves that
// tenant's own manifest or signs on its behalf.
//
// Deliberately not the full shape above. A tenant seeded here allows no broker
// relay, and the relay tests depend on that being the default rather than
// something each of them has to switch off.
func seedTenantForDomain(t *testing.T, h *pushHarness, domain string) string {
	t.Helper()
	tenantID, _ := insertTenantRow(t, h.ctx, h.queries, domain)
	return tenantID
}

// seedTenant is seedTenantForDomain under a fresh random domain, for a test
// that needs a second tenant but does not care which domain it answers to.
// Sibling tests never collide on the tenants.domain UNIQUE constraint.
func seedTenant(t *testing.T, h *pushHarness) (tenantID, domain string) {
	t.Helper()
	domain = "pub-" + uuid.NewString() + ".example"
	return seedTenantForDomain(t, h, domain), domain
}
