//go:build integration

package mcp_test

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	identitymcp "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/mcp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/session"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

const (
	baseZone  = "rampmcp.org"
	authIssue = "http://auth.rampmcp.org"
	// tokenAudience is what tokens are minted for and what the endpoint
	// advertises as its protected-resource identifier.
	tokenAudience = "http://auth.rampmcp.org/mcp"

	agentSlug   = "agent-one"
	otherSlug   = "agent-two"
	tokenTTL    = 10 * time.Minute
	dialTimeout = 10 * time.Second
)

// fixture is one fully-wired identity service with the MCP adapter mounted,
// fronted by real HTTP, talking to RAMP peers that enforce the production
// signature gate.
type fixture struct {
	srv    *httptest.Server
	tokens *token.Issuer
	broker *rampPeer
	// exchange is the agents' home Exchange — the one this service is CONFIGURED
	// with, where register and status go.
	exchange *rampPeer
	// issuer is a SECOND, unrelated Exchange: the one that issued an offer and so
	// the one a usage report must reach. It is deliberately not the configured
	// home Exchange, because that is the whole property ramp_report has to hold —
	// a report follows the offer, not our configuration. With one peer standing in
	// for both, a regression that ignored the offer's exchange entirely and posted
	// to the configured URL would land on the same server and pass.
	issuer *rampPeer
	trust  *helpers.StaticKeyResolver
	keys   *keystore.VaultStore
	signUp *signup.Service
	// pool is the service's own database handle, kept so a test can close it and
	// drive a store outage through the tools. On the two account legs the only
	// thing behind it is the note store — the bearer is a signed token and the
	// signing key comes from Vault — so closing it fails exactly the note reads
	// and writes and nothing else.
	pool *pgxpool.Pool
	// logs holds what the service recorded, for the cases where the record IS the
	// property: a failure the agent is told one thing about and the operator
	// another can only be checked by reading both halves.
	logs *testutil.LogCapture
}

// newFixture builds the service through the production composition root
// (app.Build), so these tests drive the wiring cmd/server ships rather than a
// hand-assembled subset.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newBoundedFixture(t, nil)
}

// peerSet is the RAMP doubles a config hook may need to name.
//
// The hook runs after the peers exist and before the service is built, which is
// the only window in which their ephemeral 127.0.0.1 ports can be written into
// the configuration. A setting that names an Exchange — the deployment's
// allowlist — cannot be expressed without them.
type peerSet struct {
	broker   *rampPeer
	exchange *rampPeer
	issuer   *rampPeer
}

// newBoundedFixture is newFixture with a hook on the adapter's config, so a test
// can drive the CALL-scoped bounds — the batch budget and the call deadline — at
// values small enough to reach. Both of those govern agent-facing reason tokens
// that no test could produce while the limits were compiled-in constants.
//
// It fails the test on a configuration the service refuses. Use buildFixture
// where the refusal IS the property under test.
func newBoundedFixture(t *testing.T, mut func(*app.MCPConfig, peerSet)) *fixture {
	t.Helper()
	f, err := buildFixture(t, mut)
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	return f
}

// buildFixture is newBoundedFixture returning the composition root's error
// instead of failing on it.
//
// It exists because some settings are refused at START-UP, and a fixture that
// could only succeed cannot drive that. The refusal is the service's real
// behaviour on a misconfiguration, so it is asserted through the same
// production root as everything else rather than by unit-testing the parser and
// assuming the wiring calls it.
func buildFixture(t *testing.T, mut func(*app.MCPConfig, peerSet)) (*fixture, error) {
	t.Helper()
	// Armed for EVERY fixture, not by the tests that happen to notice they need
	// it. Every peer here is an httptest server on loopback speaking plaintext
	// http, and every outbound Exchange leg — the account RPCs, the report, the
	// manifest reads behind both — now dials under the SDK's guard. A fixture
	// that left these unset would refuse each of those, so this is the fixture's
	// own precondition rather than a per-test opt-in.
	//
	// It must run before app.Build, because the SDK reads the two flags when it
	// constructs a guarded transport, not when it dials. And t.Setenv is why no
	// test that builds a fixture may be parallel.
	testutil.AllowLoopbackFetch(t)
	ctx := t.Context()
	if err := sharedVault.Reset(ctx); err != nil {
		t.Fatalf("reset vault: %v", err)
	}
	pool := acquireTestDB(t, ctx)

	// The signature window and the token clock both run on the SYSTEM clock: the
	// signature's expires is judged by the peers' verifier and the token's exp by
	// the MCP SDK middleware, and neither offers a hook to override time.Now.
	// A frozen clock would mint credentials that are born expired.
	clk := clock.Clock(clock.System{})

	store, err := keystore.NewVaultStore(keystore.Config{
		Client: sharedVault.Client, Mount: sharedVault.Mount, Clk: clk,
	})
	if err != nil {
		t.Fatalf("new vault store: %v", err)
	}

	trust := newTrustStore()
	broker := newRAMPPeer(t, trust)
	exchange := newRAMPPeer(t, trust)
	issuer := newRAMPPeer(t, trust)

	tokens, err := token.NewIssuer(newTokenKey(t), authIssue, tokenAudience, clk)
	if err != nil {
		t.Fatalf("token.NewIssuer: %v", err)
	}

	mcpCfg := &app.MCPConfig{
		BrokerURL: broker.URL(),
		// No Exchange is configured, and there is nowhere left to configure one.
		// Each peer is reached by the domain a tool call names, resolved through
		// the manifest that peer serves about itself — which is why every peer
		// here publishes one.
		WellKnownScheme: "http",
	}
	if mut != nil {
		mut(mcpCfg, peerSet{broker: broker, exchange: exchange, issuer: issuer})
	}

	// Captured rather than discarded, for every test rather than a variant that
	// opts in. What a service records is part of what it does, and a capture the
	// suite always holds is what lets a test assert it without a second fixture
	// shape to keep in step with this one.
	logs, logger := testutil.NewLogCapture()

	handler, _, err := app.Build(app.Config{
		Pool:            pool,
		Keys:            store,
		Logger:          logger,
		BaseDomain:      baseZone,
		DirectoryTTL:    publisher.DefaultTTL,
		WellKnownScheme: "http",
		Clock:           clk,
		Health:          func(context.Context) error { return nil },
		Auth: &app.AuthConfig{
			Issuer:     authIssue,
			Upstream:   stubUpstream{},
			SessionKey: fixedSessionKey(),
			Tokens:     tokens,
		},
		MCP: mcpCfg,
	})
	if err != nil {
		return nil, err
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &fixture{
		srv: srv, tokens: tokens, broker: broker, exchange: exchange, issuer: issuer,
		trust: trust, keys: store, logs: logs, pool: pool,
		signUp: newSignUp(t, pool, store, clk),
	}, nil
}

// newSignUp builds the provisioning service the fixture arranges agents through.
// Arranging via signup rather than by writing rows keeps the setup on a
// production surface: it mints the subdomain, the custodied key, and the card in
// exactly the order a real sign-up does, so a test never depends on a state the
// service could not actually reach.
func newSignUp(
	t *testing.T, pool *pgxpool.Pool, store *keystore.VaultStore, clk clock.Clock,
) *signup.Service {
	t.Helper()
	svc, err := publisher.New(publisher.Config{
		Keys:          store,
		Cards:         repo.NewCardRepo(pool),
		Revocations:   repo.NewRevocationRepo(pool),
		Registrations: repo.NewDeveloperRepo(pool),
		Clock:         clk,
	})
	if err != nil {
		t.Fatalf("publisher.New: %v", err)
	}
	signUp, err := signup.New(signup.Config{
		Keys:       store,
		Cards:      repo.NewCardRepo(pool),
		Developers: repo.NewDeveloperRepo(pool),
		// A random slug, as production uses: the subdomain a developer gets is the
		// service's to choose, and provision() reads back whichever it minted.
		Slugs:       signup.RandomSlugGen{},
		Invalidator: svc,
		Clock:       clk,
		BaseDomain:  baseZone,
	})
	if err != nil {
		t.Fatalf("signup.New: %v", err)
	}
	return signUp
}

// registerArgsAt is a well-formed ramp_register call at exchange.
//
// One invariant, stated once: the arguments are past every LOCAL check — the
// domain is a bare one this deployment permits, and the payload satisfies the
// schema the peers publish. So a refusal a test observes came from the Exchange
// rather than from the tool layer, and a success reached the Exchange rather
// than stopping short of it. Written inline at each call site, that invariant is
// carried by nothing, and an edit to one map can turn a test about an Exchange's
// refusal into a test about a local pre-check with no assertion noticing.
func registerArgsAt(exchange string) map[string]any {
	return map[string]any{
		"exchange": exchange,
		"fields":   map[string]any{"company_name": "Acme GmbH"},
	}
}

// registerArgs is registerArgsAt at the fixture's own Exchange, which is where
// every test registers except the two that deliberately name one peer while
// contrasting it with another. Those two write the expansion out and say why.
func registerArgs(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	return registerArgsAt(f.exchange.Domain(t))
}

// agent is one provisioned developer: the subdomain that identifies it, and the
// bearer token that authenticates it to the MCP endpoint.
type agent struct {
	Subdomain  string
	Thumbprint string
	Token      string
}

// provision creates a developer identified upstream by subject and publishes its
// active key to the peers' trust store so a signature it makes verifies there. The
// subdomain is whatever sign-up minted — the test reads it back rather than
// dictating it, because the mapping from OIDC identity to subdomain is the
// service's to make.
func (f *fixture) provision(t *testing.T, subject string) agent {
	t.Helper()
	ctx := t.Context()
	claims := oidcup.Claims{
		Issuer:  "https://idp.example",
		Subject: subject,
		Email:   subject + "@acme.example",
		Name:    "Dev " + subject,
	}
	subdomain, err := f.signUp.SignIn(ctx, claims)
	if err != nil {
		t.Fatalf("sign in %s: %v", subject, err)
	}
	key, err := f.keys.Active(ctx, subdomain)
	if err != nil {
		t.Fatalf("active key %s: %v", subdomain, err)
	}
	f.trust.Put(key.Ref.Thumbprint, key.Public)

	raw, err := f.tokens.Mint(subdomain, tokenTTL)
	if err != nil {
		t.Fatalf("mint token %s: %v", subdomain, err)
	}
	return agent{Subdomain: subdomain, Thumbprint: key.Ref.Thumbprint, Token: raw}
}

// connect opens an MCP session over Streamable HTTP as a, exactly as an external
// client would: a real initialize handshake and real tools/call requests over the
// wire, not an in-process call to a handler.
func (f *fixture) connect(t *testing.T, bearer string) *mcpsdk.ClientSession {
	t.Helper()
	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-agent", Version: "1"}, nil)
	transport := &mcpsdk.StreamableClientTransport{
		Endpoint:   f.srv.URL + identitymcp.EndpointPath,
		HTTPClient: &http.Client{Transport: bearerTransport{token: bearer}, Timeout: dialTimeout},
	}
	ctx, cancel := context.WithTimeout(t.Context(), dialTimeout)
	t.Cleanup(cancel)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect as bearer: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// bearerTransport attaches the bearer to every MCP request.
type bearerTransport struct {
	token string
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	if b.token != "" {
		clone.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(clone)
}

// stubUpstream stands in for the OIDC provider. Sign-in is arranged through the
// signup service directly, so the upstream is never actually driven here; the auth
// server simply requires one to be wired.
type stubUpstream struct{}

func (stubUpstream) AuthCodeURL(string, string, string) string { return authIssue }

func (stubUpstream) Exchange(context.Context, string, string, string) (oidcup.Claims, error) {
	return oidcup.Claims{}, oidcup.ErrExchange
}

func newTokenKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate token key: %v", err)
	}
	return priv
}

func fixedSessionKey() []byte {
	key := make([]byte, session.KeyLen)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// systemClock is the wall clock the credentials in these tests are judged
// against; see the note in newFixture on why nothing here freezes time.
func systemClock() clock.Clock { return clock.System{} }
