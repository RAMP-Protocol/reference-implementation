//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
	rwtestutil "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// Test helpers for the R4 relay path: body offer-acceptance signing and
// the agent+broker / broker-only transport signing variants. Split out of
// integration_helper_test.go to keep that file under the 800-line test cap.

// signAcceptanceFor mints a body AgentAcceptance for offer/txID signed with priv
// over the EXACT requester that will ride on the request. The
// signing key MUST be the agent's REGISTERED key, and requester MUST equal the
// request's requester, since the acceptance payload covers requester.id +
// requester.domain.
func signAcceptanceFor(
	t *testing.T, priv ed25519.PrivateKey, offer *rampv1.Offer, requester *rampv1.Requester, txID string,
) *rampv1.AgentAcceptance {
	t.Helper()
	sig, err := helpers.SignOfferAcceptance(priv, offer, requester, txID)
	if err != nil {
		t.Fatalf("SignOfferAcceptance: %v", err)
	}
	return &rampv1.AgentAcceptance{
		Signature:          sig,
		SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
	}
}

// signAcceptance is signAcceptanceFor for the canonical agent.example requester
// (id, domain "agent.example", type AGENT) the standard execute requests use.
func signAcceptance(
	t *testing.T, priv ed25519.PrivateKey, offer *rampv1.Offer, requesterID, txID string,
) *rampv1.AgentAcceptance {
	t.Helper()
	return signAcceptanceFor(t, priv, offer,
		newRequester(requesterID, "agent.example"),
		txID)
}

// defaultAcceptance signs the body acceptance with the harness's default
// agent-test caller key (the agents-row registered key), for the canonical
// agent-direct execute path.
func (h *testHarness) defaultAcceptance(t *testing.T, offer *rampv1.Offer, txID string) *rampv1.AgentAcceptance {
	t.Helper()
	return signAcceptance(t, h.callerPriv, offer, "agent-test", txID)
}

// newMultisigSigningTransport composes two SDK signing transports into the
// forwarding chain the Exchange's R4 multisig gate verifies: the OUTER
// agent transport signs sig1 (and stamps the agent's Signature-Agent — the
// broker relay preserves it rather than stamping its own), then the INNER
// broker transport (WithAppendSigner) sees the existing Signature and appends
// the chain-linked sig2 — exactly the production relay topology, collapsed
// into one client. Both signers' thumbprint keyids MUST be registered with the
// httpsig resolver. A shared monotonic counter keeps every signature's expires
// unique so back-to-back calls dodge the replay store.
func newMultisigSigningTransport(
	base http.RoundTripper, agentKeyID string, agentPriv ed25519.PrivateKey,
	_ string, brokerPriv ed25519.PrivateKey,
) http.RoundTripper {
	var counter atomic.Int64
	counter.Store(time.Now().Unix())
	win := core.Window(func() (created, expires int64) {
		c := counter.Add(1)
		return c, c + 3600
	})
	brokerRT := core.NewSigningTransport(
		mustSigner(brokerPriv), base,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithAppendSigner(),
		core.WithWindow(win),
	)
	return core.NewSigningTransport(
		mustSigner(agentPriv), brokerRT,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithSignatureAgent(agentKeyID),
		core.WithWindow(win),
	)
}

// brokerRelayClient registers a BROKER caller (keyID carrying the
// helpers.BrokerKeyIDPrefix) and returns a Connect-Go ExchangeService client
// whose transport signs sig1 as the default agent-test agent and sig2 as that
// broker — the forwarding chain the R4 multisig gate verifies. The agent
// identity that binds the URL still comes from the BODY acceptance, not this
// transport chain (binding decision).
func (h *testHarness) brokerRelayClient(t *testing.T, brokerKeyID string) rampconnect.ExchangeServiceClient {
	t.Helper()
	return h.relayClientAs(t, brokerKeyID, sqlc.RampRequesterTypeBROKER)
}

// relayClientAs is brokerRelayClient with an explicit agents-row requester_type
// for the relay hop (sig2). It lets a test arrange a relay hop whose directory is
// NOT a registered broker (requester_type == AGENT). The single-gate relay posture
// (Option C) admits such a hop purely on tenant.allow_broker_relay: the transport
// chain is classified by POSITION, never re-checked against requester_type, so the
// hop's role has no bearing on the relay decision.
func (h *testHarness) relayClientAs(
	t *testing.T, relayKeyID string, requesterType sqlc.RampRequesterType,
) rampconnect.ExchangeServiceClient {
	t.Helper()
	_, relayPriv := h.registerBrokerAs(t, relayKeyID, requesterType)
	transport := newMultisigSigningTransport(
		h.baseTransport, "agent-test", h.callerPriv, relayKeyID, relayPriv,
	)
	client := &http.Client{Transport: transport}
	return rampconnect.NewExchangeServiceClient(client, h.server.URL, connect.WithGRPC())
}

// brokerOnlyClient registers a BROKER caller and returns a client whose
// transport signs ONLY the broker signature (no agent sig1) — the broker-only
// transport topology (production R6 behavior, where the broker REPLACES rather
// than appends). The agent identity, if any, must come from the body acceptance.
func (h *testHarness) brokerOnlyClient(t *testing.T, brokerKeyID string) rampconnect.ExchangeServiceClient {
	t.Helper()
	_, brokerPriv := h.registerBroker(t, brokerKeyID)
	client := &http.Client{Transport: newSigningTransport(h.baseTransport, brokerKeyID, brokerPriv)}
	return rampconnect.NewExchangeServiceClient(client, h.server.URL, connect.WithGRPC())
}

// registerBroker generates a fresh Ed25519 key for brokerKeyID, registers its
// pubkey with the httpsig resolver, and upserts the agents row as a BROKER.
func (h *testHarness) registerBroker(t *testing.T, brokerKeyID string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	return h.registerBrokerAs(t, brokerKeyID, sqlc.RampRequesterTypeBROKER)
}

// registerBrokerAs is registerBroker with an explicit agents-row requester_type,
// so a test can arrange the prefix-vs-type disagreement (a 'broker.'-prefixed key
// whose agents row is requester_type=AGENT). The row is seeded below the public
// surface — a Testing-Doctrine-9 arrange-side corner, because no public
// broker-registration RPC exists (lazy self-signup refuses broker prefixes) — but
// through the shared seedAgentAs helper, so the broker carries the same key
// provenance every other seeded caller does. Side-effect ASSERTIONS still go
// through the production repo surface.
func (h *testHarness) registerBrokerAs(
	t *testing.T, brokerKeyID string, requesterType sqlc.RampRequesterType,
) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	brokerPub, brokerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("broker ed25519: %v", err)
	}
	// The httpsig resolver keys the relay's signature by its RFC 7638 thumbprint
	// (the WBA keyid); the agents row keys by the broker's directory identity.
	h.resolver.Put(rwtestutil.MustThumbprintPriv(brokerPriv), brokerPub)
	seedAgentAs(t, h.ctx, h.queries, brokerKeyID, brokerPub, string(requesterType))
	return brokerPub, brokerPriv
}
