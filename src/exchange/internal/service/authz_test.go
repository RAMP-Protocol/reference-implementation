package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// discardLogger is a no-op slog logger for unit tests that exercise paths
// emitting structured audit lines via logOutcome.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// mockAgentRepo is a minimal mock for AgentRepo used in unit tests.
type mockAgentRepo struct {
	agents map[string]repo.Agent
}

func (m *mockAgentRepo) ByID(_ context.Context, agentID string) (repo.Agent, error) {
	if a, ok := m.agents[agentID]; ok {
		return a, nil
	}
	return repo.Agent{}, repo.ErrAgentNotFound
}

func (m *mockAgentRepo) Upsert(_ context.Context, a repo.Agent) (repo.Agent, error) {
	m.agents[a.ID] = a
	return a, nil
}

func newMockAgentRepo() *mockAgentRepo {
	return &mockAgentRepo{agents: make(map[string]repo.Agent)}
}

// TestResolveMultisigCaller_AgentAndBroker verifies classification of
// agent + broker signatures in multisig scenario.
func TestResolveMultisigCaller_AgentAndBroker(t *testing.T) {
	agentPub, _, _ := ed25519.GenerateKey(nil)
	brokerPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	agentRepo.agents["agent-001"] = repo.Agent{
		ID:            "agent-001",
		PublicKey:     agentPub,
		RequesterType: "AGENT",
	}
	agentRepo.agents["broker.example"] = repo.Agent{
		ID:            "broker.example",
		PublicKey:     brokerPub,
		RequesterType: "BROKER",
	}

	svc := &ExchangeService{agents: agentRepo}

	verified := []httpsig.VerifiedRequest{
		{KeyID: "agent-001", PublicKey: agentPub},
		{KeyID: "broker.example", PublicKey: brokerPub},
	}

	agent, relay, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err != nil {
		t.Fatalf("resolveMultisigCaller failed: %v", err)
	}

	if agent.KeyID != "agent-001" {
		t.Errorf("agent.KeyID = %q, want %q", agent.KeyID, "agent-001")
	}
	if agent.Kind != CallerAgent {
		t.Errorf("agent.Kind = %v, want CallerAgent", agent.Kind)
	}
	if agent.AgentID != "agent-001" {
		t.Errorf("agent.AgentID = %q, want %q", agent.AgentID, "agent-001")
	}

	if relay == nil {
		t.Fatal("relay is nil, want non-nil")
	}
	if relay.KeyID != "broker.example" {
		t.Errorf("relay.KeyID = %q, want %q", relay.KeyID, "broker.example")
	}
	if relay.Kind != CallerBroker {
		t.Errorf("relay.Kind = %v, want CallerBroker", relay.Kind)
	}
}

// TestResolveMultisigCaller_AgentOnly verifies behavior when only agent
// signature is present (no relay).
func TestResolveMultisigCaller_AgentOnly(t *testing.T) {
	agentPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	agentRepo.agents["agent-002"] = repo.Agent{
		ID:            "agent-002",
		PublicKey:     agentPub,
		RequesterType: "AGENT",
	}

	svc := &ExchangeService{agents: agentRepo}

	verified := []httpsig.VerifiedRequest{
		{KeyID: "agent-002", PublicKey: agentPub},
	}

	agent, relay, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err != nil {
		t.Fatalf("resolveMultisigCaller failed: %v", err)
	}

	if agent.KeyID != "agent-002" {
		t.Errorf("agent.KeyID = %q, want %q", agent.KeyID, "agent-002")
	}
	if agent.Kind != CallerAgent {
		t.Errorf("agent.Kind = %v, want CallerAgent", agent.Kind)
	}

	if relay != nil {
		t.Errorf("relay = %+v, want nil", relay)
	}
}

// TestResolveMultisigCaller_BrokerPrefixNonBrokerType verifies error when
// a keyid has broker prefix but requester_type != "BROKER".
func TestResolveMultisigCaller_BrokerPrefixNonBrokerType(t *testing.T) {
	agentPub, _, _ := ed25519.GenerateKey(nil)
	fakeBrokerPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	agentRepo.agents["agent-003"] = repo.Agent{
		ID:            "agent-003",
		PublicKey:     agentPub,
		RequesterType: "AGENT",
	}
	agentRepo.agents["broker.fake"] = repo.Agent{
		ID:            "broker.fake",
		PublicKey:     fakeBrokerPub,
		RequesterType: "AGENT", // NOT BROKER
	}

	svc := &ExchangeService{agents: agentRepo}

	verified := []httpsig.VerifiedRequest{
		{KeyID: "agent-003", PublicKey: agentPub},
		{KeyID: "broker.fake", PublicKey: fakeBrokerPub},
	}

	_, _, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err == nil {
		t.Fatal("resolveMultisigCaller succeeded, want error")
	}

	var xErr *exchange.Error
	if !errors.As(err, &xErr) {
		t.Fatalf("error is not *exchange.Error: %v", err)
	}
	if xErr.Kind != exchange.KindUnauthenticated {
		t.Errorf("error.Kind = %v, want KindUnauthenticated", xErr.Kind)
	}
}

// TestResolveMultisigCaller_NoAgentSignature verifies error when no agent
// signature is present (only broker).
func TestResolveMultisigCaller_NoAgentSignature(t *testing.T) {
	brokerPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	agentRepo.agents["broker.only"] = repo.Agent{
		ID:            "broker.only",
		PublicKey:     brokerPub,
		RequesterType: "BROKER",
	}

	svc := &ExchangeService{agents: agentRepo}

	verified := []httpsig.VerifiedRequest{
		{KeyID: "broker.only", PublicKey: brokerPub},
	}

	_, _, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err == nil {
		t.Fatal("resolveMultisigCaller succeeded, want error")
	}

	var xErr *exchange.Error
	if !errors.As(err, &xErr) {
		t.Fatalf("error is not *exchange.Error: %v", err)
	}
	if xErr.Kind != exchange.KindUnauthenticated {
		t.Errorf("error.Kind = %v, want KindUnauthenticated", xErr.Kind)
	}
}

// TestResolveMultisigCaller_AgentNotFound verifies error when agent keyid
// is not registered.
func TestResolveMultisigCaller_AgentNotFound(t *testing.T) {
	agentPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	// Deliberately empty repo - agent not registered

	svc := &ExchangeService{agents: agentRepo}

	verified := []httpsig.VerifiedRequest{
		{KeyID: "unknown-agent", PublicKey: agentPub},
	}

	_, _, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err == nil {
		t.Fatal("resolveMultisigCaller succeeded, want error")
	}

	var xErr *exchange.Error
	if !errors.As(err, &xErr) {
		t.Fatalf("error is not *exchange.Error: %v", err)
	}
	if xErr.Kind != exchange.KindUnauthenticated {
		t.Errorf("error.Kind = %v, want KindUnauthenticated", xErr.Kind)
	}
}

// TestResolveMultisigCaller_OrderIndependent verifies that classification
// is order-independent (broker signature can come before agent signature).
func TestResolveMultisigCaller_OrderIndependent(t *testing.T) {
	agentPub, _, _ := ed25519.GenerateKey(nil)
	brokerPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	agentRepo.agents["agent-004"] = repo.Agent{
		ID:            "agent-004",
		PublicKey:     agentPub,
		RequesterType: "AGENT",
	}
	agentRepo.agents["broker.first"] = repo.Agent{
		ID:            "broker.first",
		PublicKey:     brokerPub,
		RequesterType: "BROKER",
	}

	svc := &ExchangeService{agents: agentRepo}

	// Broker signature BEFORE agent signature
	verified := []httpsig.VerifiedRequest{
		{KeyID: "broker.first", PublicKey: brokerPub},
		{KeyID: "agent-004", PublicKey: agentPub},
	}

	agent, relay, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err != nil {
		t.Fatalf("resolveMultisigCaller failed: %v", err)
	}

	if agent.KeyID != "agent-004" {
		t.Errorf("agent.KeyID = %q, want %q", agent.KeyID, "agent-004")
	}
	if relay == nil {
		t.Fatal("relay is nil, want non-nil")
	}
	if relay.KeyID != "broker.first" {
		t.Errorf("relay.KeyID = %q, want %q", relay.KeyID, "broker.first")
	}
}

// TestResolveMultisigCaller_AgentSlotIsBrokerType verifies that a record whose
// keyID lacks the "broker." prefix (so classifySignatures routes it into the
// agent slot) but whose DB requester_type is BROKER is REJECTED. The agent slot
// must be a genuine agent: otherwise the delivery URL would bind to a broker's
// key instead of the agent's (ADR-013). Symmetric to the existing relay-slot
// requester_type check.
func TestResolveMultisigCaller_AgentSlotIsBrokerType(t *testing.T) {
	relayPub, _, _ := ed25519.GenerateKey(nil)
	brokerPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	// "relay-1" has NO "broker." prefix, so it lands in the agent slot — but it
	// is registered as a BROKER. The DB type is authoritative.
	agentRepo.agents["relay-1"] = repo.Agent{
		ID:            "relay-1",
		PublicKey:     relayPub,
		RequesterType: "BROKER",
	}
	agentRepo.agents["broker.example"] = repo.Agent{
		ID:            "broker.example",
		PublicKey:     brokerPub,
		RequesterType: "BROKER",
	}

	svc := &ExchangeService{agents: agentRepo}

	verified := []httpsig.VerifiedRequest{
		{KeyID: "relay-1", PublicKey: relayPub},
		{KeyID: "broker.example", PublicKey: brokerPub},
	}

	_, _, err := svc.resolveMultisigCaller(context.Background(), verified)
	if err == nil {
		t.Fatal("resolveMultisigCaller accepted a BROKER in the agent slot, want error")
	}

	var xErr *exchange.Error
	if !errors.As(err, &xErr) {
		t.Fatalf("error is not *exchange.Error: %v", err)
	}
	if xErr.Kind != exchange.KindUnauthenticated {
		t.Errorf("error.Kind = %v, want KindUnauthenticated", xErr.Kind)
	}
}

// TestResolveCallerAndBinding_LoneBrokerRejected verifies that a single broker
// signature (no agent co-signature) is rejected on the delivery-URL binding
// path. The multisig dispatch gates on signature COUNT (len > 1), so a lone
// broker sig would otherwise fall through to the single-sig branch and bind the
// delivery URL to the broker's own key — there is no agent identity to bind to
// (ADR-013). A broker may only relay WITH an agent signature.
func TestResolveCallerAndBinding_LoneBrokerRejected(t *testing.T) {
	brokerPub, _, _ := ed25519.GenerateKey(nil)

	agentRepo := newMockAgentRepo()
	agentRepo.agents["broker.solo"] = repo.Agent{
		ID:            "broker.solo",
		PublicKey:     brokerPub,
		RequesterType: "BROKER",
	}
	svc := &ExchangeService{agents: agentRepo, logger: discardLogger()}

	// Single verified signature → single-sig path. Tenant permits broker relay,
	// so the only thing that can reject is the lone-broker guard itself.
	ctx := httpsig.NewMultisigContext(context.Background(), []httpsig.VerifiedRequest{
		{KeyID: "broker.solo", PublicKey: brokerPub},
	})
	tenant := repo.Tenant{AllowBrokerRelay: true}

	_, _, err := svc.resolveCallerAndBinding(ctx, "some-agent", tenant)
	if err == nil {
		t.Fatal("resolveCallerAndBinding accepted a lone broker signature, want rejection")
	}

	var xErr *exchange.Error
	if !errors.As(err, &xErr) {
		t.Fatalf("error is not *exchange.Error: %v", err)
	}
	if xErr.Kind != exchange.KindPermissionDenied {
		t.Errorf("error.Kind = %v, want KindPermissionDenied", xErr.Kind)
	}
}
