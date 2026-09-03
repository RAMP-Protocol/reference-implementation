//go:build integration

package transport_test

// ADR-019 §1 metadata-ride tests for the broker CONNECT sink (BrokerService/
// Resolve). Every broker input-validation reject must carry its offending field
// (or other machine-readable axis) as TYPED rampv1.ErrorDetail.metadata read back
// through the public Connect error envelope — NEVER string-matched on the
// non-authoritative Message (the anti-pattern ADR-019 retired on the exchange
// side, mirrored here onto the broker).
//
// These tests live in a sibling file (not resolve_integration_test.go, which is
// near the 800-line test cap) so coverage is split by scenario, never trimmed
// (Testing Doctrine: split, never shrink).
//
// WHY they are RED on HEAD: broker.Error carries only Kind/Message/Err — no
// Metadata field — and resolveFaultError builds the ErrorDetail with Message +
// Domain only (broker_connect_handler.go), so GetMetadata() is empty for every
// fault. The metadata["field"] / metadata["required_one_of"] assertions therefore
// fail until broker.Error gains Metadata/WithField/WithMeta and the field-bearing
// call sites stamp it.
//
// Round-trip honesty: each leg is a genuine PROTOCOL round-trip — signed Connect
// client → real RFC 9421 signature → real httpsig middleware → registered Connect
// handler → validateResolveRequest / authorize / resolve core → the typed Connect
// transport error the client decodes. The mockExchange (a true external) is the
// only mock; its call counters pin the absence of upstream side effects.

import (
	"context"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// signedResolveFault spins up the signed Connect harness for callerID (its key
// is registered in the resolver), issues the given DiscoveryRequest, and returns
// the server fixture plus the transport error. It asserts the call DID fault
// (the negative-path tests expect a non-nil error). Mirrors resolveOverConnect's
// wiring but returns the error rather than fatal-ing on it.
func signedResolveFault(t *testing.T, fx *fixture, callerID string, req *rampv1.DiscoveryRequest) (*brokerConnectFixture, error) {
	t.Helper()
	pub, priv := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, callerID, pub)
	client := signingBrokerClient(srv.base, srv.server.URL, callerID, priv)
	_, err := client.Resolve(context.Background(), connect.NewRequest(req))
	if err == nil {
		t.Fatal("expected a fault, got nil error")
	}
	return srv, err
}

// TestResolve_AgentIDMissing_CarriesFieldMetadata pins resolve.go:401: an empty
// requester.id is rejected InvalidArgument with metadata["field"]=="agent_id".
// validateResolveRequest runs before authorizeAgentSelfAct, so the empty-id guard
// fires before the verified-key/id binding — the request is signed with a valid
// registered key but names no requester.
func TestResolve_AgentIDMissing_CarriesFieldMetadata(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	// requester.id deliberately empty; sign with a valid registered key.
	req := &rampv1.DiscoveryRequest{
		Ver:       helpers.ProtocolVersion,
		Requester: &rampv1.Requester{Domain: requesterDomain, Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT},
		Query:     ptr("RAMP intro"),
	}
	srv, err := signedResolveFault(t, fx, "agent-1", req)

	assertConnectCodeLocal(t, err, connect.CodeInvalidArgument)
	assertBrokerErrorField(t, err, "field", "agent_id")
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("agent_id reject must not reach upstream: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// TestResolve_QueryAndURIBothEmpty_CarriesRequiredOneOfMetadata pins
// resolve.go:404: a request with neither query nor uri is rejected
// InvalidArgument carrying metadata["required_one_of"]=="query,uri" (the settled
// composite key — there is no single offending field, so no "field" key; ADR-019
// §1 metadata is a free map of axes). requester.id == the signing key so the
// query/uri guard (before authorize) is the cause, not impersonation.
func TestResolve_QueryAndURIBothEmpty_CarriesRequiredOneOfMetadata(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const callerID = "agent-1"
	req := &rampv1.DiscoveryRequest{
		Ver: helpers.ProtocolVersion,
		Requester: &rampv1.Requester{
			Id: callerID, Domain: requesterDomain, Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
		// no Query, no Uris
	}
	srv, err := signedResolveFault(t, fx, callerID, req)

	assertConnectCodeLocal(t, err, connect.CodeInvalidArgument)
	assertBrokerErrorField(t, err, "required_one_of", "query,uri")
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("query|uri reject must not reach upstream: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// TestResolve_UnparseableURI_CarriesFieldMetadata pins resolve.go:198
// (urisToDomains → exa.DomainOf): a caller-supplied uri that url.Parse cannot
// parse fails the WHOLE resolve InvalidArgument with metadata["field"]=="uri".
// "http://[::1" is a deterministic url.Parse failure ("missing ']' in host").
// The request clears the agent_id + query/uri guards and authorize (id == signer)
// so the uri-parse fault is the cause.
func TestResolve_UnparseableURI_CarriesFieldMetadata(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const callerID = "agent-1"
	req := &rampv1.DiscoveryRequest{
		Ver: helpers.ProtocolVersion,
		Requester: &rampv1.Requester{
			Id: callerID, Domain: requesterDomain, Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
		Uris: []string{"http://[::1"},
	}
	srv, err := signedResolveFault(t, fx, callerID, req)

	assertConnectCodeLocal(t, err, connect.CodeInvalidArgument)
	assertBrokerErrorField(t, err, "field", "uri")
	if srv.exchange.discoverCalls != 0 || srv.exchange.executeCalls != 0 {
		t.Errorf("unparseable uri reject must not reach upstream: discover=%d execute=%d",
			srv.exchange.discoverCalls, srv.exchange.executeCalls)
	}
}

// TestResolve_BareFault_CarriesNoMetadata is the negative control for the
// metadata ride: a fault with no single offending field (here an UNSIGNED Resolve
// → Unauthenticated, the same path TestResolve_FaultCarriesErrorDetail drives)
// must carry a typed ErrorDetail with Domain but EMPTY metadata. This proves the
// ride is conditional (only field-bearing rejects stamp metadata) rather than a
// blanket stamp. It already passes for the Domain leg on HEAD; the metadata-empty
// leg stays true after the fix (Unauthenticated is left bare), so this guards
// against a future over-eager stamp.
func TestResolve_BareFault_CarriesNoMetadata(t *testing.T) {
	ctx := context.Background()
	fx := newFixture(t, ctx, fixtureOpts{providerDomain: "acme.example"})

	const callerID = "agent-1"
	pub, _ := newBrokerKeyPair(t)
	srv := startBrokerConnectServer(t, fx, callerID, pub)

	// PLAIN unsigned client — no httpsig context → Unauthenticated, a field-less
	// fault.
	client := rampconnect.NewBrokerServiceClient(srv.server.Client(), srv.server.URL, connect.WithGRPC())
	_, err := client.Resolve(ctx, connect.NewRequest(buildDiscoveryRequest(callerID, reqOpts{query: "RAMP intro"})))

	assertConnectCodeLocal(t, err, connect.CodeUnauthenticated)
	assertBrokerErrorMetadataAbsent(t, err)
}

// ptr returns a pointer to the given string (for optional proto string fields).
func ptr(s string) *string { return &s }
