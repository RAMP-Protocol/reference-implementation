//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// These tests pin the RAMP-171 staging topology: a TLS-terminating proxy
// (Caddy) fronts the Exchange, so the caller signs the https @target-uri while
// the service socket sees plain HTTP plus X-Forwarded-Proto. With
// trust-proxy-headers wired (RAMP_TRUST_PROXY_HEADERS), verification must run
// against the forwarded scheme; without it, the caller-controlled header must
// be ignored — a directly-exposed service must not let a caller pick the
// scheme its signature is verified against.

// proxiedCatalogClient signs catalog pushes over the https URL and delivers
// them through the simulated TLS-terminating proxy.
func proxiedCatalogClient(
	t *testing.T, h *pushHarness, callerID string, priv ed25519.PrivateKey,
) rampconnect.CatalogServiceClient {
	t.Helper()
	rt := newSigningTransport(testutil.TLSTerminatingProxyTransport{Base: h.baseTransport}, callerID, priv)
	return rampconnect.NewCatalogServiceClient(
		&http.Client{Transport: rt}, testutil.HTTPSVariant(t, h.server.URL), connect.WithGRPC(),
	)
}

// proxiedExchangeClient is the ExchangeService analogue of
// proxiedCatalogClient, signing with the harness's registered discover key so
// the request must clear the connectserver verify seam.
func proxiedExchangeClient(t *testing.T, h *pushHarness) rampconnect.ExchangeServiceClient {
	t.Helper()
	rt := newSigningTransport(testutil.TLSTerminatingProxyTransport{Base: h.baseTransport}, h.discoverKeyID, h.discoverPriv)
	return rampconnect.NewExchangeServiceClient(
		&http.Client{Transport: rt}, testutil.HTTPSVariant(t, h.server.URL), connect.WithGRPC(),
	)
}

// proxiedPush drives one 1-entry catalog push through the proxied shape for
// caller.example (published + listed as contributor) and returns the error.
// The entry carries a priced term so an accepted push materializes an offer
// discoverable through DiscoverResources — the side-effect surface both the
// positive and negative tests assert on.
func proxiedPush(t *testing.T, h *pushHarness, path string) error {
	t.Helper()
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen caller key: %v", err)
	}
	h.publishAgent(t, callerID, pub)

	client := proxiedCatalogClient(t, h, callerID, priv)
	_, err = client.PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: path,
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	}))
	return err
}

// TestPushResources_ProxiedTLSTermination_VerifiesForwardedScheme proves the
// staging shape end-to-end: socket is plain HTTP, X-Forwarded-Proto: https,
// signature minted over the https URL — with trust-proxy-headers wired the
// per-contributor catalog gate verifies and the push lands. Protocol
// round-trip: signed push RPC in, offer read back through DiscoverResources.
func TestPushResources_ProxiedTLSTermination_VerifiesForwardedScheme(t *testing.T) {
	h := newPushHarnessShaped(t, true)
	if err := proxiedPush(t, h, "/articles/proxied"); err != nil {
		t.Fatalf("proxied push: %v", err)
	}
	uri := "https://" + h.publisherDom + "/articles/proxied"
	if got := discoverOfferCount(t, h, uri); got != 1 {
		t.Fatalf("offers = %d, want 1", got)
	}
}

// TestPushResources_DirectExposure_SpoofedForwardedProtoIgnored proves the
// directly-exposed shape: without the opt-in, a caller-supplied
// X-Forwarded-Proto must NOT change the verified scheme — the https-signed
// request fails against the socket's http URL and nothing is ingested.
func TestPushResources_DirectExposure_SpoofedForwardedProtoIgnored(t *testing.T) {
	h := newPushHarness(t)
	err := proxiedPush(t, h, "/articles/spoofed")
	assertConnectCode(t, err, connect.CodeUnauthenticated)
	uri := "https://" + h.publisherDom + "/articles/spoofed"
	if got := discoverOfferCount(t, h, uri); got != 0 {
		t.Fatalf("offers = %d, want 0 (rejected push must not ingest)", got)
	}
}

// TestExchangeRPC_ProxiedTLSTermination_VerifiesForwardedScheme proves the
// SDK connectserver verify seam (the main signed-RPC surface) honors the
// forwarded scheme when trust-proxy-headers is wired: a DiscoverResources
// signed over https and delivered over the proxied plain-HTTP leg clears the
// gate and returns the offer a plain-shape push seeded.
func TestExchangeRPC_ProxiedTLSTermination_VerifiesForwardedScheme(t *testing.T) {
	h := newPushHarnessShaped(t, true)
	// Seed through the unproxied shape (no forwarded headers → rewrite is a
	// no-op, schemes agree at http), so the assertion isolates the proxied leg.
	callerID := "caller.example"
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen caller key: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	if _, err := h.signedCat(callerID, priv).PushResources(h.ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: h.tenantID,
		CallerId: callerID,
		Entries: []*rampv1.ResourceEntry{{
			Domain: h.publisherDom, Path: "/articles/seeded",
			Terms: []*rampv1.LicenseTerm{seedPricedTerm()},
		}},
	})); err != nil {
		t.Fatalf("seed push: %v", err)
	}

	discovered, err := proxiedExchangeClient(t, h).DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{"https://" + h.publisherDom + "/articles/seeded"},
		Requester: &rampv1.Requester{
			Id: h.discoverKeyID, Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	if err != nil {
		t.Fatalf("proxied discover: %v", err)
	}
	if got := len(discovered.Msg.GetOffers()); got != 1 {
		t.Fatalf("offers = %d, want 1", got)
	}
}

// TestExchangeRPC_DirectExposure_SpoofedForwardedProtoIgnored proves the
// connectserver seam ignores a spoofed X-Forwarded-Proto without the opt-in:
// the https-signed request verifies against the socket's http URL and is
// rejected unauthenticated.
func TestExchangeRPC_DirectExposure_SpoofedForwardedProtoIgnored(t *testing.T) {
	h := newPushHarness(t)
	_, err := proxiedExchangeClient(t, h).DiscoverResources(h.ctx, connect.NewRequest(&rampv1.ResourceQuery{
		Ver:  "1.0",
		Uris: []string{"https://" + h.publisherDom + "/articles/any"},
		Requester: &rampv1.Requester{
			Id: h.discoverKeyID, Domain: "agent.example",
			Type: rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		},
	}))
	assertConnectCode(t, err, connect.CodeUnauthenticated)
}
