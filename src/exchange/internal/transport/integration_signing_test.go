//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

// How a test client signs its requests. Split out of integration_helper_test.go
// when that file crossed the 800-line test cap; these three are one topic and
// are used by both harnesses in this package, so they travel together.

// newSigningTransport builds the canonical RAMP RFC 9421 signing
// http.RoundTripper (sdk/go/core.NewSigningTransport) so tests exercise the
// real middleware path with byte-identical signatures to production. Both
// ExchangeService and CatalogService /ramp.* paths are signed (the
// CatalogService gets verified by CatalogSignatureMiddleware downstream;
// the global httpsig gate excludes Catalog via the predicate but the
// per-contributor signer still requires the same outbound signature).
// Non-/ramp.* paths (e.g. /exchange/v1/agents/register) pass through
// unsigned — the shared transport skips them.
//
// expires is sourced from a per-transport monotonic counter
// (seeded at the wall-clock second) rather than the wall clock. The signing
// library stamps created=now() itself (no caller override), so expires is
// the sole caller-controlled freshness axis; a strictly-increasing expires
// is what keeps each on-the-wire signature unique. Without it, two
// back-to-back calls within the same second carry identical body +
// identical created + identical expires, producing the same signature, and
// the replay store at the global httpsig
// middleware rejects the second as a replay — even when the test is
// exercising service-layer idempotency (e.g.
// TestExecuteTransaction_Idempotency). Real clients retrying after a
// network blip naturally advance the clock per retry; the counter
// simulates that. The +3600 keeps the value inside the verifier's window
// check while the increment guarantees signature uniqueness.
func newSigningTransport(base http.RoundTripper, keyID string, priv ed25519.PrivateKey) http.RoundTripper {
	var counter atomic.Int64
	counter.Store(time.Now().Unix())
	// Both axes derive from the monotonic counter so back-to-back signatures
	// stay unique (the replay-store dodge). The +3600 keeps expires inside the
	// verifier's freshness window; created is the counter base so created ≤ expires.
	win := core.Window(func() (created, expires int64) {
		base := counter.Add(1)
		return base, base + 3600
	})
	// After the WBA split keyID names the signer's directory (Signature-Agent);
	// the RFC 9421 keyid is priv's RFC 7638 thumbprint.
	return core.NewSigningTransport(
		mustSigner(priv), base,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithSignatureAgent(keyID),
		core.WithWindow(win),
	)
}

// mustSigner derives the thumbprint keyid and builds the Ed25519 signer.
func mustSigner(priv ed25519.PrivateKey) helpers.Signer {
	keyid, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		panic(err)
	}
	signer, err := helpers.NewEd25519Signer(keyid, priv)
	if err != nil {
		panic(err)
	}
	return signer
}

// mustCatalogClient wires the ingest push path's SDK catalog client for tests
// — the constructor the CLI runs, against exchangeURL, signing as kid — so
// every ingest test pushes through exactly the client production pushes
// through.
func mustCatalogClient(t *testing.T, exchangeURL, kid string, priv ed25519.PrivateKey) *sdkconnect.CatalogClient {
	t.Helper()
	client, err := ingest.NewCatalogClient(exchangeURL, kid, priv, nil)
	if err != nil {
		t.Fatalf("build catalog client: %v", err)
	}
	return client
}
