//go:build integration

package transport_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"google.golang.org/protobuf/encoding/protojson"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig/transportconnect"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// This file covers the request cap on the catalog mount, both quantities it
// bounds. The raw body first: the push endpoint is pre-auth, and
// CatalogSignatureMiddleware buffers the whole body so the handler can verify
// the contributor's RFC 9421 signature over the exact bytes, before the caller
// is known. That bound therefore has to refuse before verification, and refuse
// as a resource limit rather than as an authentication failure. Nothing tested
// it before: the LimitReader that used to sit there
// TRUNCATED an over-cap body, and the truncated bytes were misreported one
// layer down — a JSON push cut short answered InvalidArgument ("unexpected
// EOF"), and a body that still decoded failed the content digest and answered
// Unauthenticated — never as the size limit the caller had hit.
//
// The ExchangeService mount's twin of this bound is covered in
// exchange_register_size_limit_e2e_test.go. The two mounts reach it by
// different means — the SDK's verify face there, the capture middleware here —
// and have to answer an over-cap body the same way.
//
// The overshoot past the cap is small on purpose. The server refuses as soon as
// the cap is crossed and discards what remains of the body before answering; a
// request with megabytes still unsent would meet a closed connection instead
// of the 413.
const bodyCapOvershoot = 4096

// catalogPushJSON renders a conformant push for one path under the harness
// publisher as Connect JSON in proto field names, the encoding the mount's
// codec serves. Padded past the cap by padJSON it is still this same push once
// parsed, so a mount with no bound would accept and store it.
func catalogPushJSON(t *testing.T, h *pushHarness, callerID, path string) []byte {
	t.Helper()
	req := newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
		Domain: h.publisherDom,
		Path:   path,
		Terms:  []*rampv1.LicenseTerm{seedPricedTerm()},
	}})
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(req)
	if err != nil {
		t.Fatalf("marshal push: %v", err)
	}
	return body
}

// TestPushResources_CatalogBodyOverCapIsRefusedAsResourceExhausted drives a
// push padded past MaxRPCReadBytes at the real route, twice. Signed by an
// admitted contributor, it proves the classification: the refusal is a
// resource limit (413, resource_exhausted), never Unauthenticated, and the URI
// the push names does not become discoverable — a conformant push that would
// have been stored had the bound been missing. Unsigned, it proves the
// ordering: the bound bites before verification, so the caller it exists for,
// one that never authenticates, is refused by size and not by signature.
//
// Both subtests also read what the server WROTE DOWN. The response code says
// what the caller was told; the audit line says what an operator can find
// afterwards, and the operator documentation describes an
// outcome=body_too_large line for exactly this refusal. This mount has no
// verify seam to hook the observer to, so the capture middleware calls it
// itself, and nothing but this assertion holds it there.
func TestPushResources_CatalogBodyOverCapIsRefusedAsResourceExhausted(t *testing.T) {
	const callerID = "caller.example"

	t.Run("signed contributor", func(t *testing.T) {
		h := newPushHarness(t)
		h.publisher.setContributors(callerID)
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("caller key: %v", err)
		}
		h.publishAgent(t, callerID, pub)
		signing := newSigningTransport(h.baseTransport, callerID, priv)

		const path = "/cap/body-over-signed"
		body := padJSON(catalogPushJSON(t, h, callerID, path), transport.MaxRPCReadBytes+bodyCapOvershoot)
		reply := postRawConnect(t, signing, h.server.URL+rampconnect.CatalogServicePushResourcesProcedure, body)
		assertRefusedTooLarge(t, reply)
		assertRejectOutcome(t, h.logs.String(), transportconnect.OutcomeBodyTooLarge)
		assertOfferCount(t, h, "https://"+h.publisherDom+path, 0)
	})

	t.Run("unsigned caller", func(t *testing.T) {
		h := newPushHarness(t)
		h.publisher.setContributors(callerID)

		const path = "/cap/body-over-unsigned"
		body := padJSON(catalogPushJSON(t, h, callerID, path), transport.MaxRPCReadBytes+bodyCapOvershoot)
		reply := postRawConnect(t, h.baseTransport, h.server.URL+rampconnect.CatalogServicePushResourcesProcedure, body)
		assertRefusedTooLarge(t, reply)
		// The unsigned caller is the one this assertion is worth most for: with
		// no line at all an operator finds nothing, and with the wrong line
		// finds a signature failure for a caller that simply sent too much.
		assertRejectOutcome(t, h.logs.String(), transportconnect.OutcomeBodyTooLarge)
		assertOfferCount(t, h, "https://"+h.publisherDom+path, 0)
	})
}

// TestPushResources_CatalogBodyUnderCapReachesVerification is the half without
// which the test above proves too little. An unsigned, conformant push under
// the cap has to get PAST the size gate and be refused by Gate 1 instead —
// 401, unauthenticated — the same refusal TestPushResources_UnsignedRequestRejected
// observes through the Connect client. The body is a real push rather than
// arbitrary bytes because the validate interceptor runs before Gate 1 on this
// mount: a malformed body would be refused as InvalidArgument and never show
// whether the size gate let it through.
func TestPushResources_CatalogBodyUnderCapReachesVerification(t *testing.T) {
	const callerID = "caller.example"
	h := newPushHarness(t)
	h.publisher.setContributors(callerID)

	body := padJSON(catalogPushJSON(t, h, callerID, "/cap/body-under"), 128)
	reply := postRawConnect(t, h.baseTransport, h.server.URL+rampconnect.CatalogServicePushResourcesProcedure, body)
	assertReachedVerification(t, reply)
}

// TestPushResources_CatalogMessageOverCapIsResourceExhausted proves the second
// quantity bounded on this mount, the DECOMPRESSED message — the one the read
// cap in CatalogMountOptions exists for. For an uncompressed body the
// middleware's raw bound bites first, so only a compressed push can reach the
// message bound at all, and without this test nothing would notice that cap
// going. The client sends gzip: the raw body the middleware captures stays a
// few kilobytes, while the message it inflates to crosses MaxRPCReadBytes and
// the handler's decode refuses it as ResourceExhausted — before the validate
// interceptor, Gate 1 or the service run. Nothing is stored: the URI the push
// names yields no offer.
//
// The push is signed by an admitted contributor so that, with no cap, nothing
// before the wire tier would have refused it. The padding rides in the entry's
// title, which the wire tier WOULD refuse as over its length had the message
// been decoded — so the code is what proves which bound answered:
// ResourceExhausted from the decode, not InvalidArgument from the interceptor.
func TestPushResources_CatalogMessageOverCapIsResourceExhausted(t *testing.T) {
	const callerID = "caller.example"
	h := newPushHarness(t)
	h.publisher.setContributors(callerID)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("caller key: %v", err)
	}
	h.publishAgent(t, callerID, pub)
	gz := rampconnect.NewCatalogServiceClient(
		&http.Client{Transport: newSigningTransport(h.baseTransport, callerID, priv)},
		h.server.URL, connect.WithGRPC(), connect.WithSendGzip(),
	)

	const path = "/cap/message-over"
	title := strings.Repeat("x", transport.MaxRPCReadBytes+bodyCapOvershoot)
	_, err = gz.PushResources(h.ctx, connect.NewRequest(newPushRequest(h.tenantID, callerID, []*rampv1.ResourceEntry{{
		Domain: h.publisherDom,
		Path:   path,
		Title:  &title,
		Terms:  []*rampv1.LicenseTerm{seedPricedTerm()},
	}})))
	assertConnectCode(t, err, connect.CodeResourceExhausted)
	assertOfferCount(t, h, "https://"+h.publisherDom+path, 0)
}
