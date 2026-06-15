package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// httpContextKey holds the raw http.Request + body bytes so the CatalogHandler
// can enforce RFC 9421 signature verification without requiring the service
// layer to know about transport. Populated by CatalogSignatureMiddleware and
// consumed by CatalogHandler.PushResources.
type httpContextKey struct{}

type catalogSignatureCtx struct {
	request *http.Request
	body    []byte
}

// CatalogSignatureMiddleware captures the raw http.Request and body bytes for
// ramp.v1.CatalogService requests and threads them through the context so the
// downstream Connect handler can verify RFC 9421 HTTP Message Signatures.
//
// Only the CatalogService path is wrapped; other services are left untouched
// so their body streams are not buffered.
func CatalogSignatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isCatalogPush(r) {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), httpContextKey{}, &catalogSignatureCtx{request: r, body: body})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isCatalogPush(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		r.URL != nil &&
		r.URL.Path == rampconnect.CatalogServicePushResourcesProcedure
}

// CatalogHandler adapts CatalogService to the generated connect interface.
type CatalogHandler struct {
	rampconnect.UnimplementedCatalogServiceHandler
	svc      *service.CatalogService
	registry agentreg.Registry
}

// NewCatalogHandler wires the handler. registry is used for Gate 1
// (RFC 9421 caller-signature verification with lazy self-signup).
func NewCatalogHandler(svc *service.CatalogService, registry agentreg.Registry) *CatalogHandler {
	return &CatalogHandler{svc: svc, registry: registry}
}

// PushResources handles ramp.v1.CatalogService/PushResources.
func (h *CatalogHandler) PushResources(
	ctx context.Context,
	req *connect.Request[rampv1.PushResourcesRequest],
) (*connect.Response[rampv1.PushResourcesResponse], error) {
	if err := h.verifyCallerSignature(ctx, req.Msg.GetCallerId()); err != nil {
		return nil, err
	}
	out, err := h.svc.PushResources(ctx, req.Msg)
	if err != nil {
		return nil, exchange.ToConnect(err)
	}
	return connect.NewResponse(out), nil
}

// verifyCallerSignature enforces Gate 1. The middleware must have populated
// the context with raw body + headers; verification is retried once after a
// manifest-driven self-signup attempt when keyid is unknown.
func (h *CatalogHandler) verifyCallerSignature(ctx context.Context, callerID string) error {
	sigCtx, ok := ctx.Value(httpContextKey{}).(*catalogSignatureCtx)
	if !ok || sigCtx == nil {
		return connect.NewError(connect.CodeInternal, errors.New("catalog: signature middleware missing"))
	}
	lookup := func(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
		return h.registry.LookupPublicKey(ctx, keyID)
	}
	if _, err := httpsig.Verify(ctx, sigCtx.request, sigCtx.body, lookup); err != nil {
		if !errors.Is(err, agentreg.ErrUnknown) {
			return connect.NewError(connect.CodeUnauthenticated, err)
		}
		if callerID == "" {
			return connect.NewError(connect.CodeUnauthenticated, err)
		}
		if regErr := h.registry.RegisterFromManifest(ctx, callerID, callerID); regErr != nil {
			return connect.NewError(connect.CodeUnauthenticated, regErr)
		}
		if _, err := httpsig.Verify(ctx, sigCtx.request, sigCtx.body, lookup); err != nil {
			return connect.NewError(connect.CodeUnauthenticated, err)
		}
	}
	return nil
}
