package runhttp

import (
	"log/slog"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// PublicSurfaceOptions carries the deployment-shape switches WrapPublicSurface
// wires. TrustProxyHeaders mirrors TrustProxyHeadersEnv: true only when the
// service sits behind a trusted TLS-terminating proxy, so signature
// verification runs against the public https URL the caller signed instead of
// the plain-HTTP socket the proxy forwards.
type PublicSurfaceOptions struct {
	TrustProxyHeaders bool
}

// PublicSurfaceOptionsFromEnv reads the deployment-shape switches from the
// process environment, for a composition root wiring its public surface at
// boot. TrustProxyHeaders comes from TrustProxyHeadersEnv via EnvOptIn, not
// EnvBool: trusting proxy headers on a directly-exposed service lets the
// caller pick the scheme its signature verifies against, so a typo must leave
// the flag off, not turn it on.
func PublicSurfaceOptionsFromEnv() PublicSurfaceOptions {
	return PublicSurfaceOptions{TrustProxyHeaders: EnvOptIn(TrustProxyHeadersEnv)}
}

// WrapPublicSurface assembles the outermost HTTP middleware both services
// share — reqctx.RequestIDMiddleware → NormalizeToOriginForm →
// (TrustProxyHeaders, opt-in) → inner. Mounting the URL-normalizing layers
// outside the inner handler fixes the @target-uri before every verifying
// surface inside it sees the request; the order-critical NormalizeToOriginForm
// → TrustProxyHeaders pair is composed once in NormalizeAndTrustProxy. Each
// service's transport package keeps a thin WrapPublicSurface that supplies its
// inner handler (the Exchange inserts its catalog-signature capture, the
// Broker passes its mux bare), so a new deployment-shape switch lands here
// once and reaches both services.
func WrapPublicSurface(
	logger *slog.Logger,
	inner http.Handler,
	opts PublicSurfaceOptions,
) http.Handler {
	return reqctx.RequestIDMiddleware(logger, NormalizeAndTrustProxy(inner, opts.TrustProxyHeaders))
}
