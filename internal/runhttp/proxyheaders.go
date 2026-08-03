package runhttp

import (
	"net/http"
	"strings"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// TrustProxyHeadersEnv is the opt-in switch for TrustProxyHeaders: a deployment
// sets RAMP_TRUST_PROXY_HEADERS=true only when the service sits behind a
// TLS-terminating proxy it controls (Caddy on the staging VM, an ALB). Each
// cmd/server reads it once at boot via PublicSurfaceOptionsFromEnv — EnvOptIn,
// the strict allowlist, so a typo fails closed — and passes the result through
// its wiring as an explicit flag; nothing reads the env at request time.
const TrustProxyHeadersEnv = "RAMP_TRUST_PROXY_HEADERS"

// TrustProxyHeaders rewrites the inbound request's URL scheme from
// X-Forwarded-Proto, the header a TLS-terminating proxy sets. Signed RAMP
// calls cover @target-uri — the full public URL, scheme included — and the SDK
// verifier prefers URL.Scheme when set, falling back to sniffing the socket
// (plain HTTP behind the proxy → "http") only when it is empty. Rewriting
// before verification makes the service verify against the URL the client
// actually signed.
//
// Deliberately scheme-only. X-Forwarded-Host is NOT honored: the proxy
// preserves the Host header, so the inbound host is already the public one —
// and rewriting the host from a header would let a request signed for one
// endpoint verify at another (the replay store keys on keyID+signature, not
// host), breaking the @target-uri audience binding.
//
// Wire this ONLY when the deployment guarantees a trusted proxy sets the
// header (TrustProxyHeadersEnv). On a directly-exposed service the header is
// caller-controlled: honoring it would let a caller pick the scheme its
// signature is verified against.
//
// Operator contract: the trusted proxy MUST replace (not append to) any
// inbound X-Forwarded-Proto. forwardedProto reads the first comma-separated
// token, so a proxy that appended to a client-supplied value would let the
// client control that first token. Caddy and ALB replace it by default.
func TrustProxyHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := forwardedProto(r.Header.Get("X-Forwarded-Proto"))
		if proto == "" {
			next.ServeHTTP(w, r)
			return
		}
		r2 := r.Clone(r.Context())
		r2.URL.Scheme = proto
		next.ServeHTTP(w, r2)
	})
}

// NormalizeToOriginForm rejects an inbound request whose target is NOT in
// origin form, so downstream @target-uri reconstruction derives the scheme AND
// host from the socket (and, under the opt-in, the scheme from TrustProxyHeaders)
// — never from caller-supplied request bytes.
//
// Legitimate RAMP clients send an origin-form request target (POST /path), and
// a reverse proxy forwards origin-form upstream; net/http leaves URL.Scheme and
// URL.Host empty for both, and for HTTP/2 (the :scheme/:authority pseudo-headers
// land in Host, not URL.Scheme/Host). ONLY an HTTP/1.1 absolute-form request
// line (POST https://host/path — RFC 7230 §5.3.2) makes the server populate
// URL.Scheme/URL.Host from the request line — an attack-only shape here.
//
// We reject rather than sanitize because sanitizing cannot fully close the
// vector: for absolute-form, net/http ALSO sets r.Host from the request-line
// authority and DISCARDS the real Host header, and every verify seam falls back
// to r.Host once URL.Host is empty — so clearing URL.Scheme/Host would still
// leave a caller-chosen host bound into the signature. The real host is
// unrecoverable, so the only complete fix is to refuse the request. Since no
// legitimate client sends absolute-form, refusing it costs nothing.
//
// Wire this OUTERMOST of the URL-normalizing middlewares (before
// TrustProxyHeaders) and ALWAYS — the absolute-form vector does not depend on
// the proxy-trust opt-in, and running after TrustProxyHeaders would reject
// legitimate flag-on traffic whose scheme that middleware just set.
func NormalizeToOriginForm(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Scheme != "" || r.URL.Host != "" {
			// Log before rejecting: this is an attack-only request shape, and
			// the operator's only trace of it is this line. Wired inside
			// RequestIDMiddleware (see WrapPublicSurface), so the scoped
			// logger carries request_id correlation.
			reqctx.FromContext(r.Context()).WarnContext(r.Context(),
				"runhttp.absolute_form_reject",
				"scheme", r.URL.Scheme,
				"host", r.URL.Host,
				"method", r.Method)
			http.Error(w, "absolute-form request target not accepted", http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// NormalizeAndTrustProxy composes the two URL-normalizing middlewares in the one
// correct order and returns the chain wrapping next: NormalizeToOriginForm
// (always, outermost) → TrustProxyHeaders (only when trustProxyHeaders) → next.
// The order is security-load-bearing — NormalizeToOriginForm must run first so
// an absolute-form request is refused BEFORE TrustProxyHeaders sets a scheme
// (reversed, a legitimate flag-on request whose scheme TrustProxyHeaders sets
// would then be rejected as absolute-form). WrapPublicSurface calls this so
// the ordering is decided in exactly one place.
func NormalizeAndTrustProxy(next http.Handler, trustProxyHeaders bool) http.Handler {
	inner := next
	if trustProxyHeaders {
		inner = TrustProxyHeaders(inner)
	}
	return NormalizeToOriginForm(inner)
}

// forwardedProto normalizes an X-Forwarded-Proto value to a URL scheme: first
// comma-separated token (a multi-hop proxy chain appends one entry per hop),
// trimmed and lowercased, accepted only as http or https. Anything else
// returns "" and the request keeps its socket-derived scheme — a malformed
// value can only make verification fail closed, never steer it.
func forwardedProto(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "http" || v == "https" {
		return v
	}
	return ""
}
