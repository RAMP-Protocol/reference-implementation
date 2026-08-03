package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/agentsign"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

// ProtectedResourceMetadataPath is where the MCP endpoint publishes its OAuth 2.0
// protected-resource metadata (RFC 9728). An MCP client that meets a 401 reads the
// WWW-Authenticate header, fetches this document, and learns which authorization
// server to sign in against — which is how a client discovers our sign-up flow
// without being configured with its URL.
const ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource"

// bearerVerifier adapts the service's own token.Issuer to the MCP SDK's verifier
// contract. The token was minted by our sign-in and is audience-bound
// to this endpoint, so verification is local: signature, issuer, audience, and
// expiry, with no introspection call.
//
// The subject is the developer's minted subdomain — the durable agent identity —
// and it is carried out as TokenInfo.UserID so the transport layer can also use it
// to pin a session to one user.
//
// A token that fails any check comes back as auth.ErrInvalidToken, which the
// middleware renders as 401 plus the WWW-Authenticate challenge. The reason is
// deliberately not detailed to the caller: which check failed is useful to an
// attacker probing for valid tokens and useless to a legitimate client, whose
// remedy is the same either way — sign in again.
func bearerVerifier(issuer *token.Issuer) auth.TokenVerifier {
	return func(_ context.Context, raw string, _ *http.Request) (*auth.TokenInfo, error) {
		claims, err := issuer.Verify(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", auth.ErrInvalidToken, err)
		}
		if claims.Subject == "" {
			// A token with no subject names no agent. Signing an outbound RAMP
			// request for it is impossible and refusing it here is the honest
			// answer; letting it through would fail later, further from the cause.
			return nil, fmt.Errorf("%w: token carries no subject", auth.ErrInvalidToken)
		}
		if claims.Expiry == nil {
			// The SDK middleware rejects a zero Expiration anyway; failing here
			// names the reason instead of surfacing it as "token missing
			// expiration" from inside the library.
			return nil, fmt.Errorf("%w: token carries no expiry", auth.ErrInvalidToken)
		}
		// NOTE: the SDK re-checks this expiry against the real wall clock, not
		// against the issuer's clock. A test driving a fake clock far from now
		// will therefore have its token rejected here no matter what the issuer
		// thinks — keep test clocks near real time.
		return &auth.TokenInfo{
			UserID:     claims.Subject,
			Expiration: claims.Expiry.Time(),
		}, nil
	}
}

// withAgentIdentity puts the authenticated subdomain where the outbound signer
// looks for it.
//
// This is the ONLY place in the service permitted to call agentsign.WithSubdomain.
// Everything downstream — the tools, the RAMP client, the signing transport —
// takes the agent's identity from the context and never from a tool argument, so
// the question "whose key signs this?" has exactly one answer: whoever's bearer
// token authenticated this request. A second caller of WithSubdomain would be a
// second answer, which is how impersonation gets in.
//
// It runs INSIDE auth.RequireBearerToken, so by the time it executes the token is
// already verified; a missing TokenInfo therefore means the middleware chain was
// assembled wrong, and it fails closed rather than proceeding unidentified.
func withAgentIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := auth.TokenInfoFromContext(r.Context())
		if info == nil || info.UserID == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		ctx := agentsign.WithSubdomain(r.Context(), info.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireBearer wraps h in the bearer gate. resourceURL is this endpoint's own
// identifier, advertised to clients as the `resource` they must obtain a token
// for; metadataURL is where the challenge points them for discovery.
func requireBearer(h http.Handler, issuer *token.Issuer, metadataURL string) http.Handler {
	gate := auth.RequireBearerToken(bearerVerifier(issuer), &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: metadataURL,
	})
	return gate(withAgentIdentity(h))
}

// protectedResourceMetadata builds the RFC 9728 document describing this endpoint:
// the resource identifier clients request a token for, and the authorization
// server that issues it — our own sign-up server, whose metadata already lives at
// oauthserver.MetadataPath on this same origin.
func protectedResourceMetadata(resourceURL, issuerURL string) *oauthex.ProtectedResourceMetadata {
	return &oauthex.ProtectedResourceMetadata{
		Resource:               resourceURL,
		AuthorizationServers:   []string{issuerURL},
		BearerMethodsSupported: []string{"header"},
	}
}

// parseOrigin validates the service's public origin, from which both the resource
// identifier and the metadata URL are derived. An absolute URL is required: both
// values are published to clients that have no other way to resolve them.
func parseOrigin(issuerURL string) (*url.URL, error) {
	if issuerURL == "" {
		return nil, errors.New("mcp: issuer URL is required")
	}
	base, err := url.Parse(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("mcp: parse issuer URL %q: %w", issuerURL, err)
	}
	if !base.IsAbs() || base.Host == "" {
		return nil, fmt.Errorf("mcp: issuer URL %q must be absolute", issuerURL)
	}
	return base, nil
}

// metadataHandler serves an RFC 9728 document with the CORS headers a browser-based
// MCP client needs for discovery.
func metadataHandler(md *oauthex.ProtectedResourceMetadata) http.Handler {
	return auth.ProtectedResourceMetadataHandler(md)
}
