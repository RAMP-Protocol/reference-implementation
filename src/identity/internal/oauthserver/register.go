package oauthserver

import (
	"encoding/json"
	"net/http"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauth"
)

// maxRegisterBytes bounds a Dynamic Client Registration body — a small JSON object,
// never a payload.
const maxRegisterBytes = 8 << 10

// handleMetadata serves the RFC 8414 authorization-server metadata an MCP client
// reads to discover the endpoints. All URLs are built from the configured Issuer, so
// the document is identical regardless of which host served it.
func (s *Server) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	iss := s.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + AuthorizePath,
		"token_endpoint":                        iss + TokenPath,
		"registration_endpoint":                 iss + RegisterPath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
	})
}

// dcrRequest is the subset of RFC 7591 client metadata this server consumes.
type dcrRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
}

// handleRegister implements RFC 7591 Dynamic Client Registration: an MCP client
// self-registers its loopback redirect URIs and receives a client_id. Clients are
// public (PKCE, no secret), so no client_secret is issued.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req dcrRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRegisterBytes)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed registration body")
		return
	}
	if len(req.RedirectURIs) == 0 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "at least one redirect_uri is required")
		return
	}
	for _, uri := range req.RedirectURIs {
		if !validRedirectURI(uri) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				"redirect_uri must be https or a loopback http URL")
			return
		}
	}

	id, err := randomToken(16)
	if err != nil {
		logError(r, "oauthserver.register.entropy", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	client, err := s.cfg.Clients.RegisterClient(r.Context(), oauth.Client{
		ID:           "mcp-" + id,
		RedirectURIs: req.RedirectURIs,
		Name:         req.ClientName,
	})
	if err != nil {
		s.unavailableOrJSONError(w, r, "oauthserver.register.store", err)
		return
	}
	logInfo(r, "oauthserver.register.ok", "client_id", client.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  client.ID,
		"redirect_uris":              client.RedirectURIs,
		"client_name":                client.Name,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
	})
}
