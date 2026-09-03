package transport

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
)

// RegisterPath is the public path for agent self-signup.
const RegisterPath = "POST /exchange/v1/agents/register"

// Defaults for AgentsRegisterOptions.
const (
	defaultRatePerMinutePerIP = 10
	defaultMaxBodyBytes       = 4 * 1024
)

// AgentsRegisterOptions tunes the handler. Zero values select sensible
// defaults: 10 req/min/IP, 4 KB body cap.
type AgentsRegisterOptions struct {
	RatePerMinutePerIP int
	MaxBodyBytes       int64
	// LimiterFactory overrides per-IP limiter construction. When nil the
	// handler builds a token-bucket limiter sized from RatePerMinutePerIP
	// with burst=1 so the very first over-budget call trips 429. Tests
	// inject this to build deterministic limiters.
	LimiterFactory func() *rate.Limiter
}

// AgentsRegisterHandler handles POST /exchange/v1/agents/register. It
// body-caps, rate-limits per client IP, and delegates to agentreg.Registry.
type AgentsRegisterHandler struct {
	registry     agentreg.Registry
	maxBodyBytes int64
	newLimiter   func() *rate.Limiter
	mu           sync.Mutex
	limiters     map[string]*rate.Limiter
}

// NewAgentsRegisterHandler constructs the handler. The registry is required.
// Request-scoped logging flows through reqctx.FromContext — the
// RequestIDMiddleware attaches a request_id-scoped logger to the context — so
// the handler holds no logger of its own.
func NewAgentsRegisterHandler(
	registry agentreg.Registry,
	opts AgentsRegisterOptions,
) *AgentsRegisterHandler {
	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	factory := opts.LimiterFactory
	if factory == nil {
		rpm := opts.RatePerMinutePerIP
		if rpm <= 0 {
			rpm = defaultRatePerMinutePerIP
		}
		perSecond := float64(rpm) / 60.0
		factory = func() *rate.Limiter {
			return rate.NewLimiter(rate.Limit(perSecond), 1)
		}
	}
	return &AgentsRegisterHandler{
		registry:     registry,
		maxBodyBytes: maxBody,
		newLimiter:   factory,
		limiters:     make(map[string]*rate.Limiter),
	}
}

// RegisterRoutes mounts the handler at RegisterPath on mux.
func (h *AgentsRegisterHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle(RegisterPath, h)
}

// registerRequest is the request body shape.
type registerRequest struct {
	AgentID      string `json:"agent_id"`
	DiscoveryURL string `json:"discovery_url"`
}

type registerResponse struct {
	Status  string `json:"status"`
	AgentID string `json:"agent_id"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func (h *AgentsRegisterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	clientIP := clientIPFromRequest(r)
	if !h.allow(clientIP) {
		reqctx.FromContext(r.Context()).WarnContext(r.Context(), "agents.register rate-limited",
			"client_ip", clientIP)
		writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	req, errCode, errMsg := h.decodeRequest(r)
	if errCode != 0 {
		writeJSONError(w, errCode, errMsg)
		return
	}
	if err := h.registry.RegisterFromDirectory(r.Context(), req.AgentID, req.DiscoveryURL); err != nil {
		status, msg := classifyRegisterError(err)
		reqctx.FromContext(r.Context()).WarnContext(r.Context(), "agents.register failed",
			"agent_id", req.AgentID, "client_ip", clientIP,
			"status", status, "err", err)
		writeJSONError(w, status, msg)
		return
	}
	reqctx.FromContext(r.Context()).InfoContext(r.Context(), "agents.register ok",
		"agent_id", req.AgentID, "client_ip", clientIP)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(registerResponse{
		Status: "registered", AgentID: req.AgentID,
	})
}

// decodeRequest reads + validates the body. Returns (req, 0, "") on success,
// or (zero, status, msg) on error.
func (h *AgentsRegisterHandler) decodeRequest(r *http.Request) (registerRequest, int, string) {
	// Read up to MaxBodyBytes+1 so we can tell oversized from exact-cap.
	limited := io.LimitReader(r.Body, h.maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return registerRequest{}, http.StatusBadRequest, "read body: " + err.Error()
	}
	if int64(len(body)) > h.maxBodyBytes {
		return registerRequest{}, http.StatusRequestEntityTooLarge, "request body too large"
	}
	if len(body) == 0 {
		return registerRequest{}, http.StatusBadRequest, "empty request body"
	}
	var req registerRequest
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return registerRequest{}, http.StatusBadRequest, "malformed json: " + err.Error()
	}
	req.AgentID = strings.TrimSpace(req.AgentID)
	req.DiscoveryURL = strings.TrimSpace(req.DiscoveryURL)
	if req.AgentID == "" {
		return registerRequest{}, http.StatusBadRequest, "agent_id required"
	}
	if req.DiscoveryURL == "" {
		return registerRequest{}, http.StatusBadRequest, "discovery_url required"
	}
	// Canonicalize here, at the edge, so req.AgentID IS the row agentreg will
	// write. The handler echoes this field back as the registered identity and
	// logs it; left raw, a caller that posted "https://a.example" was told it had
	// registered "https://a.example" while the table held "a.example" — an answer
	// naming a row that does not exist, and an operator search that finds nothing.
	agentID, err := agentid.FromDirectory(req.AgentID)
	if err != nil {
		// Curated, like every other answer this endpoint gives — including
		// classifyRegisterError's arm for the same fault class reached through the
		// registry. Returning err.Error() here made one condition arrive in two
		// shapes depending on which check caught it first, and leaked the internal
		// wrapping to an unauthenticated caller. This branch can name the field
		// outright, which the registry-side arm cannot: it knows only that one of
		// the two submitted values is not a host.
		return registerRequest{}, http.StatusBadRequest, "agent_id does not name a host"
	}
	req.AgentID = agentID
	return req, 0, ""
}

// allow returns true when the client IP is under its per-minute budget.
func (h *AgentsRegisterHandler) allow(ip string) bool {
	h.mu.Lock()
	lim, ok := h.limiters[ip]
	if !ok {
		lim = h.newLimiter()
		h.limiters[ip] = lim
	}
	h.mu.Unlock()
	return lim.Allow()
}

// classifyRegisterError maps registry errors to HTTP status + client message.
//
// agentreg.IsCallerFault decides the status, and it is the ONLY thing that does.
// That function is the single definition of "permanent caller fault vs transient
// upstream failure", shared with service.mapLazyRegisterError and the catalog
// self-signup handler; this endpoint used to make the same split by hand and
// disagreed with it on one sentinel. An agent that serves no key directory was
// answered here with 502 "failed to fetch", telling the caller to retry, and
// answered 401 on the other two paths, telling it the identity is not
// registrable. Reading the split from one function means a sentinel added to the
// caller-fault set later cannot reintroduce that disagreement: it gets a 400
// with the closing message below rather than a 502 that invites a retry which
// can never succeed.
//
// The 400 arms differ only in wording, because each names a different repair.
// Every message names the document the Exchange actually reads: the agent's Web
// Bot Auth key directory. It fetches no ramp.json for a registering agent, so a
// message blaming a manifest would send the caller to repair a document that has
// no bearing on the outcome.
func classifyRegisterError(err error) (int, string) {
	if !agentreg.IsCallerFault(err) {
		return http.StatusBadGateway, "failed to fetch the agent's key directory"
	}
	switch {
	case errors.Is(err, agentreg.ErrNotAHost):
		// Its own arm because the caller's repair is different: nothing was
		// fetched and no two hosts disagree — one of the two submitted values is
		// simply not a host. Blaming a malformed document here sent the caller to
		// inspect one the Exchange never retrieved.
		return http.StatusBadRequest, "agent_id or discovery_url does not name a host"
	case errors.Is(err, agentreg.ErrAgentIDMismatch):
		return http.StatusBadRequest, "discovery_url host does not match agent_id"
	case errors.Is(err, rampwellknown.ErrNoDocument):
		// The fetch SUCCEEDED and the origin answered 404. Saying the fetch
		// failed described the caller's network, when the repair is to publish
		// the document.
		return http.StatusBadRequest, "the agent serves no key directory at discovery_url"
	case errors.Is(err, agentreg.ErrMalformedDirectory):
		return http.StatusBadRequest, "the agent's key directory is malformed"
	case errors.Is(err, agentreg.ErrNoValidKey):
		return http.StatusBadRequest, "the agent's key directory has no currently valid key"
	default:
		return http.StatusBadRequest, "the agent's key directory cannot establish this identity"
	}
}

// clientIPFromRequest extracts the caller's IP. We prefer RemoteAddr split on
// port to avoid trusting spoofable forwarding headers; deployments that need
// X-Forwarded-For honoring should terminate TLS at a trusted proxy and strip
// the header.
func clientIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}
