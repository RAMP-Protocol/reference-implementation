// Package agentreg wires agent public-key registration on top of repo.AgentRepo.
//
// The Exchange trusts callers whose Ed25519 public keys are published in the
// /.well-known/ramp.json manifest their own domain serves. LookupPublicKey
// returns the registered key; RegisterFromManifest fetches the manifest via the
// shared rampwellknown library, checks its domain anchors the asserted
// agent_id, selects the key whose validity window covers the registry clock,
// and upserts the raw 32-byte Ed25519 key via repo.AgentRepo. The manifest's
// role is not constrained — the caller may be an agent or a publisher
// self-registering to push its own catalog; the domain binding is the boundary.
package agentreg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// ErrUnknown is returned when LookupPublicKey has no registration for the agent.
var ErrUnknown = errors.New("agentreg: unknown agent")

// ErrNoValidKey is returned when a manifest has no key whose validity window
// covers the registry's current clock reading.
var ErrNoValidKey = errors.New("agentreg: no currently valid key in manifest")

// ErrAgentIDMismatch is returned when the manifest's domain (the agent's
// identity anchor in the unified RAMP model) does not match the agent_id the
// caller asserted.
var ErrAgentIDMismatch = errors.New("agentreg: manifest domain does not match request")

// ErrMalformedManifest is returned when the manifest fails schema validation,
// carries a non-AGENT role, or its selected key cannot be decoded.
var ErrMalformedManifest = errors.New("agentreg: malformed manifest")

// HTTPDoer is the minimal http.Client contract the registry needs.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Clock is the narrow time port consumed by the registry — only Now is
// needed because key-window selection is the sole consumer. Production
// callers wire clock.System{} from internal/clock; tests pass a
// deterministic implementation. See ADR-008 D1.
type Clock interface {
	Now() time.Time
}

// Registry is the agent public-key registry contract used by Exchange handlers.
type Registry interface {
	LookupPublicKey(ctx context.Context, agentID string) (ed25519.PublicKey, error)
	RegisterFromManifest(ctx context.Context, agentID, manifestURL string) error
}

// Config bundles registry constructor dependencies.
type Config struct {
	Repo    repo.AgentRepo
	HTTP    HTTPDoer
	Clock   Clock
	Timeout time.Duration
	// Scheme/Port shape the manifest fetch URL for bare-host agent IDs on
	// local/compose stacks (RAMP_MANIFEST_FETCH_{SCHEME,PORT}); empty means
	// https + default port. They MUST match what the httpsig per-agent resolver
	// (agentkeys) uses, so transport-key verification and service-side
	// registration fetch the same document.
	Scheme string
	Port   string
}

// New constructs a Registry. When nil, HTTP defaults to the SSRF-guarded env
// client (rampwellknown.NewGuardedClientFromEnv) and Clock to the system clock.
// The guarded default mirrors every sibling .well-known fetch constructor
// (rampwellknown.Fetch/NewCache, broker probe.New): agents/register is an
// unauthenticated, caller-controlled fetch path, so a fail-open http.DefaultClient
// would re-open SSRF-to-metadata the moment a caller omitted the client.
func New(cfg Config) Registry {
	if cfg.HTTP == nil {
		cfg.HTTP = rampwellknown.NewGuardedClientFromEnv()
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &registry{
		repo:    cfg.Repo,
		http:    cfg.HTTP,
		clock:   cfg.Clock,
		timeout: cfg.Timeout,
		scheme:  cfg.Scheme,
		port:    cfg.Port,
	}
}

type registry struct {
	repo    repo.AgentRepo
	http    HTTPDoer
	clock   Clock
	timeout time.Duration
	scheme  string
	port    string
}

func (r *registry) LookupPublicKey(ctx context.Context, agentID string) (ed25519.PublicKey, error) {
	a, err := r.repo.ByID(ctx, agentID)
	if err != nil {
		if errors.Is(err, repo.ErrAgentNotFound) {
			return nil, ErrUnknown
		}
		return nil, fmt.Errorf("agentreg: repo lookup: %w", err)
	}
	if len(a.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("agentreg: stored key length %d != %d", len(a.PublicKey), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(a.PublicKey), nil
}

// RegisterFromManifest fetches the agent's well-known manifest, checks its
// domain anchors agentID, selects the currently-valid Ed25519 key, and upserts
// the raw 32-byte key.
//
// Discovery is anchored to the agent's identity (ADR-009 D3/D4: agent_id IS the
// agent's domain / discovery anchor). The manifest is fetched from agent_id's
// own well-known location, and a caller-supplied manifestURL whose host differs
// from agent_id is refused — otherwise a caller could bind agent_id=victim to a
// manifest served by a host it controls (identity spoofing). manifestURL may be
// a full URL or a bare host; only its host is consulted, the path is fixed.
func (r *registry) RegisterFromManifest(ctx context.Context, agentID, manifestURL string) error {
	if err := requireAnchoredHost(agentID, manifestURL); err != nil {
		return err
	}
	resolvedURL, err := rampwellknown.ManifestURL(agentID, "", "")
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	// Role is intentionally NOT asserted: this resolves a caller's signing key
	// from the manifest its domain serves, and that caller may be an agent
	// (ROLE_AGENT) or a publisher self-registering to push its own catalog
	// (ROLE_PUBLISHER). The domain == agentID binding below is the security
	// boundary, not the role label.
	m, err := rampwellknown.Fetch(ctx, agentID, rampwellknown.FetchOptions{
		Client:  r.http,
		Scheme:  r.scheme,
		Port:    r.port,
		Timeout: r.timeout,
	})
	if err != nil {
		return mapFetchError(err)
	}
	if m.GetDomain() != agentID {
		return fmt.Errorf("%w: want=%q got=%q", ErrAgentIDMismatch, agentID, m.GetDomain())
	}
	pubKey, err := r.selectValidKey(m)
	if err != nil {
		return err
	}
	if _, err := r.repo.Upsert(ctx, repo.Agent{
		ID:            agentID,
		PublicKey:     pubKey,
		ManifestURL:   resolvedURL,
		RequesterType: "AGENT",
	}); err != nil {
		return fmt.Errorf("agentreg: upsert: %w", err)
	}
	return nil
}

// selectValidKey returns the raw Ed25519 public key whose validity window
// covers r.clock.Now(). When multiple keys are valid simultaneously, the first
// in document order wins — callers rotate keys by shortening the outgoing key's
// not_after.
func (r *registry) selectValidKey(m *rampwellknown.Manifest) (ed25519.PublicKey, error) {
	pub, err := rampwellknown.ActiveKey(m, r.clock.Now())
	switch {
	case errors.Is(err, rampwellknown.ErrKeyExpired):
		// No key's validity window covers now → registrable-identity fault.
		return nil, ErrNoValidKey
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	return pub, nil
}

// requireAnchoredHost refuses a registration whose manifestURL host differs
// from agentID. Discovery is anchored to the agent's identity (ADR-009 D3/D4),
// so the host that serves the manifest MUST be the agent itself; a divergent
// host is an identity-spoofing attempt and is reported as ErrAgentIDMismatch.
func requireAnchoredHost(agentID, manifestURL string) error {
	want, err := discoveryHost(agentID)
	if err != nil {
		return fmt.Errorf("%w: agent_id: %w", ErrMalformedManifest, err)
	}
	got, err := discoveryHost(manifestURL)
	if err != nil {
		return fmt.Errorf("%w: manifest_url: %w", ErrMalformedManifest, err)
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("%w: manifest_url host %q is not anchored to agent_id %q",
			ErrAgentIDMismatch, got, want)
	}
	return nil
}

// discoveryHost extracts the host (including any port) from a bare domain,
// host:port, or full-URL reference, using the same normalization as the fetch
// path so the comparison is apples-to-apples.
func discoveryHost(ref string) (string, error) {
	normalized, err := rampwellknown.ManifestURL(ref, "", "")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	return parsed.Host, nil
}

// mapFetchError translates rampwellknown fetch sentinels into agentreg's error
// vocabulary. A schema failure is a malformed registration (client-facing 400
// at the transport layer); a missing manifest (404) or a transport/non-2xx
// failure is surfaced verbatim so the transport layer maps it to an
// upstream-fetch failure (502).
func mapFetchError(err error) error {
	if errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		return fmt.Errorf("%w: %w", ErrMalformedManifest, err)
	}
	return fmt.Errorf("agentreg: fetch manifest: %w", err)
}

// IsCallerFault reports whether a RegisterFromManifest error is a permanent
// caller fault — the keyID is simply not a registrable identity (manifest
// absent, malformed, unanchored, or publishing no currently-valid key) — rather
// than a transient upstream failure (ErrFetch) the caller should retry. Every
// lazy-registration call site (service.mapLazyRegisterError, the catalog
// self-signup handler) uses it to split a 401/Unauthenticated from a
// 503/Unavailable identically, so the classification lives once next to the
// sentinels it switches on.
func IsCallerFault(err error) bool {
	switch {
	case errors.Is(err, ErrAgentIDMismatch),
		errors.Is(err, ErrMalformedManifest),
		errors.Is(err, ErrNoValidKey),
		errors.Is(err, ErrUnknown),
		errors.Is(err, rampwellknown.ErrNoManifest):
		return true
	default:
		return false
	}
}
