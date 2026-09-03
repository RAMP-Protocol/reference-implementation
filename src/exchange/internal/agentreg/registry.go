// Package agentreg wires agent public-key registration on top of repo.AgentRepo.
//
// The Exchange trusts callers whose Ed25519 public keys are published in the
// Web Bot Auth directory (/.well-known/http-message-signatures-directory) their
// own domain serves. LookupPublicKey returns the registered key;
// RegisterFromDirectory fetches that directory via the shared rampwellknown
// library, checks its host anchors the asserted agent_id, selects the key whose
// validity window covers the registry clock, and upserts the raw 32-byte Ed25519
// key via repo.AgentRepo. The directory carries only keys — the caller may be an
// agent or a publisher self-registering to push its own catalog; the host
// binding (the fetch location) is the boundary.
package agentreg

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// ErrUnknown is returned when LookupPublicKey has no registration for the agent.
var ErrUnknown = errors.New("agentreg: unknown agent")

// ErrNoValidKey is returned when the key directory has no key whose validity
// window covers the registry's current clock reading.
var ErrNoValidKey = errors.New("agentreg: no currently valid key in the key directory")

// ErrAgentIDMismatch is returned when the discovery URL's host does not match
// the agent_id the caller asserted. Identity is anchored to the host that
// serves the agent's key directory (see requireAnchoredHost) — no manifest
// content is read on either side of the comparison.
var ErrAgentIDMismatch = errors.New("agentreg: discovery host does not match the asserted agent id")

// ErrMalformedDirectory is returned when the key directory fails schema
// validation, its URL cannot be built from the identity, or its selected key
// cannot be decoded.
//
// The document is the agent's Web Bot Auth key directory, NOT its ramp.json
// commercial overlay: this package fetches only the former, and the role a
// caller might have declared in the latter is never read. Naming the overlay
// here sent an operator to the wrong document, which is the same failure the
// ErrNotAHost split below was introduced to fix.
var ErrMalformedDirectory = errors.New("agentreg: malformed key directory")

// ErrNotAHost is returned when a value this package was asked to treat as an
// identity does not name a host — so it can be neither a storage key nor a fetch
// target. It is its own sentinel because the three refusals that share it are one
// failure class, and the two they used to borrow both claim something the caller
// can act on and this does not: ErrAgentIDMismatch says two hosts disagree, which
// is a different repair from "this is not a host at all", and ErrMalformedDirectory
// points at a document that in this case was never retrieved. On the
// unauthenticated agents/register endpoint that produced a 400 blaming a
// malformed document for a bad discovery_url, which sent the caller to inspect a
// document the Exchange never fetched.
//
// IsCallerFault classifies it as a permanent caller fault, like the sentinels it
// splits from, so no call site's accept/reject behaviour changes — only the
// diagnosis a caller is handed.
// It is an alias of agentid.ErrNotAHost — the package that owns the derivation
// owns the sentinel, so a caller matches one condition rather than one per
// package.
var ErrNotAHost = agentid.ErrNotAHost

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
	RegisterFromDirectory(ctx context.Context, agentID, directoryURL string) error
	// RefreshDirectoryKey re-pins directory's currently-valid key so a caller
	// that rotated its key is recognized without operator intervention. It is
	// debounced per directory to bound re-fetch amplification (see the impl).
	RefreshDirectoryKey(ctx context.Context, directory string) error
}

// Config bundles registry constructor dependencies.
type Config struct {
	Repo    repo.AgentRepo
	HTTP    HTTPDoer
	Clock   Clock
	Timeout time.Duration
	// Scheme/Port shape the well-known fetch URL for bare hosts, mirroring the
	// Gate-2 publisher-manifest Cache (cmd/server newManifestCache wires the same
	// RAMP_WELLKNOWN_{SCHEME,PORT}). Empty Scheme defaults to https and the
	// scheme-default port. Without this, self-signup (Gate-1) always fetches
	// https:443 and cannot reach an http compose/local edge — which is exactly
	// what forces the DB key pre-seed the well-known trust model exists to remove.
	// They MUST also match what the httpsig per-agent resolver (agentkeys) uses,
	// so transport-key verification and service-side lazy registration fetch the
	// same document.
	Scheme string
	Port   string
	// RefreshDebounce bounds how often RefreshDirectoryKey re-fetches a given
	// directory: within this window of a prior refresh the call is a no-op, so a
	// burst of key-mismatch requests cannot amplify into a directory-fetch storm.
	// The first refresh for a directory always fetches (no prior timestamp), so a
	// rotation is still picked up promptly. New defaults an unset (zero) value to
	// defaultRefreshDebounce; tests may set a small window for determinism.
	RefreshDebounce time.Duration
}

// New constructs a Registry. Clock defaults to the system clock. HTTP is
// REQUIRED and injected: the SSRF guard is SDK-owned, so the caller constructs
// the client once from resolvers.NewGuardedClientFromEnv at its composition root
// and passes it here (this package never re-wraps the SDK factory as an
// in-constructor default). agents/register is an unauthenticated,
// caller-controlled fetch path, so the injected client MUST be the SDK-guarded
// one, never a fail-open http.DefaultClient.
func New(cfg Config) Registry {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.RefreshDebounce == 0 {
		cfg.RefreshDebounce = defaultRefreshDebounce
	}
	return &registry{
		repo:            cfg.Repo,
		http:            cfg.HTTP,
		clock:           cfg.Clock,
		timeout:         cfg.Timeout,
		scheme:          cfg.Scheme,
		port:            cfg.Port,
		refreshDebounce: cfg.RefreshDebounce,
		lastRefresh:     map[string]time.Time{},
	}
}

// defaultRefreshDebounce is the production window RefreshDirectoryKey coalesces
// re-fetches into when Config.RefreshDebounce is unset. A legitimate key
// rotation is picked up within one window; an attacker cannot drive more than
// one directory fetch per window per directory.
const defaultRefreshDebounce = 30 * time.Second

type registry struct {
	repo    repo.AgentRepo
	http    HTTPDoer
	clock   Clock
	timeout time.Duration
	scheme  string
	port    string

	refreshDebounce time.Duration
	refreshMu       sync.Mutex
	lastRefresh     map[string]time.Time
}

// storageKey normalizes an asserted agent identity into the form the agents table
// is keyed on: the canonical directory host (internal/agentid).
//
// Every value this package keys on — the lookup argument, the refresh debounce
// map, the registered identity — reaches agentid.FromDirectory before it is used,
// which is what makes the invariant "agent_id holds a canonical directory host"
// hold for the column rather than for whichever caller remembered. Registration
// gets there through requireAnchoredHost, which returns the host it anchored so
// the checked value and the stored value cannot be two different derivations;
// the other paths call this wrapper, whose only added job is translating agentid's
// error into agentreg's vocabulary.
//
// The identities reaching this package are spelled inconsistently by design — one
// arrives as a signed Signature-Agent header, another as a caller-supplied
// caller_id on a catalog push — and keying on them raw gave one host a row per
// spelling, each with its own key pin and billing ref.
//
// A value naming no host is refused as ErrNotAHost: it can be neither a storage
// key nor a fetch target, and IsCallerFault classifies that sentinel as a
// permanent caller fault, so every call site maps it to the unauthenticated
// answer it already gives an unregistrable identity.
func storageKey(agentID string) (string, error) {
	// No re-wrap: FromDirectory already reports the sentinel ErrNotAHost names.
	return agentid.FromDirectory(agentID)
}

func (r *registry) LookupPublicKey(ctx context.Context, agentID string) (ed25519.PublicKey, error) {
	// Returned bare, like the other storageKey call sites: every sentinel it
	// wraps already begins "agentreg:", so adding the prefix here produced a
	// doubled "agentreg: agentreg: ..." message.
	key, err := storageKey(agentID)
	if err != nil {
		return nil, err
	}
	a, err := r.repo.ByID(ctx, key)
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

// RegisterFromDirectory fetches the agent's Web Bot Auth directory
// (/.well-known/http-message-signatures-directory), checks its host anchors
// agentID, selects the currently-valid Ed25519 key, and upserts the raw 32-byte
// key.
//
// Discovery is anchored to the agent's identity (ADR-009 D3/D4: agent_id IS the
// agent's domain / discovery anchor). The directory is fetched from agent_id's
// own well-known location, and a caller-supplied directoryURL whose host differs
// from agent_id is refused — otherwise a caller could bind agent_id=victim to a
// directory served by a host it controls (identity spoofing). directoryURL may
// be a full URL or a bare host; only its host is consulted, the path is fixed.
func (r *registry) RegisterFromDirectory(ctx context.Context, agentID, directoryURL string) error {
	// The anchoring check hands back the host it anchored, and that host IS the
	// stored identity — one derivation, not two that have to agree. Deriving it
	// twice is what let the check compare folded and the column store unfolded,
	// so "Agent.Example" anchored to "agent.example" and then took a second row.
	//
	// It is also what the fetch URL is rebuilt from, so the scheme the caller
	// happened to assert never reaches either — a caller presenting
	// "http://victim.example" cannot pull THIS fetch down to cleartext, because
	// the configured scheme decides. That is a property of this function, not of
	// the platform: the transport key resolver runs earlier and does honour a
	// caller-supplied scheme, where the guarded client's ALLOW_INSECURE gate is
	// what refuses the dial.
	identity, err := requireAnchoredHost(agentID, directoryURL)
	if err != nil {
		return err
	}
	resolvedURL, err := rampwellknown.WBAURL(identity, r.scheme, r.port)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedDirectory, err)
	}
	// The WBA directory carries only keys — no role, no domain field. The
	// anchoring boundary is the fetch LOCATION: the directory is fetched from the
	// identity's own well-known path (requireAnchoredHost enforces directoryURL is
	// anchored to agentID), so a currently-valid key published there is
	// TOFU-pinned as (identity, key). The signer may be an agent or a publisher
	// self-registering to push its own catalog; the fetch location is the
	// security boundary, not any self-asserted identity.
	f, err := rampwellknown.FetchWBA(ctx, identity, rampwellknown.FetchOptions{
		Client:  r.http,
		Scheme:  r.scheme,
		Port:    r.port,
		Timeout: r.timeout,
	})
	if err != nil {
		return mapFetchError(err)
	}
	pubKey, err := r.selectValidKey(f)
	if err != nil {
		return err
	}
	if _, err := r.repo.Upsert(ctx, repo.Agent{
		ID:            identity,
		PublicKey:     pubKey,
		DiscoveryURL:  resolvedURL,
		RequesterType: "AGENT",
	}); err != nil {
		return fmt.Errorf("agentreg: upsert: %w", err)
	}
	return nil
}

// RefreshDirectoryKey re-fetches directory's WBA directory and re-pins its
// currently-valid key, so a caller that legitimately rotated its key is
// recognized without operator intervention. Identity anchoring is unchanged:
// the directory IS the agent's discovery anchor, so it is fetched from its own
// well-known path.
//
// The re-fetch is DEBOUNCED per directory (RefreshDebounce): within the window
// of a prior refresh this is a no-op, so a stream of key-mismatch requests — an
// impersonator hammering a victim directory, or a genuinely rotated caller
// retrying — cannot amplify into a directory-fetch storm. The first refresh for
// a directory always fetches, so a rotation is picked up on first contact.
func (r *registry) RefreshDirectoryKey(ctx context.Context, directory string) error {
	// Debounce on the canonical host, not on what the caller typed. The window is
	// documented as anti-amplification — one fetch per window per directory — and
	// a key that varied with spelling made that bound per-spelling instead: one
	// victim directory, as many fetch budgets as the caller cared to invent. One
	// of the two callers passes an unverified caller_id straight off a catalog
	// push, so the spellings are caller-chosen.
	//
	// RegisterFromDirectory normalizes again; that second pass is a no-op because
	// agentid.FromDirectory is idempotent, which agentid's own tests pin.
	identity, err := storageKey(directory)
	if err != nil {
		return err
	}
	if !r.beginRefresh(identity) {
		return nil
	}
	return r.RegisterFromDirectory(ctx, identity, identity)
}

// beginRefresh records a refresh attempt for directory against the registry
// clock and reports whether the caller should proceed with the network fetch.
// Within refreshDebounce of the last attempt it returns false so concurrent /
// repeated refreshes coalesce into a single fetch. The attempt time is recorded
// even for a fetch that later fails, so a persistently-unreachable directory is
// not re-hammered every request.
func (r *registry) beginRefresh(directory string) bool {
	now := r.clock.Now()
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if last, ok := r.lastRefresh[directory]; ok && now.Sub(last) < r.refreshDebounce {
		return false
	}
	r.lastRefresh[directory] = now
	return true
}

// selectValidKey returns the raw Ed25519 public key whose validity window
// covers r.clock.Now(). When multiple keys are valid simultaneously, the first
// in document order wins — callers rotate keys by shortening the outgoing key's
// not_after.
func (r *registry) selectValidKey(f *rampwellknown.WBAFile) (ed25519.PublicKey, error) {
	pub, err := resolvers.ActiveEd25519Key(f, r.clock.Now())
	switch {
	case errors.Is(err, resolvers.ErrKeyExpired):
		// No key's validity window covers now → registrable-identity fault.
		return nil, ErrNoValidKey
	case err != nil:
		return nil, fmt.Errorf("%w: %w", ErrMalformedDirectory, err)
	}
	return pub, nil
}

// requireAnchoredHost refuses a registration whose discoveryURL host differs
// from agentID, and returns the host both resolved to. Discovery is anchored to
// the agent's identity (ADR-009 D3/D4), so the host that serves the WBA directory
// MUST be the agent itself; a divergent host is an identity-spoofing attempt and
// is reported as ErrAgentIDMismatch.
//
// Both sides are reduced through agentid.FromDirectory, and the anchored host is
// RETURNED rather than recomputed by the caller. That is deliberate: this used to
// compare with EqualFold while the column was keyed on a separately-derived value,
// so the check accepted "Agent.Example" as "agent.example" and the write then
// stored a second row for it. Returning the compared value makes the identity and
// the thing that was checked the same string by construction.
func requireAnchoredHost(agentID, discoveryURL string) (string, error) {
	want, err := agentid.FromDirectory(agentID)
	if err != nil {
		return "", fmt.Errorf("%w: agent_id: %w", ErrNotAHost, err)
	}
	got, err := agentid.FromDirectory(discoveryURL)
	if err != nil {
		// ErrNotAHost, not ErrMalformedDirectory: no manifest was fetched, so
		// pointing the caller at one to inspect would be a false lead.
		return "", fmt.Errorf("%w: discovery_url: %w", ErrNotAHost, err)
	}
	if got != want {
		return "", fmt.Errorf("%w: discovery_url host %q is not anchored to agent_id %q",
			ErrAgentIDMismatch, got, want)
	}
	return want, nil
}

// mapFetchError translates rampwellknown fetch sentinels into agentreg's error
// vocabulary. A schema failure is a malformed registration; an absent key
// directory (404) and a transport/non-2xx failure are both surfaced verbatim,
// so callers keep the distinction rampwellknown drew between them.
//
// This function does NOT decide how a caller answers. It once said an absent
// directory was surfaced "so the transport layer maps it to an upstream-fetch
// failure (502)", which contradicted IsCallerFault ten lines below — the same
// 404 was a permanent caller fault there. IsCallerFault is the decision; this
// one only preserves the sentinels it switches on.
func mapFetchError(err error) error {
	if errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		return fmt.Errorf("%w: %w", ErrMalformedDirectory, err)
	}
	return fmt.Errorf("agentreg: fetch key directory: %w", err)
}

// IsCallerFault reports whether a RegisterFromDirectory error is a permanent
// caller fault — the keyID is simply not a registrable identity (key directory
// absent, malformed, unanchored, or publishing no currently-valid key) — rather
// than a transient upstream failure (ErrFetch) the caller should retry. Every
// lazy-registration call site (service.mapLazyRegisterError, the catalog
// self-signup handler) uses it to split a 401/Unauthenticated from a
// 503/Unavailable identically, so the classification lives once next to the
// sentinels it switches on.
func IsCallerFault(err error) bool {
	switch {
	case errors.Is(err, ErrAgentIDMismatch),
		errors.Is(err, ErrNotAHost),
		errors.Is(err, ErrMalformedDirectory),
		errors.Is(err, ErrNoValidKey),
		errors.Is(err, ErrUnknown),
		errors.Is(err, rampwellknown.ErrNoDocument):
		return true
	default:
		return false
	}
}
