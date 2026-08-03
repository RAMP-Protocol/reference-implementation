// Package ramphttpsig provides the single canonical outbound RFC 9421
// Ed25519 signing http.RoundTripper used by every RAMP client that talks
// to a signature-verifying server.
//
// The wire contract is owned by the SDK (helpers.SignRequest / helpers.AppendSignature) (the same
// function the Exchange's verifier mirrors): for every /ramp.* request the
// transport buffers the body, re-seats Body/GetBody/ContentLength/Host so the
// signed bytes match the transmitted bytes, and emits the RAMP covered
// component set (@method, @target-uri, content-digest, authorization, plus
// x-ramp-entitlement-biscuit when present). Bodyless /ramp.* requests pass
// through unsigned.
//
// A non-/ramp.* request is forwarded untouched by default. WithWBASigning instead
// signs it under the Web Bot Auth profile (internal/httpsig.SignRequestWBA):
// @authority + signature-agent, tag="web-bot-auth", a per-request nonce. That is
// the profile an arbitrary WBA-aware origin verifies, and unlike the RAMP branch
// it covers bodyless GETs, which is what such traffic mostly is.
//
// Which key signs is a separate axis. By default it is the one bound at
// construction. WithKeySource resolves it per request, so a service holding
// custody of many agents' keys signs each request as the agent it is acting for.
//
// Callers differ only in how the signature's (created, expires) instants are
// sourced — the production ingester stamps a wall-clock instant plus a TTL; a
// monotonic source keeps back-to-back signatures in the same wall-clock second
// unique so they do not trip the server's replay store. That axis of variation
// is captured by the Window func; the signing bytes are otherwise identical
// across callers.
//
// Two signing branches share that Window, and they source created differently:
//
//   - A plain outbound /ramp.* request is signed with
//     the SDK's helpers.SignRequest, which stamps
//     created=now() ITSELF — the caller-supplied created is unused on this path.
//   - A request that already carries an incoming Signature header — the relay
//     path — CHAINS a co-signature on top via the SDK
//     helpers.AppendSignature so the ordered set of signatures forms the
//     forwarding chain. The SDK helpers are L1 and read no clock: their
//     SignOptions.Created/Expires are caller-injected and Created=0 is omitted
//     from the wire. The multisig verifier requires created on EVERY signature,
//     so the caller MUST inject created here from the same clock as expires.
package ramphttpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

// ErrUnusableKey is returned when the key a request would be signed with cannot
// be used: wrong length, or carrying a keyid that does not identify it. It is
// distinct from an error the KeySource itself returned (custody down, no active
// key, an unauthenticated caller), which is wrapped through unchanged so the
// caller can still match on the custody sentinels — the two call for different
// answers, an outage being retryable where malformed key material is not.
var ErrUnusableKey = errors.New("ramphttpsig: unusable signing key")

// Window returns the RFC 9421 (created, expires) cutoffs (unix seconds) to stamp
// on the next outbound signature. It is invoked once per signed request. Both
// axes matter: the internal/httpsig (yaronf) non-relay path stamps created=now()
// itself and ignores the returned created, but the SDK helpers relay path reads
// no clock and MUST receive created from the caller — the multisig verifier
// rejects any signature missing created. An implementation may return
// monotonically increasing values to keep each on-the-wire signature unique (the
// integration replay-uniqueness need) or a wall-clock instant plus a fixed TTL
// (production); created and expires should derive from the same source so a
// deterministic-clock test stays inside the verifier's freshness window.
type Window func() (created, expires int64)

// ClockWindow returns the production Window: it stamps each outbound signature
// with wall-clock-derived created=now() and expires=now()+ttl (now read through
// clk). This is the shared constructor for every production caller that signs
// against a real clock; integration tests that need strictly-increasing values
// to dodge the server's replay store supply their own monotonic Window instead.
// Both axes come from the single clk.Now() reading so created ≤ expires and both
// land in the verifier's window.
func ClockWindow(clk clock.Clock, ttl time.Duration) Window {
	return func() (int64, int64) {
		now := clk.Now()
		return now.Unix(), now.Add(ttl).Unix()
	}
}

// MonotonicWindow returns a Window whose expires cutoff increases across calls
// within the same wall-clock second, so a burst of identical relay requests does
// not collide on (keyid, signature) in the server's replay store. created tracks
// now(); the pair stays clock-consistent. Safe for concurrent RoundTrips: the
// running maximum is held in an atomic updated by compare-and-swap.
//
// The drift is CAPPED at one further ttl, so a signature can never live longer
// than 2*ttl no matter the request rate. Without a cap the +1s bump compounds:
// above one request per second the cutoff runs permanently ahead of the clock
// and a signature's real lifetime becomes a function of traffic rate rather than
// ttl — at 10 rps the window grows by 9 seconds every second. That silently
// disables the short-lifetime control, and the replay store only remembers a
// signature for ReplayTTL, so past that point a captured request is replayable
// again.
//
// Above the saturation rate (ttl bumps per second) two signatures in one second
// can share a cutoff, which is exactly what a plain clock window does. Losing
// collision-avoidance under sustained load is the deliberate trade: a bounded
// lifetime matters more than sparing the replay store a duplicate.
func MonotonicWindow(clk clock.Clock, ttl time.Duration) Window {
	var lastExpires atomic.Int64
	return func() (int64, int64) {
		now := clk.Now()
		floor := now.Unix() + int64(ttl.Seconds())
		ceiling := floor + int64(ttl.Seconds())
		for {
			prev := lastExpires.Load()
			next := floor
			if prev >= next {
				next = prev + 1
			}
			if next > ceiling {
				next = ceiling
			}
			if lastExpires.CompareAndSwap(prev, next) {
				return now.Unix(), next
			}
		}
	}
}

// AgentKey is the identity ONE outbound request is signed as: the signer's own
// directory origin, its RFC 9421 keyid, and the Ed25519 private half. KeyID may be
// left empty, in which case it is derived as the RFC 7638 thumbprint of Private's
// public key — the only value a WBA verifier will accept.
type AgentKey struct {
	Directory string
	KeyID     string
	Private   ed25519.PrivateKey
}

// KeySource resolves the key to sign the current request with. It is consulted
// once per signed request, which is what lets ONE transport sign on behalf of MANY
// agents: a registry holding custody of its users' keys returns the authenticated
// user's key here, per request, instead of binding a single key at construction.
//
// The subdomain it resolves MUST come from the authenticated identity of the
// inbound request, never from a field the caller filled in — a source that reads
// the wire will happily sign as whoever was asked for.
type KeySource func(ctx context.Context) (AgentKey, error)

// Transport is an http.RoundTripper that signs outbound requests with the
// canonical RAMP RFC 9421 message. After the WBA split the RFC 9421 keyid is the
// RFC 7638 thumbprint of the signing key's public half (proof of key possession);
// the signer's identity is its directory origin, carried in the covered
// Signature-Agent header. Construct it with New.
//
// By default only bodied /ramp.* requests are signed and everything else is
// forwarded to base untouched. WithWBASigning additionally signs non-/ramp.*
// requests with the Web Bot Auth profile, which is how the registry identifies an
// agent to an arbitrary WBA-aware origin.
type Transport struct {
	base   http.RoundTripper
	keys   KeySource
	window Window
	// appendOnly selects the always-append signing branch (WithAppendSigner):
	// every /ramp.* request is signed with helpers.AppendSignature regardless
	// of whether an incoming Signature is present. See signRAMP for the two branches.
	appendOnly bool
	// wba enables the Web Bot Auth branch for non-/ramp.* targets (WithWBASigning).
	wba bool
	// rampTarget, when non-nil, marks additional non-/ramp.* requests as RAMP
	// traffic (WithRAMPTargets). It exists for the Broker's execute relay route,
	// which is not a /ramp.* path yet is verified under the RAMP covered set.
	rampTarget func(*http.Request) bool
}

// Option customizes a Transport at construction time.
type Option func(*Transport)

// WithAppendSigner routes EVERY signed /ramp.* request through the yaronf
// helpers.AppendSignature instead of the default split (fresh sig1
// via SignRequestRAMP, chained sig2 via the SDK helpers). This is the relay
// caller's mode: AppendSignatureRAMP degrades to a plain sig1 when no incoming
// signature is present and appends a forwarding-chain-linked sigN+1 when one is,
// so a single always-append branch serves both the broker-originated and the
// relayed call. Pair it with MonotonicWindow so identical back-to-back relay
// requests do not collide in the server's replay store.
func WithAppendSigner() Option {
	return func(t *Transport) { t.appendOnly = true }
}

// WithWBASigning signs requests whose target is NOT /ramp.* with the Web Bot Auth
// profile (@authority + signature-agent, tag="web-bot-auth", nonce) instead of
// forwarding them unsigned. It is opt-in because every existing caller relies on
// non-RAMP traffic leaving this transport untouched, and because a WBA signature
// is only meaningful when the signer publishes a directory the origin can fetch.
//
// Unlike the RAMP branch it also signs BODYLESS requests: the ordinary Web Bot
// Auth request is a plain GET, and refusing to sign it would leave exactly the
// traffic the profile exists for unauthenticated.
func WithWBASigning() Option {
	return func(t *Transport) { t.wba = true }
}

// WithKeySource resolves the signing key per request instead of using the one
// bound at construction. This is what a key-custody service wires in: the key that
// signs is the authenticated agent's own, looked up on every call.
func WithKeySource(src KeySource) Option {
	return func(t *Transport) { t.keys = src }
}

// WithRAMPTargets extends which requests get the RAMP signature. pred is called
// for each outgoing request and reports whether it should be signed under the
// RAMP profile. By default only requests whose path is /ramp.* are signed as
// RAMP; with this option, any request for which pred returns true is also
// signed as RAMP. pred can only add targets — a /ramp.* path is signed as RAMP
// regardless of what pred returns.
//
// This exists for the agent posting to the Broker's execute relay
// (/broker/v1/exchange/execute). That route is not a /ramp.* path, but the
// Broker verifies it exactly like a /ramp.* request: it expects the RAMP
// signature, which covers the method, target URI, body digest, and
// authorization header. Without this option the transport would treat the
// request as ordinary non-RAMP traffic — forwarding it unsigned, or signing it
// with the Web Bot Auth profile, which covers different components — and the
// Broker would reject it.
func WithRAMPTargets(pred func(*http.Request) bool) Option {
	return func(t *Transport) { t.rampTarget = pred }
}

// New builds a signing Transport over base. directory is the signer's own
// directory origin (published in the covered Signature-Agent header so the
// verifier resolves the thumbprint keyid against that directory's WBA file);
// priv is its Ed25519 private key; window supplies the per-request (created,
// expires) cutoffs (unix seconds). The keyid is derived once as the RFC 7638
// thumbprint of priv's public key. base defaults to http.DefaultTransport when
// nil. opts customize the signing branch (see WithAppendSigner, WithWBASigning).
//
// A caller that supplies WithKeySource signs with a key resolved per request; the
// directory and priv arguments are then unused and may be zero.
func New(
	base http.RoundTripper, directory string, priv ed25519.PrivateKey, window Window, opts ...Option,
) (*Transport, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &Transport{base: base, window: window}
	for _, opt := range opts {
		opt(t)
	}
	if t.keys != nil {
		return t, nil
	}
	static, err := completeKey(AgentKey{Directory: directory, Private: priv})
	if err != nil {
		return nil, err
	}
	t.keys = func(context.Context) (AgentKey, error) { return static, nil }
	return t, nil
}

// completeKey validates key material and derives the keyid as the RFC 7638
// thumbprint of the key's public half, so the keyid on the wire always identifies
// the key that actually signed and cannot drift from it. Construction and the
// per-request path share it, which is what keeps a KeySource held to the same
// standard as a statically-supplied key.
//
// The thumbprint is derived on EVERY call, including when the caller already
// supplied one, and a supplied keyid that disagrees is refused. Trusting the
// caller's value would make the guarantee above hold only on the branch nobody
// takes: the custody-backed KeySource always supplies a keyid, read from the
// store rather than recomputed from the key, so a rotation bug or a partial
// write there would put a keyid on the wire that resolves at the origin to a
// different public key — every signature rejected, and nothing on this side
// noticing.
func completeKey(key AgentKey) (AgentKey, error) {
	if len(key.Private) != ed25519.PrivateKeySize {
		return AgentKey{}, fmt.Errorf(
			"%w: key for %q is %d bytes, want an %d-byte ed25519 private key",
			ErrUnusableKey, key.Directory, len(key.Private), ed25519.PrivateKeySize,
		)
	}
	derived, err := helpers.Thumbprint(key.Private.Public().(ed25519.PublicKey))
	if err != nil {
		return AgentKey{}, fmt.Errorf("ramphttpsig: derive keyid thumbprint: %w", err)
	}
	if key.KeyID != "" && key.KeyID != derived {
		return AgentKey{}, fmt.Errorf(
			"%w: keyid %q for %q does not identify the signing key (thumbprint %q)",
			ErrUnusableKey, key.KeyID, key.Directory, derived,
		)
	}
	key.KeyID = derived
	return key, nil
}

// signMode is which profile, if any, an outbound request is signed under.
type signMode int

const (
	signNone signMode = iota
	signRAMP
	signWBA
)

// modeFor picks the profile by target. A /ramp.* request is a RAMP RPC and gets
// the RAMP covered set — but only when it carries a body, preserving the contract
// every existing caller was built against. Anything else is Web Bot Auth traffic
// when that branch is enabled (bodied or not), and untouched otherwise.
func (t *Transport) modeFor(req *http.Request) signMode {
	if req.URL == nil {
		return signNone
	}
	if strings.HasPrefix(req.URL.Path, "/ramp.") || t.isRAMPTarget(req) {
		if req.Body == nil {
			return signNone
		}
		return signRAMP
	}
	if t.wba {
		return signWBA
	}
	return signNone
}

// isRAMPTarget reports whether a non-/ramp.* request opted into RAMP signing via
// WithRAMPTargets (the execute relay route).
func (t *Transport) isRAMPTarget(req *http.Request) bool {
	return t.rampTarget != nil && t.rampTarget(req)
}

// RoundTrip signs req under the profile its target selects and forwards it to the
// base transport; a request no profile claims passes through unchanged.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	mode := t.modeFor(req)
	if mode == signNone {
		return t.base.RoundTrip(req)
	}
	// Buffering comes first because it is the only place the caller's body is
	// closed, and RoundTrip must close it on every path including the error ones.
	// Key resolution fails routinely — custody down, no active key, an
	// unauthenticated caller — so resolving before buffering would leak the body
	// of every request that hits one of those.
	body, err := t.buffer(req)
	if err != nil {
		return nil, err
	}
	key, err := t.resolveKey(req.Context())
	if err != nil {
		return nil, err
	}
	created, expires := t.window()
	if mode == signWBA {
		err = t.signWBA(req, body, key, expires)
	} else {
		err = t.signRAMP(req, body, key, created, expires)
	}
	if err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// resolveKey consults the KeySource for the key this request is signed as. A
// source that cannot answer — custody down, no active key, an unauthenticated
// caller — aborts the request: sending it unsigned would present the agent to the
// origin as an anonymous bot, which is the failure this transport exists to
// prevent.
func (t *Transport) resolveKey(ctx context.Context) (AgentKey, error) {
	key, err := t.keys(ctx)
	if err != nil {
		return AgentKey{}, fmt.Errorf("ramphttpsig: resolve signing key: %w", err)
	}
	return completeKey(key)
}

// buffer drains req.Body into memory and re-seats Body, GetBody, ContentLength,
// and Host so the signed bytes match the transmitted bytes AND so net/http can
// replay the body on a retried request (a signer that leaves GetBody nil silently
// loses the body on the second attempt). A bodyless request — the ordinary Web Bot
// Auth GET — yields a nil body and only the Host is seated, which is what the
// @authority component canonicalizes.
func (t *Transport) buffer(req *http.Request) ([]byte, error) {
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	if req.Body == nil {
		return nil, nil
	}
	// Close the caller's reader exactly once, on the read-failure path too: a
	// half-drained body that is never closed leaks the underlying reader for
	// anything but an in-memory one.
	orig := req.Body
	body, err := io.ReadAll(orig)
	_ = orig.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
	return body, nil
}

// signRAMP stamps the outbound RAMP RFC 9421 signature(s) on the buffered req. It
// first stamps the covered Signature-Agent header with the signer's own directory
// when — and only when — the request does not already carry one: on the relay path
// the originating agent already set Signature-Agent to ITS directory and its sig1
// covers that value, so overwriting it would break sig1 at the verifier. The
// relay's own key is resolved by its thumbprint keyid, not via Signature-Agent.
//
// Two signing branches follow, selected at construction:
//
//   - appendOnly (WithAppendSigner, the relay caller): every request is signed
//     with helpers.AppendSignature, which degrades to a plain sig1
//     when no incoming signature is present and appends a chain-linked sigN+1 when
//     one is. The yaronf signer stamps created=now() itself, so created is unused
//     on this branch.
//   - default: a fresh /ramp.* request is signed with helpers.SignRequest
//     (yaronf, created=now()); a request already carrying an incoming Signature —
//     the relay path — CHAINS a co-signature via the SDK helpers, which
//     read no clock (L1) and so REQUIRE created injected from the Window or the
//     multisig verifier rejects sig2 for the missing created param.
//
// signRAMP signs a RAMP leg through the SDK. The covered set, the canonical
// signature base and the chain linkage are the SDK's — this function only
// decides WHICH of its two entry points applies and supplies the per-request
// key, which is the whole reason this transport exists (one identity service
// signs for every agent, so the keyid is not fixed for the life of a transport
// the way core.NewSigningTransport assumes).
//
// AppendSignature covers both the always-append relay mode and the chained case:
// the SDK documents that appending to a request with no existing signature
// produces a sig1 byte-for-byte identical to SignRequest, so single-sig is just
// the N=1 case and needs no separate branch.
func (t *Transport) signRAMP(req *http.Request, body []byte, key AgentKey, created, expires int64) error {
	if key.Directory != "" && req.Header.Get(helpers.SignatureAgentHeader) == "" {
		req.Header.Set(helpers.SignatureAgentHeader, key.Directory)
	}
	signer, err := helpers.NewEd25519Signer(key.KeyID, key.Private)
	if err != nil {
		return err
	}
	opts := helpers.SignOptions{Created: created, Expires: expires}
	if t.appendOnly || req.Header.Get("Signature") != "" {
		return helpers.AppendSignature(req.Context(), req, body, signer, opts)
	}
	return helpers.SignRequest(req.Context(), req, body, signer, opts)
}

// signWBA stamps a Web Bot Auth signature on a request bound for an arbitrary
// WBA-aware origin: the profile's own covered set and parameters, with the keyid
// resolved against the directory named in the (covered, quoted) Signature-Agent
// header. The RAMP covered set does not apply — the receiver is not a RAMP peer.
func (t *Transport) signWBA(req *http.Request, body []byte, key AgentKey, expires int64) error {
	return httpsig.SignRequestWBA(req, body, key.Private, httpsig.WBAOptions{
		Directory: key.Directory,
		KeyID:     key.KeyID,
		Expires:   expires,
	})
}
