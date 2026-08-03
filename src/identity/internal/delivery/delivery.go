// Package delivery is the Identity Service's content leg: it fetches the bytes
// a signed delivery URL names, presenting the custodied key that URL is bound
// to.
//
// # Why the registry fetches at all
//
// The Exchange binds each delivery URL to the RFC 7638 thumbprint of the key
// that signed the offer acceptance, and a capable edge makes the fetcher prove
// possession of that key (ADR-013). In the custodial registry flow that key
// lives in Vault and never reaches the agent, so the agent cannot satisfy the
// proof — it can only ever be refused. Moving the fetch here answers that
// without weakening the edge: the registry holds the key AND makes the request,
// so the proof is one it can actually produce (ADR-023).
//
// # One transport, many agents
//
// Like rampclient, this package holds no key material and takes no subdomain
// argument. The key is resolved per request by the KeySource, reading the
// authenticated subdomain off the context, so one client fetches for every agent
// as that agent — and a request carrying no identity is refused rather than
// signed as anyone. It is deliberately the SAME KeySource rampclient signs
// acceptances with: that is what makes the key presented here the key the
// Exchange bound the URL to.
package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/ramphttpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// DefaultTimeout bounds one content fetch. An agent is blocked on the tool call
// that triggered it, so a fetch that has not answered by now is more useful as a
// reported failure than as a hang.
const DefaultTimeout = 30 * time.Second

// DefaultSignatureTTL is how long the proof of possession stays valid. It is
// short on purpose: the covered set is only the method and the URL, so within
// this window the proof is replayable by anyone who observes the request.
const DefaultSignatureTTL = 30 * time.Second

// DefaultMaxBytes caps one fetched body at 8 MiB.
//
// This is a memory bound on the registry, not a judgement about how large
// licensed content may be. The body is buffered whole, base64-expanded by a
// third on its way into a JSON-RPC frame, and held for the life of the tool call
// — and a batch fetches one per item. The relay's 4 MiB cap is the nearest
// precedent; content runs larger, so this doubles it.
//
// An operator overrides it with IDENTITY_MCP_MAX_CONTENT_BYTES.
const DefaultMaxBytes int64 = 8 << 20

// maxErrorBodyBytes caps how much of a refusal body is read before parsing the
// edge's reason out of it. The payload is a small JSON object; anything past
// this is not a refusal we can interpret.
const maxErrorBodyBytes int64 = 4 << 10

// defaultMIMEType is what a body with no usable Content-Type is labelled. Guessing
// from the bytes would be worse: the agent is told what the publisher said, and
// "unknown" is a true answer where a sniffed guess might not be.
const defaultMIMEType = "application/octet-stream"

// Config configures a Fetcher. Only Keys is required.
type Config struct {
	// Keys resolves the signing key for the agent the inbound request
	// authenticated. Pass agentsign.Resolver.Source — the same source rampclient
	// signs offer acceptances with, so the key presented at the edge is the key
	// the Exchange bound the URL to.
	Keys ramphttpsig.KeySource
	// Transport is the underlying round-tripper. Defaults to the SDK's
	// SSRF-guarded one.
	//
	// The seam is the transport rather than the whole client on purpose: the
	// redirect policy is a security property of this profile, not a detail a
	// caller supplies, so it is applied here in every case. A test that injected
	// its own client would be asserting against its own policy instead of the
	// one production runs.
	Transport http.RoundTripper
	// Timeout bounds one fetch. Defaults to DefaultTimeout.
	Timeout time.Duration
	// MaxBytes caps one fetched body. Defaults to DefaultMaxBytes.
	MaxBytes int64
	// TTL is the proof-of-possession lifetime. Defaults to DefaultSignatureTTL.
	TTL time.Duration
	// Clock sources the created/expires window. Defaults to the system clock.
	Clock clock.Clock
}

// Content is one fetched resource.
type Content struct {
	// URL is the signed delivery URL that was fetched, echoed back so a caller
	// correlating a batch does not have to keep its own map.
	URL string
	// MIMEType is the media type the edge served, parameters stripped.
	MIMEType string
	// Body is the fetched bytes.
	Body []byte
}

// Fetcher fetches licensed content on behalf of whichever agent the inbound
// request authenticated.
type Fetcher struct {
	keys     ramphttpsig.KeySource
	http     *http.Client
	timeout  time.Duration
	maxBytes int64
	window   ramphttpsig.Window
}

// New builds a Fetcher. It fails rather than defaulting when Keys is absent: a
// fetcher that cannot sign can only ever be refused by a capable edge, and
// discovering that per request hides the wiring mistake behind a 403.
func New(cfg Config) (*Fetcher, error) {
	if cfg.Keys == nil {
		return nil, errors.New("delivery: Config.Keys is required")
	}
	cfg = cfg.withDefaults()
	return &Fetcher{
		keys:     cfg.Keys,
		http:     &http.Client{Transport: cfg.Transport, CheckRedirect: refuseRedirects},
		timeout:  cfg.Timeout,
		maxBytes: cfg.MaxBytes,
		// ClockWindow, not MonotonicWindow: the drift MonotonicWindow adds exists
		// to dodge a replay store keyed on (keyid, signature), and the delivery
		// edge deliberately keeps no such state (ADR-013 D2 defers nonces).
		window: ramphttpsig.ClockWindow(cfg.Clock, cfg.TTL),
	}, nil
}

// withDefaults resolves every optional field once, so the rest of the package
// reads settled values.
func (c Config) withDefaults() Config {
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxBytes <= 0 {
		c.MaxBytes = DefaultMaxBytes
	}
	if c.TTL <= 0 {
		c.TTL = DefaultSignatureTTL
	}
	if c.Clock == nil {
		c.Clock = clock.System{}
	}
	if c.Transport == nil {
		// The delivery URL comes from an Exchange response, not from operator
		// configuration, so the host is one a caller's offer named. That is the
		// same reasoning rampclient applies to its report leg, and the SDK's
		// guarded transport is the sanctioned answer to it.
		c.Transport = resolvers.NewGuardedClientFromEnv().Transport
	}
	return c
}

// refuseRedirects stops the client following any 3xx.
//
// A redirect cannot be followed under this profile. The proof covers
// @target-uri, so replaying it at the new location fails the edge's own check;
// re-signing for the new location is worse, because it would hand a fresh proof
// of possession of the agent's key to whatever host the first hop named. Note
// this diverges from the SDK-agent fetch path, which does follow redirects — a
// publisher edge that redirects works there and is refused here (ADR-023).
//
// The refusal names where it refused to go, redacted. That target is the most
// useful field on the failure an agent is handed, and the sibling RAMP leg
// reports it for the same reason.
func refuseRedirects(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf(
		"delivery: refusing redirect to %s: a bound fetch is never redirected",
		redactURL(req.URL),
	)
}

// redactURL reduces a URL to scheme://host/path, for a value that is going
// somewhere more durable than the caller who already holds it — a log line, or an
// error an operator will read.
//
// url.URL.Redacted() is NOT the tool for this. It masks userinfo passwords, and a
// delivery URL carries its credential in the QUERY: sig, kid, exp and agent_id.
// Redacted() would pass the signature through untouched while reading like a
// redaction, which is worse than not redacting at all.
//
// Every caller that needs this reduction goes through here rather than repeating
// it. That is not tidiness: the MCP adapter did once carry its own copy for the
// embedded-resource uri, the two drifted on userinfo, and the comment claiming
// they matched is what made the drift invisible.
func redactURL(u *url.URL) string {
	stripped := *u
	stripped.RawQuery, stripped.Fragment, stripped.User = "", "", nil
	return stripped.String()
}

// RedactURL is redactURL for a URL still in string form, so a caller holding the
// delivery URL can log it without reaching for the query-stripping itself. An
// unparseable input yields "" rather than the original: a value that could not be
// sanitized is not one to emit.
func RedactURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return redactURL(parsed)
}

// Fetch retrieves the content at signedURL, presenting the calling agent's
// custodied key as proof of possession.
func (f *Fetcher) Fetch(ctx context.Context, signedURL string) (Content, error) {
	const op = "fetch content"
	// The deadline is derived BEFORE the request is built, because building it
	// resolves the custodied key — a call to the custody backend, bounded only by
	// that backend's own client otherwise. A Timeout that covered the round trip
	// alone would leave the documented "bounds one content fetch" untrue against a
	// degraded Vault, and a batch pays that cost once per item.
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := f.request(ctx, op, signedURL)
	if err != nil {
		return Content{}, err
	}
	resp, err := f.http.Do(req)
	if err != nil {
		return Content{}, &Error{Kind: KindUnreachable, Op: op, Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Content{}, &Error{
			Kind: KindRefused, Op: op, Status: resp.StatusCode, Reason: edgeReason(resp.Body),
		}
	}
	body, err := f.read(resp.Body)
	if err != nil {
		return Content{}, err
	}
	return Content{URL: signedURL, MIMEType: mimeTypeOf(resp.Header.Get("Content-Type")), Body: body}, nil
}

// request builds the signed GET. It is separate from Fetch so the signing
// preconditions are all in one place, and so no partially-built request can
// reach the wire.
func (f *Fetcher) request(ctx context.Context, op, signedURL string) (*http.Request, error) {
	key, err := f.keys(ctx)
	if err != nil {
		// Wrapped, not replaced: a caller must still be able to reach the custody
		// sentinel underneath through errors.Is.
		return nil, &Error{Kind: KindNotSignable, Op: op, Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signedURL, nil)
	if err != nil {
		return nil, &Error{Kind: KindMalformed, Op: op, Err: err}
	}
	// The proof covers @target-uri as the VERBATIM string, while the request line
	// carries whatever url.URL re-serializes to. They agree for every URL an
	// Exchange mints, but if they ever diverge the signature cannot verify, and
	// the edge reports only an undifferentiated 403. Refusing here names the
	// cause instead of shipping a proof that is guaranteed to fail.
	if req.URL.String() != signedURL {
		// The given URL is deliberately NOT echoed: this error reaches a log, and
		// the value carries a live credential in its query. The re-serialized form
		// is what an operator compares against what the Exchange minted.
		return nil, &Error{
			Kind: KindMalformed, Op: op,
			Err: fmt.Errorf("url is not round-trip stable: it re-serializes to %s (query redacted)",
				redactURL(req.URL)),
		}
	}
	req.Header.Set(reqctx.HeaderRequestID, reqctx.IDOrNew(ctx))

	created, expires := f.window()
	binding, err := httpsig.SignAgentBinding(ctx, key.Private, httpsig.PoPOptions{
		URL: signedURL, KeyID: key.KeyID, Created: created, Expires: expires,
	})
	if err != nil {
		return nil, &Error{Kind: KindNotSignable, Op: op, Err: err}
	}
	binding.Apply(req.Header)
	return req, nil
}

// read consumes the body under the configured cap.
//
// It reads one byte past the cap so an oversized body is DETECTED rather than
// silently truncated. Truncated content that looks whole is worse than a
// refusal: the agent has paid for it and has no way to tell it is incomplete.
func (f *Fetcher) read(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, f.maxBytes+1))
	if err != nil {
		return nil, &Error{Kind: KindUnreachable, Op: "read content", Err: err}
	}
	if int64(len(body)) > f.maxBytes {
		return nil, &Error{
			Kind: KindTooLarge, Op: "read content",
			Err: fmt.Errorf("body exceeds the %d byte cap", f.maxBytes),
		}
	}
	return body, nil
}

// edgeReason pulls the edge's own refusal token out of a rejection body. The
// edge answers {"error": "...", "reason": "..."} on a binding failure; anything
// else yields "", and the caller falls back to the failure class.
func edgeReason(r io.Reader) string {
	var payload struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxErrorBodyBytes)).Decode(&payload); err != nil {
		return ""
	}
	if !reasonToken.MatchString(payload.Reason) {
		return ""
	}
	return payload.Reason
}

// reasonToken is the shape a refusal token may have.
//
// The body this is read from is written by the host we just fetched from, and the
// value is promoted over our own classification and presented to the agent as a
// machine-readable token — this service's own vocabulary. Unchecked, a publisher
// could answer any 4 KiB of text and have it render as though we had said it,
// including claiming a custody fault that is ours rather than theirs. Anything
// that is not token-shaped falls back to the failure class, which we do own.
var reasonToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// mimeTypeOf reduces a Content-Type to its media type, dropping parameters such
// as charset. The charset belongs to the client that decodes the bytes, and the
// blob this becomes carries the media type alone.
func mimeTypeOf(header string) string {
	if header == "" {
		return defaultMIMEType
	}
	mediaType, _, err := mime.ParseMediaType(header)
	if err != nil || mediaType == "" {
		return defaultMIMEType
	}
	return mediaType
}
