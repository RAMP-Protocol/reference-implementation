// Package exchreg reads what one Exchange asks of a registration — the schema
// its registration_data must match, and the terms revision that submitting one
// accepts — from that Exchange's own /.well-known/ramp.json.
//
// # Every read is a fresh fetch
//
// The protocol requires it, in as many words: a registering client must read the
// terms digest from a freshly fetched manifest rather than a cached copy. A
// cached ENDPOINT is fine, because a wrong endpoint fails loudly; a cached
// DIGEST is not, because a client cannot detect staleness locally, and a warm
// cache would make it echo a value the Exchange has already stopped accepting
// and retry the same refusal until the cache expired. Registration happens once
// per Exchange per agent, so the fetch is cheap.
//
// Reading the schema out of the same fresh bytes then costs nothing extra, and
// it removes a whole failure mode: a stale local schema cannot refuse a payload
// the Exchange would have taken, because there is no stale local schema.
//
// What IS held is the COMPILED validator, keyed by the SHA-256 of the served
// schema bytes. That key is the document, so a hit means the schema has not
// changed rather than that nobody re-read it — which is why holding this is safe
// where holding the document is not. It is bounded rather than expiring: an
// entry keyed by content cannot go stale, so age buys nothing, and what needs
// limiting is memory over a key space an authenticated caller influences.
//
// # Why the compile is worth avoiding twice
//
// A published schema is attacker-influenced input from a third party. The SDK
// bounds what compiling one can cost — a size cap, a depth cap, an evaluation
// budget and a compile timeout — but bounded is not free, and an agent naming
// the same hostile Exchange repeatedly would pay the bound on every call. Keyed
// by content, that cost is paid once per distinct document.
package exchreg

import (
	"context"
	"errors"
	"fmt"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
)

// DefaultCacheSize is how many distinct compiled schemas one Reader holds.
//
// The same bound the SDK puts on its own caller-influenced caches. Generous for
// the real case — a deployment speaks to a handful of Exchanges — and small
// enough that the worst case is bounded by the schema size cap times this, not
// by how many domains an agent can name.
const DefaultCacheSize = 256

// Config wires a Reader. Fetch is required; the rest take defaults.
type Config struct {
	// Fetch performs the manifest GET. It is REQUIRED and it is INJECTED,
	// because it MUST be the SSRF-guarded client: the host comes from an
	// authenticated agent's tool argument, so this is a request-derived address
	// and an unguarded client here would make the registry dial internal
	// networks on an agent's say-so. Built once at the composition root from the
	// SDK factory, and shared with the service's other guarded hops so one
	// reading of the SSRF environment governs all of them.
	Fetch rampwellknown.HTTPDoer

	// Scheme is the URL scheme the manifest is fetched over ("https" in
	// production, "http" for a local stack). Empty means https.
	Scheme string

	// Timeout bounds one manifest fetch. Zero uses rampwellknown's own.
	Timeout time.Duration

	// CacheSize is how many compiled validators to hold. Zero uses
	// DefaultCacheSize; a negative value is a configuration error.
	CacheSize int

	// Allow is the deployment's Exchange policy, consulted BEFORE the fetch.
	//
	// It is here, and not left to the caller, because this is the one outbound
	// leg that dials without going through an endpoint resolver — and the
	// resolver's overlay is what makes the policy unavoidable everywhere else.
	// A call-site check would make this leg's guarantee conventional: a second
	// caller, or one that forgot, would fetch any domain an authenticated agent
	// named, on the leg that dials before anything else runs.
	//
	// Nil permits every domain, which is the same answer an unset allowlist
	// gives.
	Allow func(domain string) bool
}

// Reader fetches registration requirements. It is safe for concurrent use.
type Reader struct {
	fetch    rampwellknown.HTTPDoer
	scheme   string
	timeout  time.Duration
	allow    func(domain string) bool
	compiled *lru.Cache[string, compiled]
}

// New builds a Reader from cfg, failing on missing required configuration rather
// than nil-panicking on the first register.
func New(cfg Config) (*Reader, error) {
	if cfg.Fetch == nil {
		return nil, errors.New(
			"exchreg: Config.Fetch is required; inject the SSRF-guarded client the " +
				"composition root builds")
	}
	size := cfg.CacheSize
	switch {
	case size == 0:
		size = DefaultCacheSize
	case size < 0:
		return nil, fmt.Errorf("exchreg: Config.CacheSize must not be negative, got %d", size)
	}
	cache, err := lru.New[string, compiled](size)
	if err != nil {
		return nil, fmt.Errorf("exchreg: build schema cache: %w", err)
	}
	return &Reader{
		fetch:    cfg.Fetch,
		scheme:   cfg.Scheme,
		timeout:  cfg.Timeout,
		allow:    cfg.Allow,
		compiled: cache,
	}, nil
}

// Requirements fetches exchange's manifest and reports what it asks of a
// registration. The fetch is never served from a cache; see the package doc.
//
// Two refusals come before anything is dialled: a value that is not a bare
// domain, and a domain the deployment's policy excludes.
//
// The SHAPE check is here for the same reason Config.Allow is, and the argument
// is the same word for word. This is the one outbound leg that dials without
// going through an endpoint resolver. The resolver runs helpers.IsBareHost,
// which is a WEAKER question than this one and not a substitute for it: the SDK
// keeps the two apart deliberately, because IsBareHost asks whether a value is
// safe to concatenate into a URL while IsBareDomain asks whether it is the shape
// the contract admits. A trailing root dot, a leading or trailing hyphen, an
// underscore and a bracketed IPv6 literal are usable hosts that the wire rule
// refuses — which is this project's own shared refusal table. So no leg gets the
// contract's rule from a resolver; a leg that wants it runs it. Left to the call
// site, this leg's guarantee would be conventional: a second caller, or one that
// forgot, would hand
// FetchDocument a value carrying a path or userinfo, and the URL is built by
// concatenation for a value with no scheme — so such a caller chooses the URL
// this service fetches, not merely the host it fetches from. The SSRF guard
// filters addresses and would not see it, because the address is legitimate and
// the path is what was smuggled.
//
// The tool layer keeps its own copy of this check, which is not redundant: what
// it adds is a sentence naming what a bare domain is, where this one is the
// structural guarantee underneath. Same split as the policy check above it.
func (r *Reader) Requirements(ctx context.Context, exchange string) (account.Requirements, error) {
	if !helpers.IsBareDomain(exchange) {
		return account.Requirements{}, fmt.Errorf("%w: %q", account.ErrNotBareDomain, exchange)
	}
	if r.allow != nil && !r.allow(exchange) {
		return account.Requirements{}, fmt.Errorf("%w: %s", account.ErrNotPermitted, exchange)
	}
	doc, err := rampwellknown.FetchDocument(ctx, exchange, rampwellknown.FetchOptions{
		Client:  r.fetch,
		Scheme:  r.scheme,
		Timeout: r.timeout,
		// An Exchange's manifest is what is being read, so a document that says
		// it belongs to a Broker or a publisher is refused here rather than read
		// for members it has no business publishing.
		ExpectRole: rampwellknown.RoleExchange,
	})
	if err != nil {
		return account.Requirements{}, fmt.Errorf("exchreg: read %s registration requirements: %w", exchange, err)
	}
	raw, published, err := doc.RegistrationSchemaBytes()
	if err != nil {
		return account.Requirements{}, fmt.Errorf("exchreg: read %s registration schema: %w", exchange, err)
	}
	reqs := account.Requirements{
		TermsDigest: doc.Manifest.TermsDigest,
		Verdict:     helpers.SchemaNotPublished,
	}
	if published {
		reqs.Schema, reqs.Verdict = r.compile(raw)
	}
	return reqs, nil
}
